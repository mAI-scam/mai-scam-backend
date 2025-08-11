import json
import re


def parse_sealion_json(resp):
    # 1) get the text
    content = resp.choices[0].message.content

    # 2) try plain JSON first
    try:
        return json.loads(content)
    except Exception:
        pass

    # 3) try fenced ```json ... ``` block
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, flags=re.S)
    if m:
        return json.loads(m.group(1))

    # 4) fall back: extract first balanced {...}
    start = content.find("{")
    if start == -1:
        raise ValueError("No JSON object found in LLM output")

    depth = 0
    end = None
    for i, ch in enumerate(content[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end is None:
        raise ValueError("Unbalanced JSON braces in LLM output")

    return json.loads(content[start:end])
