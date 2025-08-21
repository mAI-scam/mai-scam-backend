"""
LLM Utilities for MAI Scam Detection System

This module provides centralized functions for interacting with the Sea Lion LLM,
including prompt handling, response parsing, and JSON extraction.

TABLE OF CONTENTS:
==================

EXPORTED FUNCTIONS:
------------------
1. call_sea_lion_llm
2. parse_sealion_json

USAGE EXAMPLES:
--------------
# Basic LLM call
completion = await call_sea_lion_llm(prompt="Analyze this content")

# Custom configuration
completion = await call_sea_lion_llm(
    prompt="Translate this text",
    model="different-model",
    thinking_mode="on",
    cache=True
)

# Parse response
json_response = parse_sealion_json(completion)
"""

import json
import re
from models.clients import get_sea_lion_client


# =============================================================================
# 1. LLM INTERACTION FUNCTION
# =============================================================================

async def call_sea_lion_llm(
    prompt: str,
    model: str = "aisingapore/Llama-SEA-LION-v3.5-70B-R",
    thinking_mode: str = "off",
    cache: bool = False
):
    """
    Centralized function to call Sea Lion LLM with configurable parameters.

    This function provides a unified interface for all LLM calls across the system,
    with sensible defaults and the ability to customize model, thinking mode, and caching.

    Args:
        prompt: The prompt to send to the LLM (required)
        model: The model to use (default: "aisingapore/Llama-SEA-LION-v3.5-70B-R")
        thinking_mode: Thinking mode setting - "on" or "off" (default: "off")
        cache: Whether to enable caching (default: False)

    Returns:
        The LLM completion response object

    Example:
        completion = await call_sea_lion_llm(
            prompt="Analyze this email for scam indicators",
            thinking_mode="off",
            cache=False
        )
    """
    client = get_sea_lion_client()

    completion = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        extra_body={
            "chat_template_kwargs": {
                "thinking_mode": thinking_mode
            },
            "cache": {
                "no-cache": not cache
            }
        },
    )

    return completion


# =============================================================================
# 2. RESPONSE PARSING FUNCTION
# =============================================================================

def parse_sealion_json(resp):
    """
    Extract and parse JSON from Sea Lion LLM responses.

    This function handles multiple JSON formats that the LLM might return:
    1. Plain JSON: {"key": "value"}
    2. Fenced JSON blocks: ```json {"key": "value"} ```
    3. Balanced braces: Extracts first complete {...} object

    Args:
        resp: The Sea Lion LLM completion response object

    Returns:
        dict: Parsed JSON object

    Raises:
        ValueError: If no valid JSON object can be found in the response
    """
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
