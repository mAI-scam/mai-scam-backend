prompts = {
    "detectLanguage": """
[ROLE]
You are a precise language identification module for email data in Southeast Asia.

[GOAL]
Return ONLY the dominant BASE language of the EMAIL CONTENT as an ISO-639-1 code in lowercase.

[AVAILABLE LANGUAGES]
```
{available_languages}
```

[RULES]
- Choose from ALLOWED LANGUAGES only. Do not invent new codes (e.g., no "zh-cn", "sg-en").
- If content is code-mixed, pick the language covering the majority of meaningful tokens in CONTENT.
- If near-tie, prefer the language used by the majority of complete sentences in CONTENT.
- Normalize: treat “Chinese/Mandarin” as "zh"; “Bahasa Melayu” -> "ms"; “Bahasa Indonesia” -> "id".
- Ignore when deciding: URLs, email addresses, numbers, emojis, boilerplate signatures/disclaimers, quoted previous replies, headers like "Re:"/"Fwd:".
- Be deterministic.

[OUTPUT FORMAT]
Return EXACTLY one single-line minified JSON object (no prose, no markdown, no code fences):
{{
    "base_language":"<iso>"
}}

[EMAIL CONTENT]
```
{content}
```
""",
    "analyzeEmail": """
[ROLE]
You are an email fraud-analysis module, specialized in analyzing emails of {language} language.

[GOAL]
Analyze the email and output a calibrated risk assessment.

[INPUTS]
LANGUAGE: {language}
TITLE: {title}
CONTENT: {content}

[HOW TO EVALUATE]
Consider red flags: urgent/threatening tone, requests for credentials/OTP/payment, links to suspicious domains, look-alike brands, from↔reply-to mismatch, unexpected attachments, poor grammar, unusual sender context, cryptocurrency or gift-card requests, account suspension warnings, spoofed login pages, shortened URLs.

[SCORING RULES]
- "high": clear phishing/scam indicators (e.g., credential/payment request, malicious-looking link, explicit urgency + consequence).
- "medium": some suspicious cues but not conclusive (generic greeting, vague urgency, minor inconsistencies).
- "low": normal communication, no meaningful red flags.

[OUTPUT FORMAT]
You must return EXACTLY one minified JSON object with these keys and nothing else.
No prose, no markdown, no code fences.
If there are additional or missing keys, your answer is invalid.

Schema (conceptual):
{{
    "risk_level":"<low|medium|high in LANGUAGE>",
    "analysis":"<1-2 sentences in LANGUAGE>",
    "recommended_action":"<1-2 sentences in LANGUAGE>"
}}

Now produce ONLY:
{{
"risk_level":"...",
"analysis":"...",
"recommended_action":"..."
}}
""",
    "translateAnalysis": """
[ROLE]
You are a precise translator for security risk assessments, mainly translating from {base_language} to {target_language}.

[GOAL]
Translate the three fields into TARGET_LANGUAGE, preserving the original meaning and tone.

[INPUT]
BASE_LANGUAGE: {base_language}
TARGET_LANGUAGE: {target_language}
risk_level (BASE_LANGUAGE): {risk_level}
analysis (BASE_LANGUAGE): {analysis}
recommended_action (BASE_LANGUAGE): {recommended_action}

[GUIDELINES]
- Translate all three fields into TARGET_LANGUAGE.
- Keep "risk_level" as the natural, commonly-used equivalent of low/medium/high in TARGET_LANGUAGE (short, formal).
- "analysis": clear, 1-2 sentences, formal/helpful tone.
- "recommended_action": short imperative (e.g., 2-8 words).
- If BASE_LANGUAGE == TARGET_LANGUAGE, return the original text unchanged.
- No explanations, no markdown, no extra keys.

[OUTPUT FORMAT]
You must return EXACTLY one minified JSON object with these keys and nothing else.
No prose, no markdown, no code fences.
If there are additional or missing keys, your answer is invalid.

Schema (conceptual):
{{
    "risk_level":"<low|medium|high in TARGET_LANGUAGE>",
    "analysis":"<1-2 sentences in TARGET_LANGUAGE>",
    "recommended_action":"<1-2 sentences in TARGET_LANGUAGE>"
}}

Now produce ONLY:
{{
"risk_level":"...",
"analysis":"...",
"recommended_action":"..."
}}
"""
}
