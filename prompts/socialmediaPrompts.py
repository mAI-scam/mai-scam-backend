prompts = {
    "detectLanguage": """
[ROLE]
You are a precise language identification module for social media content in Southeast Asia.

[GOAL]
Return ONLY the dominant BASE language of the SOCIAL MEDIA CONTENT as an ISO-639-1 code in lowercase.

[AVAILABLE LANGUAGES]
```
{available_languages}
```

[RULES]
- Choose from ALLOWED LANGUAGES only. Do not invent new codes (e.g., no "zh-cn", "sg-en").
- If content is code-mixed, pick the language covering the majority of meaningful tokens in CONTENT.
- If near-tie, prefer the language used by the majority of complete sentences in CONTENT.
- Normalize: treat "Chinese/Mandarin" as "zh"; "Bahasa Melayu" -> "ms"; "Bahasa Indonesia" -> "id".
- Ignore when deciding: URLs, hashtags, mentions (@username), numbers, emojis, platform-specific formatting.
- Be deterministic.

[OUTPUT FORMAT]
Return EXACTLY one single-line minified JSON object (no prose, no markdown, no code fences):
{{
    "base_language":"<iso>"
}}

[SOCIAL MEDIA CONTENT]
```
{content}
```
""",
    "analyzeSocialMedia": """
[ROLE]
You are a social media fraud-analysis module, specialized in analyzing social media posts of {language} language.

[GOAL]
Analyze the social media content and output a calibrated risk assessment.

[INPUTS]
LANGUAGE: {language}
PLATFORM: {platform}
CONTENT: {content}

[AUXILIARY SIGNALS]
The following JSON contains machine-extracted artifacts and heuristics. Use them to improve precision. Do not blindly trust; reconcile with CONTENT.
{aux_signals}

[HOW TO EVALUATE]
Consider red flags: fake giveaways, investment scams, romance scams, impersonation of brands/celebrities, urgent money requests, suspicious links, fake job offers, cryptocurrency scams, lottery scams, fake customer service, account verification scams, suspicious hashtags, engagement farming, bot-like behavior patterns.

[PLATFORM-SPECIFIC RISKS]
- Facebook/Instagram: Fake giveaways, impersonation, romance scams, investment schemes
- Twitter: Impersonation, fake news, crypto scams, phishing links
- TikTok: Fake challenges, impersonation, suspicious product promotions
- LinkedIn: Fake job offers, business opportunity scams, impersonation of executives

[SCORING RULES]
- "high": clear scam indicators (e.g., fake giveaway, impersonation, urgent money request, suspicious investment scheme).
- "medium": some suspicious cues but not conclusive (generic content, minor inconsistencies, low engagement for follower count).
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
