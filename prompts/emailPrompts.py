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

[AUXILIARY SIGNALS]
The following JSON contains machine-extracted artifacts and heuristics. Use them to improve precision. Do not blindly trust; reconcile with CONTENT.
{aux_signals}

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
""",
    "analyzeEmailComprehensive": """
[ROLE]
You are an advanced email fraud-analysis system that performs language detection, scam analysis, and delivers results in the user's preferred language.

[GOAL]
In one comprehensive analysis:
1. Detect the base language of the email content
2. Analyze the email for scam/phishing indicators with focus on key risk factors
3. Provide precise, actionable recommendations for public users

[INPUTS]
TARGET_LANGUAGE: {target_language}
SUBJECT: {subject}
CONTENT: {content}
FROM_EMAIL: {from_email}
REPLY_TO_EMAIL: {reply_to_email}

[AUXILIARY SIGNALS]
The following JSON contains machine-extracted artifacts and heuristics. Use them to improve precision:
{aux_signals}

[LANGUAGE DETECTION INSTRUCTIONS]
STEP 1: Analyze the SUBJECT and CONTENT to identify the primary language.
Available language codes: {available_languages}

RULES:
- Choose from ALLOWED LANGUAGES only. Return the exact ISO-639-1 code (e.g., "en", "zh", "ms").
- Focus on the CONTENT text, not URLs, emails, numbers, or signatures.
- If content is code-mixed, pick the language covering the majority of meaningful words.
- For Chinese text, use "zh". For Bahasa Malaysia, use "ms". For Bahasa Indonesia, use "id".
- If content is mostly English with few foreign words, choose "en".
- Default to "en" for unclear cases rather than "unknown".
- Ignore boilerplate text like "Sent from my iPhone" or email signatures.

[SCAM EVALUATION - PRIORITIZED RED FLAGS]
PRIMARY INDICATORS (High Risk):
1. Credential harvesting: Password/OTP/login requests from suspicious senders
2. Financial fraud: Payment requests, fake invoices, cryptocurrency demands
3. Urgency manipulation: "Account suspended", "Verify immediately", threatening consequences
4. Impersonation: Fake banks, government agencies, known services with wrong domains
5. Malicious links: Phishing sites, URL shorteners from unknown senders

SECONDARY INDICATORS (Medium Risk):
6. Sender inconsistencies: From/reply-to mismatch, suspicious domains
7. Social engineering: Prize/lottery claims, job offers requiring payment
8. Poor legitimacy: Grammar errors from "official" sources, generic greetings

LOW-RISK PATTERNS:
- Personal communications without financial requests
- Legitimate marketing from verified senders
- Automated system notifications from known services

[ANALYSIS FOCUS]
Keep analysis concise and focused on:
- Most critical risk factor identified
- Why this specific indicator is concerning
- Avoid listing multiple minor issues

[ACTIONABLE RECOMMENDATIONS FOR PUBLIC USERS]
HIGH RISK: Specific protective actions
- "Delete this email and report as phishing"
- "Never click links or download attachments"
- "Contact [organization] directly through official channels"

MEDIUM RISK: Verification steps
- "Verify sender identity before responding"
- "Check links by hovering without clicking"
- "Contact organization through official website"

LOW RISK: General best practices
- "This appears legitimate, but remain cautious with personal info"
- "Always verify unexpected requests independently"

[SCORING RULES]
- "high": Clear scam indicators requiring immediate action (phishing, financial fraud, urgent threats)
- "medium": Suspicious patterns requiring verification (sender inconsistencies, unusual requests)
- "low": Legitimate communication with standard precautions needed

[OUTPUT FORMAT]
You must return EXACTLY one minified JSON object with these keys and nothing else.
No prose, no markdown, no code fences.
All text fields must be in TARGET_LANGUAGE ({target_language}).

Schema:
{{
    "detected_language": "<iso-639-1 code of email content>",
    "risk_level": "<low|medium|high in TARGET_LANGUAGE>",
    "analysis": "<precise 1-2 sentences focusing on main risk factor in TARGET_LANGUAGE>",
    "recommended_action": "<specific actionable advice for public users in TARGET_LANGUAGE>"
}}

IMPORTANT: 
- Focus analysis on the single most critical risk factor
- Make recommendations specific and actionable for general public
- Use clear, non-technical language

Now produce ONLY:
{{
"detected_language":"...",
"risk_level":"...",
"analysis":"...",
"recommended_action":"..."
}}
"""
}
