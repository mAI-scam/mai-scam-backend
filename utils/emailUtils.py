"""
Email Analysis Utilities for MAI Scam Detection System

This module provides specialized functions for analyzing email content for scam indicators,
including language detection, signal extraction, and LLM-based analysis.

TABLE OF CONTENTS:
==================

EXPORTED FUNCTIONS:
------------------
1. detect_language
2. extract_signals
3. analyze_email
4. translate_analysis

USAGE EXAMPLES:
--------------
# Detect language
language = await detect_language("Hello world")

# Extract signals
signals = extract_signals(
    title="Urgent Account Update",
    content="Your account has been suspended...",
    from_email="support@bank.com",
    reply_to_email="noreply@bank.com"
)

# Analyze email
analysis = await analyze_email(
    title="Account Suspension",
    content="Your account has been suspended...",
    base_language="en",
    signals=signals
)

# Translate analysis
translated = await translate_analysis(
    base_language_analysis=analysis,
    base_language="en",
    target_language="zh"
)
"""

from utils.constant import (
    LANGUAGES, URL_PATTERN, EMAIL_PATTERN, PHONE_PATTERN,
    SUSPICIOUS_TLDS, URL_SHORTENERS, EMAIL_KEYWORDS, MIN_PHONE_LENGTH
)
from utils.llmUtils import parse_sealion_json, call_sea_lion_llm, call_sea_lion_v4_llm
from prompts.emailPrompts import prompts
import re
import json
import logging


# =============================================================================
# HELPER FUNCTIONS FOR SIGNAL EXTRACTION
# =============================================================================

def _extract_urls(text: str) -> list:
    """
    Extract URLs from text using regex pattern.

    Args:
        text: Input text to search for URLs

    Returns:
        list: List of found URLs
    """
    url_pattern = re.compile(URL_PATTERN, re.IGNORECASE)
    return url_pattern.findall(text or "")


def _extract_emails(text: str) -> list:
    """
    Extract email addresses from text using regex pattern.

    Args:
        text: Input text to search for emails

    Returns:
        list: List of found email addresses
    """
    email_pattern = re.compile(EMAIL_PATTERN)
    return email_pattern.findall(text or "")


def _extract_phone_numbers(text: str) -> list:
    """
    Extract phone numbers from text using regex pattern.

    This function uses a heuristic approach to find international and local
    phone numbers, filtering out very short strings and duplicates.

    Args:
        text: Input text to search for phone numbers

    Returns:
        list: List of found phone numbers (filtered and deduplicated)
    """
    phone_pattern = re.compile(PHONE_PATTERN)
    candidates = [p.strip() for p in phone_pattern.findall(text or "")]
    # De-duplicate and filter very short strings
    unique = []
    seen = set()
    for c in candidates:
        if len(c) < MIN_PHONE_LENGTH:
            continue
        if c in seen:
            continue
        seen.add(c)
        unique.append(c)
    return unique


def _domain_from_email(email: str) -> str:
    """
    Extract domain from email address.

    Args:
        email: Email address to extract domain from

    Returns:
        str: Domain part of email (lowercase) or empty string if invalid
    """
    if not email or "@" not in email:
        return ""
    return email.split("@", 1)[1].lower()


def _domains_from_urls(urls: list) -> list:
    """
    Extract domains from list of URLs.

    Args:
        urls: List of URLs to extract domains from

    Returns:
        list: List of unique domains (lowercase, sorted)
    """
    domains = []
    for url in urls:
        m = re.match(r"https?://([^/]+)/?", url, flags=re.IGNORECASE)
        if m:
            domains.append(m.group(1).lower())
    # de-duplicate
    return sorted(set(domains))


# =============================================================================
# 1. LANGUAGE DETECTION FUNCTION
# =============================================================================

async def detect_language(content: str) -> str:
    """
    Detect the base language of email content using LLM.

    This function uses the Sea Lion LLM to identify the primary language
    of the email content from a predefined list of supported languages.

    Args:
        content: The email content to analyze

    Returns:
        str: Language code (e.g., "en", "zh", "ms")

    Example:
        language = await detect_language("Hello world")
        # Returns: "en"
    """
    prompt = prompts["detectLanguage"].format(
        available_languages=str(", ".join(LANGUAGES)),
        content=content,
    )

    completion = await call_sea_lion_llm(prompt=prompt)
    json_response = parse_sealion_json(completion)

    return json_response["base_language"]


# =============================================================================
# 2. SIGNAL EXTRACTION FUNCTION
# =============================================================================

def extract_signals(title: str, content: str, from_email: str = "", reply_to_email: str = "") -> dict:
    """
    Extract auxiliary signals from email content for scam detection.

    This function analyzes email content to extract various indicators that
    can help identify potential scams, including:
    - URLs, emails, and phone numbers
    - Domain analysis and suspicious patterns
    - Keyword-based heuristics for different scam types
    - Email metadata analysis

    Args:
        title: Email subject line
        content: Email body content
        from_email: Sender email address
        reply_to_email: Reply-to email address

    Returns:
        dict: Structured signal data with the following keys:
            - artifacts: URLs, domains, emails, phone numbers
            - email_meta: Email metadata and domain analysis
            - heuristics: Keyword-based scam indicators

    Example:
        signals = extract_signals(
            title="Urgent Account Update",
            content="Your account has been suspended. Click here to verify...",
            from_email="support@bank.com",
            reply_to_email="noreply@bank.com"
        )
    """
    text = f"{title}\n\n{content}" if title else (content or "")
    urls = _extract_urls(text)
    url_domains = _domains_from_urls(urls)
    emails_in_text = _extract_emails(text)
    phone_numbers = _extract_phone_numbers(text)

    from_domain = _domain_from_email(from_email)
    reply_to_domain = _domain_from_email(reply_to_email)
    reply_mismatch = bool(from_domain and reply_to_domain and (
        from_domain != reply_to_domain))

    # Heuristic keyword signals
    lowered = text.lower()
    keywords = {}
    for category, keyword_list in EMAIL_KEYWORDS.items():
        keywords[category] = any(k in lowered for k in keyword_list)

    # Suspicious hosts/tlds
    has_shortened = any(d in URL_SHORTENERS for d in url_domains)
    has_suspicious_tld = any(
        d.split(".")[-1] in SUSPICIOUS_TLDS for d in url_domains if "." in d)

    return {
        "artifacts": {
            "urls": urls,
            "url_domains": url_domains,
            "emails_in_text": emails_in_text,
            "phone_numbers": phone_numbers,
        },
        "email_meta": {
            "from_email": from_email,
            "from_domain": from_domain,
            "reply_to_email": reply_to_email,
            "reply_to_domain": reply_to_domain,
            "reply_to_mismatch": reply_mismatch,
        },
        "heuristics": {
            **keywords,
            "has_shortened_link": has_shortened,
            "has_suspicious_tld": has_suspicious_tld,
            "link_count": len(urls),
        },
    }


# =============================================================================
# 3. EMAIL ANALYSIS FUNCTION
# =============================================================================

async def analyze_email(title: str, content: str, base_language: str, signals: dict | None = None) -> dict:
    """
    Perform comprehensive email analysis using LLM.

    This function uses the Sea Lion LLM to analyze email content for scam indicators,
    taking into account the extracted signals and providing a detailed risk assessment.

    Args:
        title: Email subject line
        content: Email body content
        base_language: Detected language of the content
        signals: Extracted auxiliary signals (optional)

    Returns:
        dict: Analysis results containing:
            - risk_level: "high", "medium", or "low"
            - analysis: Detailed analysis explanation
            - recommended_action: Suggested action for the user

    Example:
        analysis = await analyze_email(
            title="Account Suspension Notice",
            content="Your account has been suspended...",
            base_language="en",
            signals=extracted_signals
        )
    """
    aux_signals = json.dumps(signals or {}, ensure_ascii=False)
    prompt = prompts["analyzeEmail"].format(
        language=base_language,
        title=title,
        content=content,
        aux_signals=aux_signals,
    )

    completion = await call_sea_lion_llm(prompt=prompt)
    json_response = parse_sealion_json(completion)

    return json_response


# =============================================================================
# 4. TRANSLATION FUNCTION
# =============================================================================

async def translate_analysis(base_language_analysis, base_language, target_language) -> dict:
    """
    Translate analysis results to target language.

    This function translates the risk assessment, analysis, and recommended
    actions from the base language to the target language using LLM.

    Args:
        base_language_analysis: Original analysis results
        base_language: Language of the original analysis
        target_language: Target language for translation

    Returns:
        dict: Translated analysis results with the same structure as input

    Example:
        translated = await translate_analysis(
            base_language_analysis=english_analysis,
            base_language="en",
            target_language="zh"
        )
    """
    prompt = prompts["translateAnalysis"].format(
        base_language=base_language,
        target_language=target_language,
        risk_level=base_language_analysis.get('risk_level'),
        analysis=base_language_analysis.get('analysis'),
        recommended_action=base_language_analysis.get('recommended_action'),
    )

    completion = await call_sea_lion_llm(prompt=prompt)
    json_response = parse_sealion_json(completion)

    return json_response


# =============================================================================
# 5. COMPREHENSIVE EMAIL ANALYSIS FUNCTION (SINGLE LLM CALL)
# =============================================================================

async def analyze_email_comprehensive(
    subject: str, 
    content: str, 
    from_email: str, 
    reply_to_email: str, 
    target_language: str, 
    signals: dict
) -> dict:
    """
    Perform comprehensive email analysis with single LLM call.

    This function combines language detection, scam analysis, and target language
    output into one efficient Sea-Lion API call, reducing from 3 calls to 1 call.

    Args:
        subject: Email subject line
        content: Email body content  
        from_email: Sender email address
        reply_to_email: Reply-to email address
        target_language: Target language for analysis output
        signals: Extracted auxiliary signals

    Returns:
        dict: Complete analysis results containing:
            - detected_language: ISO-639-1 code of email content
            - risk_level: "high", "medium", or "low" in target language
            - analysis: Detailed analysis explanation in target language
            - recommended_action: Suggested action in target language

    Example:
        result = await analyze_email_comprehensive(
            subject="Account Suspension Notice",
            content="Your account has been suspended...",
            from_email="support@bank.com",
            reply_to_email="noreply@bank.com", 
            target_language="en",
            signals=extracted_signals
        )
        # Returns: {
        #   "detected_language": "en",
        #   "risk_level": "high", 
        #   "analysis": "This email shows multiple red flags...",
        #   "recommended_action": "Do not click any links..."
        # }
    """
    aux_signals = json.dumps(signals or {}, ensure_ascii=False)
    prompt = prompts["analyzeEmailComprehensive"].format(
        target_language=target_language,
        subject=subject,
        content=content,
        from_email=from_email,
        reply_to_email=reply_to_email or "",
        aux_signals=aux_signals,
        available_languages=", ".join(LANGUAGES)
    )

    # Debug: Log the complete prompt being sent to LLM (V1)
    logging.info("="*80)
    logging.info("🔍 EMAIL V1 ANALYSIS - LLM INPUT DEBUG")
    logging.info("="*80)
    logging.info("AUXILIARY SIGNALS (Checker Results):")
    logging.info(aux_signals)
    logging.info("FULL PROMPT BEING SENT TO LLM:")
    logging.info(prompt[:2000] + "..." if len(prompt) > 2000 else prompt)
    logging.info("="*80)

    # Single LLM call combining: language detection + scam analysis + target language output
    completion = await call_sea_lion_llm(prompt=prompt)
    json_response = parse_sealion_json(completion)

    return json_response


# =============================================================================
# EMAIL V2 COMPREHENSIVE ANALYSIS (SEA-LION V4)
# =============================================================================

async def analyze_email_comprehensive_v2(
    subject: str, 
    content: str, 
    from_email: str, 
    reply_to_email: str, 
    target_language: str, 
    signals: dict
) -> dict:
    """
    Perform comprehensive email analysis with single SEA-LION v4 LLM call.
    
    This function analyzes email content for scam indicators using the upgraded
    SEA-LION v4 model without reasoning toggle functionality.
    
    Args:
        subject: Email subject line
        content: Email body/content  
        from_email: Sender email address
        reply_to_email: Reply-to email address
        target_language: Target language for analysis output
        signals: Extracted auxiliary signals

    Returns:
        dict: Complete analysis results containing:
            - detected_language: ISO-639-1 code of email content
            - risk_level: "high", "medium", or "low" in target language
            - analysis: Detailed analysis explanation in target language
            - recommended_action: Suggested action in target language

    Example:
        result = await analyze_email_comprehensive_v2(
            subject="Account Suspension Notice",
            content="Your account has been suspended...",
            from_email="support@bank.com",
            reply_to_email="noreply@bank.com", 
            target_language="en",
            signals=extracted_signals
        )
        # Returns: {
        #   "detected_language": "en",
        #   "risk_level": "high", 
        #   "analysis": "This email shows multiple red flags...",
        #   "recommended_action": "Do not click any links..."
        # }
    """
    aux_signals = json.dumps(signals or {}, ensure_ascii=False)
    prompt = prompts["analyzeEmailComprehensive"].format(
        target_language=target_language,
        subject=subject,
        content=content,
        from_email=from_email,
        reply_to_email=reply_to_email or "",
        aux_signals=aux_signals,
        available_languages=", ".join(LANGUAGES)
    )

    # Debug: Log the complete prompt being sent to LLM (V2)
    logging.info("="*80)
    logging.info("🔍 EMAIL V2 ANALYSIS - LLM INPUT DEBUG")
    logging.info("="*80)
    logging.info("AUXILIARY SIGNALS (Checker Results):")
    logging.info(aux_signals)
    logging.info("FULL PROMPT BEING SENT TO LLM:")
    logging.info(prompt[:2000] + "..." if len(prompt) > 2000 else prompt)
    logging.info("="*80)

    # Single SEA-LION v4 LLM call combining: language detection + scam analysis + target language output
    completion = await call_sea_lion_v4_llm(prompt=prompt)
    json_response = parse_sealion_json(completion)

    return json_response
