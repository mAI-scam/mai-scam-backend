"""
Website Analysis Utilities for MAI Scam Detection System

This module provides specialized functions for analyzing website content for scam indicators,
including language detection, signal extraction, and LLM-based analysis with domain-specific features.

TABLE OF CONTENTS:
==================

EXPORTED FUNCTIONS:
------------------
1. detect_language
2. extract_website_signals
3. analyze_website_content
4. translate_analysis

USAGE EXAMPLES:
--------------
# Detect language
language = await detect_language("Welcome to our secure banking portal")

# Extract signals
signals = extract_website_signals(
    url="https://secure-bank-login.com",
    title="Secure Banking Login",
    content="Enter your credentials to access your account...",
    screenshot_data="base64_encoded_screenshot",
    metadata={"ssl_valid": True, "domain_age_days": 5}
)

# Analyze website content
analysis = await analyze_website_content(
    url="https://secure-bank-login.com",
    title="Secure Banking Login",
    content="Enter your credentials to access your account...",
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
    SUSPICIOUS_TLDS, URL_SHORTENERS, KNOWN_BRANDS, WEBSITE_KEYWORDS,
    NEW_DOMAIN_THRESHOLD_DAYS, MIN_PHONE_LENGTH, MAX_HYPHENS_IN_DOMAIN,
    RANDOM_SUBDOMAIN_PATTERN, SUSPICIOUS_PATH_KEYWORDS
)
from utils.llmUtils import parse_sealion_json, call_sea_lion_llm
from prompts.websitePrompts import prompts
import re
import json
from urllib.parse import urlparse


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


def _parse_domain_info(url: str) -> dict:
    """
    Extract domain information from URL.

    This function parses a URL to extract various domain components
    including TLD, SLD, path, query parameters, and scheme.

    Args:
        url: URL to parse

    Returns:
        dict: Domain information with keys:
            - full_domain: Complete domain name
            - tld: Top-level domain
            - sld: Second-level domain
            - path: URL path
            - query: Query parameters
            - scheme: URL scheme (http/https)
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query

        # Extract domain parts
        domain_parts = domain.split('.')
        tld = domain_parts[-1] if len(domain_parts) > 1 else ""
        sld = domain_parts[-2] if len(domain_parts) > 2 else ""

        return {
            "full_domain": domain,
            "tld": tld,
            "sld": sld,
            "path": path,
            "query": query,
            "scheme": parsed.scheme,
        }
    except Exception:
        return {
            "full_domain": "",
            "tld": "",
            "sld": "",
            "path": "",
            "query": "",
            "scheme": "",
        }


def _is_lookalike_domain(domain: str, known_brands: list = None) -> bool:
    """
    Check if domain is a lookalike of known brands.

    This function compares a domain against a list of known brand names
    to detect potential typosquatting or brand impersonation attempts.

    Args:
        domain: Domain to check
        known_brands: List of known brand names (optional, uses default if not provided)

    Returns:
        bool: True if domain appears to be a lookalike, False otherwise
    """
    if not known_brands:
        known_brands = KNOWN_BRANDS

    domain_lower = domain.lower()
    for brand in known_brands:
        if brand in domain_lower and domain_lower != brand:
            return True
    return False


# =============================================================================
# 1. LANGUAGE DETECTION FUNCTION
# =============================================================================

async def detect_language(content: str) -> str:
    """
    Detect the base language of website content using LLM.

    This function uses the Sea Lion LLM to identify the primary language
    of the website content from a predefined list of supported languages.

    Args:
        content: The website content to analyze

    Returns:
        str: Language code (e.g., "en", "zh", "ms")

    Example:
        language = await detect_language("Welcome to our secure banking portal")
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

def extract_website_signals(url: str, title: str = "", content: str = "",
                            screenshot_data: str = "", metadata: dict = None) -> dict:
    """
    Extract auxiliary signals from website content for scam detection.

    This function analyzes website content to extract various indicators that
    can help identify potential scams, including:
    - URLs, emails, and phone numbers
    - Domain analysis and suspicious patterns
    - SSL and security information
    - Form detection and suspicious patterns
    - Keyword-based heuristics for different scam types

    Args:
        url: Website URL
        title: Page title
        content: Page content
        screenshot_data: Base64 encoded screenshot (optional)
        metadata: Website metadata including SSL info, domain age (optional)

    Returns:
        dict: Structured signal data with the following keys:
            - artifacts: URLs, emails, phone numbers
            - domain_analysis: Domain information and suspicious patterns
            - content_analysis: Content metadata and screenshot info
            - ssl_security: SSL certificate and security information
            - form_indicators: Form detection heuristics
            - suspicious_patterns: Domain and path suspicious patterns
            - heuristics: Keyword-based scam indicators
            - metadata: Raw metadata

    Example:
        signals = extract_website_signals(
            url="https://secure-bank-login.com",
            title="Secure Banking Login",
            content="Enter your credentials to access your account...",
            screenshot_data="base64_encoded_screenshot",
            metadata={"ssl_valid": True, "domain_age_days": 5}
        )
    """
    # Extract text-based signals
    urls = _extract_urls(content or "")
    emails = _extract_emails(content or "")
    phone_numbers = _extract_phone_numbers(content or "")

    # Parse domain information
    domain_info = _parse_domain_info(url)

    # Domain analysis
    has_suspicious_tld = domain_info["tld"] in SUSPICIOUS_TLDS
    has_shortened = domain_info["full_domain"] in URL_SHORTENERS
    is_lookalike = _is_lookalike_domain(domain_info["full_domain"])

    # Content analysis
    text_for_analysis = f"{title or ''} {content or ''}".lower()

    # Keyword-based heuristics
    keywords = {}
    for category, keyword_list in WEBSITE_KEYWORDS.items():
        keywords[category] = any(k in text_for_analysis for k in keyword_list)

    # SSL and security analysis
    ssl_signals = {}
    if metadata:
        ssl_signals = {
            "has_ssl": metadata.get("ssl_valid", False),
            "ssl_expired": metadata.get("ssl_expired", False),
            "domain_age_days": metadata.get("domain_age_days", 0),
            "is_new_domain": metadata.get("domain_age_days", 0) < NEW_DOMAIN_THRESHOLD_DAYS,
        }

    # Form detection (basic heuristic)
    form_indicators = {
        "has_input_fields": any(k in text_for_analysis for k in ["input", "form", "submit", "button"]),
        "has_password_field": "password" in text_for_analysis,
        "has_email_field": "email" in text_for_analysis,
    }

    # Suspicious patterns
    suspicious_patterns = {
        "random_subdomain": bool(re.search(RANDOM_SUBDOMAIN_PATTERN, domain_info["full_domain"])),
        "numbers_in_domain": bool(re.search(r'\d+', domain_info["full_domain"])),
        "multiple_hyphens": domain_info["full_domain"].count('-') > MAX_HYPHENS_IN_DOMAIN,
        "suspicious_path": any(k in domain_info["path"] for k in SUSPICIOUS_PATH_KEYWORDS),
    }

    return {
        "artifacts": {
            "urls": urls,
            "emails": emails,
            "phone_numbers": phone_numbers,
        },
        "domain_analysis": {
            **domain_info,
            "has_suspicious_tld": has_suspicious_tld,
            "has_shortened": has_shortened,
            "is_lookalike": is_lookalike,
        },
        "content_analysis": {
            "title": title,
            "content_length": len(content or ""),
            "has_screenshot": bool(screenshot_data),
        },
        "ssl_security": ssl_signals,
        "form_indicators": form_indicators,
        "suspicious_patterns": suspicious_patterns,
        "heuristics": {
            **keywords,
            "link_count": len(urls),
            "email_count": len(emails),
            "phone_count": len(phone_numbers),
        },
        "metadata": metadata or {},
    }


# =============================================================================
# 3. WEBSITE ANALYSIS FUNCTION
# =============================================================================

async def analyze_website_content(url: str, title: str, content: str, base_language: str, signals: dict | None = None) -> dict:
    """
    Perform comprehensive website analysis using LLM.

    This function uses the Sea Lion LLM to analyze website content for scam indicators,
    taking into account the extracted signals and providing a detailed risk assessment.

    Args:
        url: Website URL
        title: Page title
        content: Page content
        base_language: Detected language of the content
        signals: Extracted auxiliary signals (optional)

    Returns:
        dict: Analysis results containing:
            - risk_level: "high", "medium", or "low"
            - analysis: Detailed analysis explanation
            - recommended_action: Suggested action for the user

    Example:
        analysis = await analyze_website_content(
            url="https://secure-bank-login.com",
            title="Secure Banking Login",
            content="Enter your credentials to access your account...",
            base_language="en",
            signals=extracted_signals
        )
    """
    aux_signals = json.dumps(signals or {}, ensure_ascii=False)
    prompt = prompts["analyzeWebsite"].format(
        language=base_language,
        url=url,
        title=title or "",
        content=content or "",
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
