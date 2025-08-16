"""
Social Media Analysis Utilities for MAI Scam Detection System

This module provides specialized functions for analyzing social media content for scam indicators,
including language detection, signal extraction, and LLM-based analysis with platform-specific features.

TABLE OF CONTENTS:
==================

EXPORTED FUNCTIONS:
------------------
1. detect_language
2. extract_social_media_signals
3. analyze_social_media_content
4. translate_analysis

USAGE EXAMPLES:
--------------
# Detect language
language = await detect_language("Check out this amazing offer!")

# Extract signals
signals = extract_social_media_signals(
    platform="facebook",
    content="Win a free iPhone! Click here...",
    author_username="user123",
    post_url="https://facebook.com/post/123",
    author_followers_count=1000,
    engagement_metrics={"likes": 50, "comments": 10, "shares": 5}
)

# Analyze social media content
analysis = await analyze_social_media_content(
    platform="facebook",
    content="Win a free iPhone! Click here...",
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
    LANGUAGES, URL_PATTERN, PHONE_PATTERN, HASHTAG_PATTERN, MENTION_PATTERN,
    SUSPICIOUS_TLDS, URL_SHORTENERS, SOCIAL_MEDIA_KEYWORDS,
    LOW_ENGAGEMENT_RATE_THRESHOLD, HIGH_ENGAGEMENT_RATE_THRESHOLD, MIN_PHONE_LENGTH
)
from utils.llmUtils import parse_sealion_json, call_sea_lion_llm
from prompts.socialmediaPrompts import prompts
import re
import json


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


def _extract_hashtags(text: str) -> list:
    """
    Extract hashtags from text using regex pattern.

    Args:
        text: Input text to search for hashtags

    Returns:
        list: List of found hashtags
    """
    hashtag_pattern = re.compile(HASHTAG_PATTERN)
    return hashtag_pattern.findall(text or "")


def _extract_mentions(text: str) -> list:
    """
    Extract mentions (@username) from text using regex pattern.

    Args:
        text: Input text to search for mentions

    Returns:
        list: List of found mentions
    """
    mention_pattern = re.compile(MENTION_PATTERN)
    return mention_pattern.findall(text or "")


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
    return sorted(set(domains))


# =============================================================================
# 1. LANGUAGE DETECTION FUNCTION
# =============================================================================

async def detect_language(content: str) -> str:
    """
    Detect the base language of social media content using LLM.

    This function uses the Sea Lion LLM to identify the primary language
    of the social media content from a predefined list of supported languages.

    Args:
        content: The social media content to analyze

    Returns:
        str: Language code (e.g., "en", "zh", "ms")

    Example:
        language = await detect_language("Check out this amazing offer!")
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

def extract_social_media_signals(platform: str, content: str, author_username: str = "",
                                 post_url: str = "", author_followers_count: int = None,
                                 engagement_metrics: dict = None) -> dict:
    """
    Extract auxiliary signals from social media content for scam detection.

    This function analyzes social media content to extract various indicators that
    can help identify potential scams, including:
    - URLs, hashtags, mentions, and phone numbers
    - Domain analysis and suspicious patterns
    - Platform-specific keyword heuristics
    - Engagement metrics analysis
    - Platform-specific risk patterns

    Args:
        platform: Social media platform (e.g., "facebook", "instagram", "twitter")
        content: Post content
        author_username: Author's username
        post_url: URL of the post
        author_followers_count: Number of followers (optional)
        engagement_metrics: Engagement data (likes, comments, shares, views) (optional)

    Returns:
        dict: Structured signal data with the following keys:
            - artifacts: URLs, domains, hashtags, mentions, phone numbers
            - platform_meta: Platform-specific metadata
            - engagement_metrics: Raw engagement data
            - engagement_signals: Calculated engagement indicators
            - heuristics: Keyword-based scam indicators
            - platform_risks: Platform-specific risk patterns

    Example:
        signals = extract_social_media_signals(
            platform="facebook",
            content="Win a free iPhone! Click here to claim...",
            author_username="user123",
            post_url="https://facebook.com/post/123",
            author_followers_count=1000,
            engagement_metrics={"likes": 50, "comments": 10, "shares": 5}
        )
    """
    # Extract text-based signals
    urls = _extract_urls(content)
    url_domains = _domains_from_urls(urls)
    hashtags = _extract_hashtags(content)
    mentions = _extract_mentions(content)
    phone_numbers = _extract_phone_numbers(content)

    # Platform-specific analysis
    platform_lower = platform.lower()

    # Heuristic keyword signals for social media
    lowered = content.lower()
    keywords = {}
    for category, keyword_list in SOCIAL_MEDIA_KEYWORDS.items():
        keywords[category] = any(k in lowered for k in keyword_list)

    # Suspicious domains and TLDs
    has_shortened = any(d in URL_SHORTENERS for d in url_domains)
    has_suspicious_tld = any(
        d.split(".")[-1] in SUSPICIOUS_TLDS for d in url_domains if "." in d)

    # Engagement analysis
    engagement_signals = {}
    if engagement_metrics:
        likes = engagement_metrics.get('likes', 0)
        comments = engagement_metrics.get('comments', 0)
        shares = engagement_metrics.get('shares', 0)
        views = engagement_metrics.get('views', 0)

        total_engagement = likes + comments + shares
        if author_followers_count and author_followers_count > 0:
            engagement_rate = total_engagement / author_followers_count
            engagement_signals = {
                "low_engagement_rate": engagement_rate < LOW_ENGAGEMENT_RATE_THRESHOLD,
                "high_engagement_rate": engagement_rate > HIGH_ENGAGEMENT_RATE_THRESHOLD,
                "engagement_to_follower_ratio": engagement_rate
            }

    # Platform-specific risk patterns
    platform_risks = {
        "facebook": {
            "fake_giveaway": keywords["giveaway_mention"] and has_shortened,
            "impersonation": keywords["impersonation"] and not author_username.startswith("verified"),
        },
        "instagram": {
            "fake_giveaway": keywords["giveaway_mention"] and has_shortened,
            "suspicious_promotion": keywords["investment_mention"] and has_suspicious_tld,
        },
        "twitter": {
            "fake_news": keywords["impersonation"] and has_shortened,
            "crypto_scam": keywords["investment_mention"] and "crypto" in lowered,
        },
        "tiktok": {
            "fake_challenge": keywords["giveaway_mention"] and keywords["urgency_mention"],
            "suspicious_promotion": keywords["investment_mention"] and has_suspicious_tld,
        },
        "linkedin": {
            "fake_job": keywords["investment_mention"] and keywords["urgency_mention"],
            "business_scam": keywords["investment_mention"] and has_suspicious_tld,
        }
    }

    return {
        "artifacts": {
            "urls": urls,
            "url_domains": url_domains,
            "hashtags": hashtags,
            "mentions": mentions,
            "phone_numbers": phone_numbers,
        },
        "platform_meta": {
            "platform": platform_lower,
            "author_username": author_username,
            "post_url": post_url,
            "author_followers_count": author_followers_count,
        },
        "engagement_metrics": engagement_metrics or {},
        "engagement_signals": engagement_signals,
        "heuristics": {
            **keywords,
            "has_shortened_link": has_shortened,
            "has_suspicious_tld": has_suspicious_tld,
            "link_count": len(urls),
            "hashtag_count": len(hashtags),
            "mention_count": len(mentions),
        },
        "platform_risks": platform_risks.get(platform_lower, {}),
    }


# =============================================================================
# 3. SOCIAL MEDIA ANALYSIS FUNCTION
# =============================================================================

async def analyze_social_media_content(platform: str, content: str, base_language: str, signals: dict | None = None) -> dict:
    """
    Perform comprehensive social media analysis using LLM.

    This function uses the Sea Lion LLM to analyze social media content for scam indicators,
    taking into account the extracted signals and providing a detailed risk assessment.

    Args:
        platform: Social media platform (e.g., "facebook", "instagram", "twitter")
        content: Post content
        base_language: Detected language of the content
        signals: Extracted auxiliary signals (optional)

    Returns:
        dict: Analysis results containing:
            - risk_level: "high", "medium", or "low"
            - analysis: Detailed analysis explanation
            - recommended_action: Suggested action for the user

    Example:
        analysis = await analyze_social_media_content(
            platform="facebook",
            content="Win a free iPhone! Click here to claim...",
            base_language="en",
            signals=extracted_signals
        )
    """
    aux_signals = json.dumps(signals or {}, ensure_ascii=False)
    prompt = prompts["analyzeSocialMedia"].format(
        language=base_language,
        platform=platform,
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
