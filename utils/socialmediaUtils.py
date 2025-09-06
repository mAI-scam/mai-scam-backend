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
from utils.llmUtils import parse_sealion_json, call_sea_lion_llm, call_sea_lion_v4_llm
from prompts.socialmediaPrompts import prompts
import re
import json
import base64
import os
import logging


# =============================================================================
# HELPER FUNCTIONS FOR SIGNAL EXTRACTION
# =============================================================================

def encode_image_to_base64(image_path: str) -> str:
    """
    Encode image to base64 string for multimodal AI analysis.
    
    Args:
        image_path: Path to the image file
        
    Returns:
        str: Base64 encoded image string
        
    Raises:
        FileNotFoundError: If the image file doesn't exist
        Exception: If encoding fails
        
    Example:
        base64_image = encode_image_to_base64("test-scam.jpg")
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image file not found: {image_path}")
    
    try:
        with open(image_path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode('utf-8')
    except Exception as e:
        raise Exception(f"Failed to encode image {image_path}: {str(e)}")


def decode_base64_to_image(base64_string: str, output_path: str) -> None:
    """
    Decode base64 string to image file (utility for testing).
    
    Args:
        base64_string: Base64 encoded image string
        output_path: Path where to save the decoded image
        
    Raises:
        Exception: If decoding fails
    """
    try:
        image_data = base64.b64decode(base64_string)
        with open(output_path, "wb") as image_file:
            image_file.write(image_data)
    except Exception as e:
        raise Exception(f"Failed to decode base64 to image: {str(e)}")

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
            "fake_giveaway": keywords["financial"] and has_shortened,
            "impersonation": keywords["engagement"] and not author_username.startswith("verified"),
        },
        "instagram": {
            "fake_giveaway": keywords["financial"] and has_shortened,
            "suspicious_promotion": keywords["financial"] and has_suspicious_tld,
        },
        "twitter": {
            "fake_news": keywords["engagement"] and has_shortened,
            "crypto_scam": keywords["financial"] and "crypto" in lowered,
        },
        "tiktok": {
            "fake_challenge": keywords["financial"] and keywords["trending"],
            "suspicious_promotion": keywords["financial"] and has_suspicious_tld,
        },
        "linkedin": {
            "fake_job": keywords["financial"] and keywords["trending"],
            "business_scam": keywords["financial"] and has_suspicious_tld,
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

    # Debug: Log the complete prompt being sent to LLM (V1)
    logging.info("="*80)
    logging.info("🔍 SOCIAL MEDIA V1 ANALYSIS - LLM INPUT DEBUG")
    logging.info("="*80)
    logging.info("AUXILIARY SIGNALS (Checker Results):")
    logging.info(aux_signals)
    logging.info("FULL PROMPT BEING SENT TO LLM:")
    logging.info(prompt[:2000] + "..." if len(prompt) > 2000 else prompt)
    logging.info("="*80)

    completion = await call_sea_lion_llm(prompt=prompt)
    json_response = parse_sealion_json(completion)

    return json_response


# =============================================================================
# 3.5. MULTIMODAL SOCIAL MEDIA ANALYSIS FUNCTION (v2 with Sea-Lion v4)
# =============================================================================

async def analyze_social_media_multimodal_v2(
    platform: str, 
    content: str, 
    base64_image: str, 
    target_language: str, 
    signals: dict | None = None
) -> dict:
    """
    Perform comprehensive multimodal social media analysis using Sea-Lion v4 LLM.
    
    This function uses the Sea-Lion v4 LLM to analyze both text content and images
    for scam indicators, providing a more comprehensive analysis that combines
    textual and visual cues.
    
    Args:
        platform: Social media platform (e.g., "facebook", "instagram", "twitter")
        content: Post content/text
        base64_image: Base64 encoded image string
        target_language: Target language for analysis output
        signals: Extracted auxiliary signals (optional)
        
    Returns:
        dict: Analysis results containing:
            - detected_language: Detected language of the content
            - risk_level: "high", "medium", or "low"
            - analysis: Detailed analysis explanation covering both text and image
            - recommended_action: Suggested action for the user
            - image_analysis: Specific findings from image analysis
            - text_analysis: Specific findings from text analysis
            
    Example:
        analysis = await analyze_social_media_multimodal_v2(
            platform="facebook",
            content="Win a free iPhone! Click here to claim...",
            base64_image="iVBORw0KGgoAAAANSUhEUgAA...",
            target_language="en",
            signals=extracted_signals
        )
    """
    from models.clients import get_sea_lion_v4_client
    
    aux_signals = json.dumps(signals or {}, ensure_ascii=False)
    
    # Create multimodal prompt for Sea-Lion v4
    text_prompt = f"""
You are an expert social media scam detector analyzing both text content and visual content from a {platform} post with focus on providing precise, actionable recommendations for public users.

TEXT CONTENT: {content}

AUXILIARY SIGNALS: {aux_signals}

TASK: Analyze both the provided image and text content for scam indicators with focus on key risk factors. Consider:

1. IMAGE ANALYSIS PRIORITIES:
   - Brand impersonation: Fake logos, copied official designs, fraudulent verification badges
   - Financial fraud visuals: Fake payment screenshots, fabricated earnings, investment charts
   - Quality assessment: Professional vs amateur design (legitimate brands maintain quality)
   - Text extraction: OCR any visible text and analyze for scam language patterns
   - Visual manipulation: Doctored screenshots, fake testimonials, misleading before/after

2. TEXT ANALYSIS PRIORITIES:
   - Financial exploitation: Money requests, investment "opportunities", get-rich-quick promises
   - Social engineering: Urgency tactics, emotional manipulation, fear-based appeals
   - Platform inconsistencies: Mismatched usernames, fake verification claims
   - Contact method red flags: Requests to move to WhatsApp/Telegram, suspicious phone numbers

3. COMBINED MULTIMODAL ANALYSIS:
   - Narrative consistency: Do image and text support the same credible story?
   - Platform context: Does the content match expected {platform} post patterns?
   - Scam sophistication: Professional visuals with amateur text (or vice versa)

4. PLATFORM-SPECIFIC CONSIDERATIONS for {platform}:
   - Facebook/Instagram: Giveaway scams, fake brand partnerships, romance exploitation
   - Twitter/X: Crypto pump schemes, fake news monetization, impersonation with stolen verification
   - TikTok: Challenge scams, product fraud, targeting younger demographics
   - LinkedIn: Fake job offers, pyramid recruiting, executive impersonation

LANGUAGE DETECTION: First detect the primary language of the text content from these options: {', '.join(LANGUAGES)}

ANALYSIS FOCUS:
- Identify the single most critical risk factor from image + text combination
- Explain why this specific pattern is concerning on {platform}
- Provide specific, actionable guidance for general public users

ACTIONABLE RECOMMENDATIONS:
HIGH RISK: "Block account, report to {platform}, never send money/info"
MEDIUM RISK: "Verify account legitimacy, check official sources before engaging"
LOW RISK: "Appears normal, but remain cautious with personal information"

You must return EXACTLY one minified JSON object with these keys and nothing else.
No prose, no markdown, no code fences.
All text fields must be in TARGET_LANGUAGE ({target_language}).

Schema:
{{
    "detected_language": "<language_code>",
    "risk_level": "<high|medium|low in TARGET_LANGUAGE>",
    "analysis": "<precise 1-2 sentences focusing on main risk factor in TARGET_LANGUAGE>",
    "recommended_action": "<specific actionable advice for public users in TARGET_LANGUAGE>",
    "image_analysis": "<key visual scam indicators in TARGET_LANGUAGE>",
    "text_analysis": "<key textual scam indicators in TARGET_LANGUAGE>"
}}

IMPORTANT:
- Focus on single most critical combined risk factor
- Make recommendations specific and actionable for general {platform} users
- Use clear, non-technical language
"""
    
    # Debug: Log the complete prompt being sent to LLM (V2 Multimodal)
    logging.info("="*80)
    logging.info("🔍 SOCIAL MEDIA V2 MULTIMODAL ANALYSIS - LLM INPUT DEBUG")
    logging.info("="*80)
    logging.info("AUXILIARY SIGNALS (Checker Results):")
    logging.info(aux_signals)
    logging.info("FULL TEXT PROMPT BEING SENT TO LLM:")
    logging.info(text_prompt[:2000] + "..." if len(text_prompt) > 2000 else text_prompt)
    logging.info(f"IMAGE PROVIDED: {'Yes' if base64_image else 'No'}")
    logging.info("="*80)

    try:
        client = get_sea_lion_v4_client()
        
        # Create multimodal message with both image and text
        completion = client.chat.completions.create(
            model="aisingapore/Gemma-SEA-LION-v4-27B-IT",
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{base64_image}"
                            }
                        },
                        {
                            "type": "text",
                            "text": text_prompt
                        }
                    ]
                }
            ]
        )
        
        json_response = parse_sealion_json(completion)
        return json_response
        
    except Exception as e:
        # Fallback to text-only analysis if multimodal fails
        print(f"Multimodal analysis failed, falling back to text-only: {str(e)}")
        return await analyze_social_media_content_v2(platform, content, target_language, signals)


async def analyze_social_media_content_v2(
    platform: str, 
    content: str, 
    target_language: str, 
    signals: dict | None = None
) -> dict:
    """
    Perform comprehensive social media analysis using Sea-Lion v4 LLM (text-only fallback).
    
    This is a v2 version that uses Sea-Lion v4 and provides comprehensive analysis
    including language detection in a single call.
    
    Args:
        platform: Social media platform
        content: Post content
        target_language: Target language for analysis output
        signals: Extracted auxiliary signals (optional)
        
    Returns:
        dict: Analysis results with detected_language, risk_level, analysis, recommended_action
    """
    aux_signals = json.dumps(signals or {}, ensure_ascii=False)
    
    prompt = f"""
You are an expert social media scam detector analyzing {platform} post content with focus on providing precise, actionable recommendations for public users.

CONTENT: {content}

AUXILIARY SIGNALS: {aux_signals}

TASK:
1. LANGUAGE DETECTION: First detect the primary language from these options: {', '.join(LANGUAGES)}

2. SCAM ANALYSIS PRIORITIES:
   PRIMARY INDICATORS (High Risk):
   - Financial fraud: Fake giveaways, investment schemes, get-rich-quick promises
   - Identity impersonation: Fake celebrity/brand accounts, verification fraud
   - Credential harvesting: Account verification scams, fake login prompts
   - Social engineering: Romance scams, urgent money requests

   SECONDARY INDICATORS (Medium Risk):
   - Engagement anomalies: Bot patterns, suspicious follower counts
   - Misleading content: Unrealistic claims, fake testimonials
   - Platform inconsistencies: Wrong verification status, mismatched details

3. PLATFORM-SPECIFIC FOCUS for {platform}:
   - Facebook/Instagram: Brand giveaway scams, romance fraud, fake investment groups
   - Twitter/X: Crypto scams, impersonation with stolen verification, fake news monetization
   - TikTok: Challenge exploitation, product fraud, targeting younger users
   - LinkedIn: Fake recruitment, pyramid schemes, executive impersonation

4. ANALYSIS FOCUS:
   - Identify single most critical risk factor
   - Explain why this matters specifically on {platform}
   - Provide actionable guidance for general public

ACTIONABLE RECOMMENDATIONS:
HIGH RISK: "Block this account and report as scam to {platform}"
MEDIUM RISK: "Verify account legitimacy through official sources before engaging"
LOW RISK: "This appears normal, but remain cautious with personal information"
   
You must return EXACTLY one minified JSON object with these keys and nothing else.
No prose, no markdown, no code fences.
All text fields must be in TARGET_LANGUAGE ({target_language}).

Schema:
{{
    "detected_language": "<language_code>",
    "risk_level": "<high|medium|low in TARGET_LANGUAGE>", 
    "analysis": "<precise 1-2 sentences focusing on main risk factor in TARGET_LANGUAGE>",
    "recommended_action": "<specific actionable advice for public users in TARGET_LANGUAGE>",
    "image_analysis": "N/A - text-only analysis",
    "text_analysis": "<key scam indicators in TARGET_LANGUAGE>"
}}

IMPORTANT:
- Focus analysis on single most critical risk factor
- Make recommendations specific and actionable for general {platform} users  
- Use clear, non-technical language
"""
    
    # Debug: Log the complete prompt being sent to LLM (V2 Text-only)
    logging.info("="*80)
    logging.info("🔍 SOCIAL MEDIA V2 TEXT-ONLY ANALYSIS - LLM INPUT DEBUG")
    logging.info("="*80)
    logging.info("AUXILIARY SIGNALS (Checker Results):")
    logging.info(aux_signals)
    logging.info("FULL PROMPT BEING SENT TO LLM:")
    logging.info(prompt[:2000] + "..." if len(prompt) > 2000 else prompt)
    logging.info("="*80)

    completion = await call_sea_lion_v4_llm(prompt=prompt)
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
