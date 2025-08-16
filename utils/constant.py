"""
Constants for MAI Scam Detection System

This module contains all centralized constants used throughout the application.
All constants are in capital letters for easy identification.

TABLE OF CONTENTS:
==================

CONSTANT SECTIONS:
-----------------
1. LANGUAGES - Supported languages for analysis
2. REGEX PATTERNS - Common regex patterns for text extraction
3. SUSPICIOUS INDICATORS - Domains, TLDs, and keywords for scam detection
4. KEYWORDS - Scam-related keywords for each use case
5. THRESHOLDS - Various thresholds and limits
6. AUTHENTICATION - JWT and API key configuration
7. HASHING - Hashing algorithm configuration

USAGE EXAMPLES:
--------------
from utils.constant import EMAIL_KEYWORDS, URL_PATTERN, CLIENT_TYPES

# Use constants in your code
if any(keyword in text.lower() for keyword in EMAIL_KEYWORDS["urgency"]):
    print("Urgency scam detected")
"""

import os
from setting import Setting

# Load configuration
config = Setting()

# =============================================================================
# LANGUAGE CONSTANTS
# =============================================================================

LANGUAGES = ["en", "zh", "ms", "th", "vi"]

# =============================================================================
# REGEX PATTERNS
# =============================================================================

URL_PATTERN = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
PHONE_PATTERN = r'\+?[\d\s\-\(\)]{7,}'
HASHTAG_PATTERN = r'#\w+'
MENTION_PATTERN = r'@\w+'

# =============================================================================
# SUSPICIOUS DOMAINS AND TLDs
# =============================================================================

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf",
                   ".gq", ".xyz", ".top", ".club", ".online"]
URL_SHORTENERS = ["bit.ly", "tinyurl.com",
                  "goo.gl", "t.co", "is.gd", "v.gd", "ow.ly"]

# =============================================================================
# KNOWN BRANDS (for lookalike detection)
# =============================================================================

KNOWN_BRANDS = [
    "google", "facebook", "amazon", "apple", "microsoft", "netflix", "paypal",
    "ebay", "linkedin", "twitter", "instagram", "whatsapp", "telegram",
    "spotify", "youtube", "discord", "slack", "zoom", "dropbox", "github"
]

# =============================================================================
# EMAIL ANALYSIS KEYWORDS
# =============================================================================

EMAIL_KEYWORDS = {
    "urgency": [
        "urgent", "immediate", "limited time", "act now", "expires soon",
        "urgent action required", "account suspended", "account locked"
    ],
    "financial": [
        "bank transfer", "wire transfer", "payment pending", "refund available",
        "free money", "cash prize", "gift card", "voucher", "discount code"
    ],
    "prizes": [
        "claim your prize", "you've won", "congratulations", "lottery", "inheritance"
    ],
    "security": [
        "verify your account", "security alert", "unusual activity", "login attempt",
        "password reset"
    ]
}

# =============================================================================
# SOCIAL MEDIA ANALYSIS KEYWORDS
# =============================================================================

SOCIAL_MEDIA_KEYWORDS = {
    "engagement": [
        "follow for follow", "like for like", "comment for comment",
        "free followers", "get verified", "blue badge", "viral post"
    ],
    "trending": [
        "trending", "going viral", "share to win", "tag friends"
    ],
    "offers": [
        "limited offer", "exclusive deal", "private account", "premium content"
    ],
    "financial": [
        "crypto giveaway", "bitcoin", "ethereum", "investment opportunity",
        "quick money", "earn from home", "work from home", "side hustle"
    ]
}

# =============================================================================
# WEBSITE ANALYSIS KEYWORDS
# =============================================================================

WEBSITE_KEYWORDS = {
    "authentication": [
        "login", "sign in", "verify", "secure", "account", "password"
    ],
    "financial": [
        "credit card", "banking", "payment", "checkout", "order"
    ],
    "urgency": [
        "limited time", "act now", "exclusive", "discount", "sale"
    ],
    "subscription": [
        "free trial", "subscription", "membership", "premium", "upgrade"
    ],
    "security": [
        "download", "install", "update", "scan", "virus", "malware"
    ]
}

# =============================================================================
# THRESHOLDS AND LIMITS
# =============================================================================

LOW_ENGAGEMENT_RATE_THRESHOLD = 0.01  # 1%
HIGH_ENGAGEMENT_RATE_THRESHOLD = 0.1  # 10%
NEW_DOMAIN_THRESHOLD_DAYS = 30
MIN_PHONE_LENGTH = 7
MAX_HYPHENS_IN_DOMAIN = 3
RANDOM_SUBDOMAIN_PATTERN = r'[a-z0-9]{8,}'
SUSPICIOUS_PATH_KEYWORDS = ["login", "secure", "verify", "confirm"]

# =============================================================================
# AUTHENTICATION CONSTANTS
# =============================================================================

# JWT Configuration
JWT_SECRET_KEY = config.get(
    "JWT_SECRET_KEY", "your-super-secret-jwt-key-change-in-production")
JWT_ALGORITHM = config.get("JWT_ALGORITHM", "HS256")
JWT_EXPIRY_HOURS = config.get("JWT_EXPIRY_HOURS", 24)

# API Key Configuration
API_KEY_LENGTH = config.get("API_KEY_LENGTH", 32)
API_KEY_PREFIX = config.get("API_KEY_PREFIX", "mai_")

# Client Types and Permissions
CLIENT_TYPES = {
    "web_extension": {
        "permissions": ["email_analysis", "website_analysis", "social_media_analysis"],
        "rate_limit": 100,  # requests per hour
        "description": "Web browser extension for real-time scam detection"
    },
    "chatbot": {
        "permissions": ["email_analysis"],
        "rate_limit": 50,  # requests per hour
        "description": "Chatbot integration for email analysis"
    },
    "mobile_app": {
        "permissions": ["email_analysis", "website_analysis", "social_media_analysis"],
        "rate_limit": 200,  # requests per hour
        "description": "Mobile application for scam detection"
    },
    "api_client": {
        "permissions": ["email_analysis", "website_analysis", "social_media_analysis"],
        "rate_limit": 1000,  # requests per hour
        "description": "Third-party API client"
    }
}

# =============================================================================
# HASHING CONSTANTS
# =============================================================================

HASH_ALGORITHM = "sha256"
HASH_LENGTH = 64
