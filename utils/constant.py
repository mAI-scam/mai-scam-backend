"""
Constants for MAI Scam Detection System

This module contains all centralized constants used throughout the application.
All constants are in capital letters for easy identification.

TABLE OF CONTENTS:
==================

CONSTANT SECTIONS:
-----------------
1. ENDPOINT CONFIGURATION - API endpoint protection settings
2. AUTHENTICATION & SECURITY - JWT, API keys, and client types
3. LANGUAGES - Supported languages for analysis
4. REGEX PATTERNS - Common regex patterns for text extraction
5. SUSPICIOUS INDICATORS - Domains, TLDs, and keywords for scam detection
6. KEYWORDS - Scam-related keywords for each use case
7. THRESHOLDS - Various thresholds and limits
8. HASHING - Hashing algorithm configuration

USAGE EXAMPLES:
--------------
from utils.constant import PUBLIC_ENDPOINTS, EMAIL_KEYWORDS, URL_PATTERN

# Check if endpoint is public
if path in PUBLIC_ENDPOINTS:
    skip_auth = True

# Use constants in your code
if any(keyword in text.lower() for keyword in EMAIL_KEYWORDS["urgency"]):
    print("Urgency scam detected")
"""

import os
from setting import Setting

# Load configuration
config = Setting()

# =============================================================================
# ENDPOINT PROTECTION CONFIGURATION
# =============================================================================

# Public endpoints (no authentication required)
PUBLIC_ENDPOINTS = [
    "/",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/health",
    "/email/",
    "/debug/auth",
    "/auth/token",
    "/auth/api-key",
    "/auth/verify"
]

# Endpoints that require authentication but no specific permissions
AUTH_REQUIRED_ENDPOINTS = [
    "/email/v1/analyze",
    "/email/v1/translate",
    "/email/v2/analyze",
    "/socialmedia/v1/analyze",
    "/socialmedia/v1/translate",
    "/website/v1/analyze",
    "/website/v1/translate",
    "/website/v2/analyze"
]

# Endpoints with specific permission requirements
PERMISSION_PROTECTED_ENDPOINTS = {
    "/email/v1/analyze": ["email_analysis"],
    "/email/v1/translate": ["email_analysis"],
    "/email/v2/analyze": ["email_analysis"],
    "/socialmedia/v1/analyze": ["social_media_analysis"],
    "/socialmedia/v1/translate": ["social_media_analysis"],
    "/website/v1/analyze": ["website_analysis"],
    "/website/v1/translate": ["website_analysis"],
    "/website/v2/analyze": ["website_analysis"]
}

# Admin-only endpoints
ADMIN_ENDPOINTS = [
    "/auth/keys",
    "/auth/keys/{key_id}",
    "/debug/admin"
]

# =============================================================================
# AUTHENTICATION & SECURITY CONFIGURATION
# =============================================================================

# JWT Configuration
JWT_SECRET_KEY = "your-super-secret-jwt-key-change-in-production"
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24

# API Key Configuration
API_KEY_LENGTH = 32
API_KEY_PREFIX = "mai_"

# Client Types and their rate limits
CLIENT_TYPES = {
    "web_extension": {
        # 100 requests per hour
        "rate_limit": {"requests": 100, "window": 3600},
        "default_permissions": ["email_analysis", "website_analysis", "social_media_analysis"]
    },
    "chatbot": {
        # 1000 requests per hour
        "rate_limit": {"requests": 1000, "window": 3600},
        "default_permissions": ["email_analysis", "website_analysis", "social_media_analysis"]
    },
    "mobile_app": {
        "rate_limit": {"requests": 50, "window": 3600},  # 50 requests per hour
        "default_permissions": ["email_analysis", "website_analysis", "social_media_analysis"]
    },
    "admin": {
        # 10000 requests per hour
        "rate_limit": {"requests": 10000, "window": 3600},
        "default_permissions": ["*"]  # All permissions
    }
}

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
# Removed NEW_DOMAIN_THRESHOLD_DAYS - domain age cannot be reliably detected from frontend
MIN_PHONE_LENGTH = 7
MAX_HYPHENS_IN_DOMAIN = 3
RANDOM_SUBDOMAIN_PATTERN = r'[a-z0-9]{8,}'
SUSPICIOUS_PATH_KEYWORDS = ["login", "secure", "verify", "confirm"]

# =============================================================================
# HASHING CONSTANTS
# =============================================================================

HASH_ALGORITHM = "sha256"
HASH_LENGTH = 64
