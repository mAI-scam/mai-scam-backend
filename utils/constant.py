"""
Centralized constants for the MAI Scam Detection System.

This file contains all reusable constants across the utility modules,
allowing for centralized configuration and easy maintenance.
"""

# =============================================================================
# LANGUAGE SUPPORT
# =============================================================================
LANGUAGES = ["en", "ms", "zh", "vi", "th", "fil",
             "id", "jv", "su", "km", "lo", "my", "ta"]

# =============================================================================
# REGEX PATTERNS
# =============================================================================
URL_PATTERN = r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+"
EMAIL_PATTERN = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
PHONE_PATTERN = r"(?:(?:\+\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d{3,4}[\s-]?\d{3,4})"
HASHTAG_PATTERN = r"#[\w\u4e00-\u9fff]+"
MENTION_PATTERN = r"@[\w\u4e00-\u9fff]+"

# =============================================================================
# SUSPICIOUS DOMAINS AND TLDs
# =============================================================================
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country",
    "gq", "cn", "ru"
}

URL_SHORTENERS = {
    "bit.ly", "t.co", "goo.gl", "tinyurl.com",
    "ow.ly", "is.gd"
}

# =============================================================================
# KNOWN BRANDS FOR LOOKALIKE DETECTION
# =============================================================================
KNOWN_BRANDS = [
    "google", "facebook", "amazon", "apple", "microsoft", "netflix",
    "paypal", "ebay", "alibaba", "tencent", "baidu", "yahoo"
]

# =============================================================================
# KEYWORD CATEGORIES FOR SCAM DETECTION
# =============================================================================

# Email-specific keywords
EMAIL_KEYWORDS = {
    "otp_request": ["otp", "one-time password", "verification code", "6-digit code"],
    "credential_request": ["password", "login", "account details", "pin"],
    "payment_request": ["transfer", "bank", "wire", "crypto", "gift card", "bitcoin", "usdt", "wallet"],
    "urgency": ["urgent", "immediately", "asap", "deadline", "suspend", "suspension", "24 hours", "48 hours"],
    "attachment_mention": ["attached", "attachment", ".pdf", ".zip", ".doc", ".xls"]
}

# Social media-specific keywords
SOCIAL_MEDIA_KEYWORDS = {
    "giveaway_mention": ["giveaway", "free", "win", "prize", "contest", "lucky"],
    "investment_mention": ["investment", "profit", "earn", "money", "crypto", "bitcoin", "trading"],
    "urgency_mention": ["urgent", "limited time", "last chance", "hurry", "asap", "deadline"],
    "romance_scam": ["love", "relationship", "marriage", "dating", "romance"],
    "impersonation": ["official", "verified", "celeb", "celebrity", "brand"],
    "suspicious_contact": ["whatsapp", "telegram", "dm", "direct message", "private message"]
}

# Website-specific keywords
WEBSITE_KEYWORDS = {
    "login_form": ["login", "sign in", "password", "username", "account"],
    "payment_form": ["payment", "credit card", "bank", "transfer", "wire"],
    "urgency_tactics": ["urgent", "limited time", "last chance", "hurry", "asap", "deadline", "suspend"],
    "authority_impersonation": ["government", "official", "bank", "police", "irs", "tax"],
    "investment_scam": ["investment", "profit", "earn", "money", "crypto", "bitcoin", "trading"],
    "tech_support": ["tech support", "computer", "virus", "microsoft", "apple support"],
    "lottery_winner": ["lottery", "winner", "prize", "claim", "million"],
    "romance_scam": ["love", "relationship", "marriage", "dating", "romance"],
    "suspicious_contact": ["whatsapp", "telegram", "dm", "direct message"]
}

# =============================================================================
# ENGAGEMENT THRESHOLDS
# =============================================================================
LOW_ENGAGEMENT_RATE_THRESHOLD = 0.01  # Less than 1%
HIGH_ENGAGEMENT_RATE_THRESHOLD = 0.1  # More than 10%

# =============================================================================
# DOMAIN AGE THRESHOLDS
# =============================================================================
NEW_DOMAIN_THRESHOLD_DAYS = 30

# =============================================================================
# PHONE NUMBER VALIDATION
# =============================================================================
MIN_PHONE_LENGTH = 7

# =============================================================================
# DOMAIN PATTERN THRESHOLDS
# =============================================================================
MAX_HYPHENS_IN_DOMAIN = 2
RANDOM_SUBDOMAIN_PATTERN = r'[a-f0-9]{8,}'

# =============================================================================
# SUSPICIOUS PATH PATTERNS
# =============================================================================
SUSPICIOUS_PATH_KEYWORDS = ["login", "secure", "verify", "confirm"]
