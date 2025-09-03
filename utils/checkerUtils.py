"""
Checker Utilities for MAI Scam Detection System

This module provides utilities for checking URLs, emails, and phone numbers
against various validation services and databases. Designed to be modular
and reusable across different API endpoints.
"""

import requests
import json
import re
import gzip
import os
from typing import Dict, List, Optional, Tuple
import logging

from setting import Setting

config = Setting()

# Global variable to store phish data (for endpoint efficiency)
_phish_data = None

# =============================================================================
# 1. URL EXTRACTION AND PHISHING CHECK
# =============================================================================

def extract_urls_from_text(text: str) -> List[str]:
    """
    Extract URLs from text content.
    
    Args:
        text: Text content to extract URLs from
        
    Returns:
        List of extracted URLs
    """
    logging.info("🔍 DEBUG: Starting URL extraction from text")
    logging.info(f"Input text: {text}")
    
    # Primary pattern for URLs with protocol - strict ASCII-only URLs
    # This pattern only captures standard ASCII characters used in URLs
    # and stops at non-ASCII characters (Chinese, Thai, Vietnamese, etc.)
    url_pattern = r'http[s]?://[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+(?=[\s\u00A0\u4e00-\u9fff\u0e00-\u0e7f\u1ea0-\u1ef9]|$)'
    urls = re.findall(url_pattern, text)
    logging.info(f"URLs found with http/https pattern: {urls}")
    
    # Clean up URLs to remove trailing punctuation and non-English words
    cleaned_urls = []
    for url in urls:
        # Remove trailing punctuation
        cleaned_url = re.sub(r'[,;!?.\u00A0]+$', '', url)
        
        # Remove common words from various languages that might be attached
        # Malay/Indonesian
        cleaned_url = re.sub(r'(Sekiranya|sekiranya|anda|Anda|jika|Jika|untuk|Untuk|dengan|Dengan)$', '', cleaned_url)
        # Thai common words (transliterated)
        cleaned_url = re.sub(r'(khrap|kha|dai|mai|thii|nai|kap|laew)$', '', cleaned_url, re.IGNORECASE)
        # Vietnamese common words
        cleaned_url = re.sub(r'(neu|va|hoac|thi|cua|cho|trong|voi)$', '', cleaned_url, re.IGNORECASE)
        # Chinese pinyin common words
        cleaned_url = re.sub(r'(ruguo|jiushi|weile|yinwei|suoyi|danshi|zhege|nage)$', '', cleaned_url, re.IGNORECASE)
        
        # Remove trailing slashes and clean up
        cleaned_url = cleaned_url.rstrip('/')
        
        # Remove any URLs that end with non-ASCII characters (safety check)
        if re.search(r'[\u00A0\u4e00-\u9fff\u0e00-\u0e7f\u1ea0-\u1ef9]$', cleaned_url):
            # Find the last ASCII character and truncate there
            match = re.search(r'([a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+)', cleaned_url)
            if match:
                cleaned_url = match.group(1).rstrip('/')
        
        if cleaned_url != url:
            logging.info(f"Cleaned URL: {url} -> {cleaned_url}")
        
        # Only add if it's still a valid-looking URL after cleaning
        if cleaned_url and len(cleaned_url) > 10:  # Minimum reasonable URL length
            cleaned_urls.append(cleaned_url)
        else:
            logging.info(f"Rejected URL after cleaning: {cleaned_url}")
    
    urls = cleaned_urls
    
    # More restrictive pattern for domains without protocol 
    # Only match if it looks like a real domain (not random words with dots)
    domain_pattern = r'(?:^|\s|[\[\(])(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)(?=\s|$|[\]\)]|[.,!?])'
    potential_domains = re.findall(domain_pattern, text, re.MULTILINE)
    logging.info(f"Potential domains found: {potential_domains}")
    
    # Add http:// prefix to potential domains, but be more selective
    for domain in potential_domains:
        # Skip if domain looks like common words or has suspicious patterns
        if (len(domain.split('.')) >= 2 and 
            not any(word in domain.lower() for word in ['anda.', 'dibekukan.', 'untuk.', 'yang.', 'ini.', 'akan.']) and
            not any(existing_url in domain for existing_url in urls)):
            full_url = 'http://' + domain
            urls.append(full_url)
            logging.info(f"Added domain as URL: {full_url}")
        else:
            logging.info(f"Skipped suspicious domain: {domain}")
    
    final_urls = list(set(urls))  # Remove duplicates
    logging.info(f"Final extracted URLs: {final_urls}")
    return final_urls

def load_phishtank_database(force_download: bool = False, app_key: Optional[str] = None) -> bool:
    """
    Load PhishTank database from local file or download if needed.
    
    Args:
        force_download: Force download even if local file exists
        app_key: Optional PhishTank application key
        
    Returns:
        True if database loaded successfully, False otherwise
    """
    global _phish_data
    
    local_file = 'phishtank_data.json'
    
    # Try to load from local file first (unless forced to download)
    if not force_download and os.path.exists(local_file):
        try:
            with open(local_file, 'r') as f:
                _phish_data = json.load(f)
            logging.info(f"Loaded {len(_phish_data)} phishing URLs from local database")
            return True
        except Exception as e:
            logging.error(f"Error loading local database: {e}")
    
    # Download database
    try:
        base_url = "http://data.phishtank.com/data"
        headers = {'User-Agent': 'phishtank/mai-scam-checker'}
        
        # Construct URL with app key if provided
        if app_key:
            url = f"{base_url}/{app_key}/online-valid.json.gz"
        else:
            url = f"{base_url}/online-valid.json.gz"
        
        logging.info("Downloading PhishTank database...")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        # Decompress and parse
        data = gzip.decompress(response.content).decode('utf-8')
        _phish_data = json.loads(data)
        
        # Save to local file
        with open(local_file, 'w') as f:
            json.dump(_phish_data, f, indent=2)
        
        logging.info(f"Successfully downloaded {len(_phish_data)} phishing URLs")
        return True
        
    except Exception as e:
        logging.error(f"Error downloading database: {e}")
        return False

def normalize_url(url: str) -> str:
    """
    Normalize URL for comparison.
    
    Args:
        url: URL to normalize
        
    Returns:
        Normalized URL
    """
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Remove trailing slash and convert to lowercase
    return url.rstrip('/').lower()

def check_url_phishing(url: str) -> Dict:
    """
    Check if a URL is a phishing site according to PhishTank database.
    
    Args:
        url: URL to check
        
    Returns:
        Dictionary with check results:
        {
            'url': str,
            'is_phishing': bool,
            'confidence': str,  # 'high' if found in database, 'unknown' if not
            'details': dict or None  # Additional info if phishing detected
        }
    """
    global _phish_data
    
    # Ensure database is loaded
    if _phish_data is None:
        if not load_phishtank_database():
            return {
                'url': url,
                'is_phishing': False,
                'confidence': 'unknown',
                'error': 'Database not available'
            }
    
    normalized_url = normalize_url(url)
    
    # Search for exact match in database
    for entry in _phish_data:
        phish_url = normalize_url(entry.get('url', ''))
        if phish_url == normalized_url:
            return {
                'url': url,
                'is_phishing': True,
                'confidence': 'high',
                'details': {
                    'phish_id': entry.get('phish_id'),
                    'target': entry.get('target', 'Unknown'),
                    'submission_time': entry.get('submission_time'),
                    'verification_time': entry.get('verification_time'),
                    'detail_url': entry.get('phish_detail_url')
                }
            }
    
    return {
        'url': url,
        'is_phishing': False,
        'confidence': 'unknown',
        'message': 'URL not found in PhishTank database'
    }

def check_multiple_urls(urls: List[str]) -> Dict:
    """
    Check multiple URLs for phishing.
    
    Args:
        urls: List of URLs to check
        
    Returns:
        Dictionary with results for all URLs
    """
    results = {
        'total_urls': len(urls),
        'phishing_detected': 0,
        'results': []
    }
    
    for url in urls:
        result = check_url_phishing(url)
        results['results'].append(result)
        if result.get('is_phishing', False):
            results['phishing_detected'] += 1
    
    return results

# =============================================================================
# 2. EMAIL EXTRACTION AND VALIDATION
# =============================================================================

def extract_emails_from_text(text: str) -> List[str]:
    """
    Extract email addresses from text content.
    Handles multilingual text by ensuring email extraction stops at non-ASCII boundaries.
    
    Args:
        text: Text content to extract emails from
        
    Returns:
        List of extracted email addresses
    """
    # Standard email pattern but with better boundary detection for multilingual text
    email_pattern = r'(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}(?![A-Za-z0-9._%+-])'
    emails = re.findall(email_pattern, text, re.IGNORECASE)
    
    # Clean up emails that might have captured non-ASCII characters
    cleaned_emails = []
    for email in emails:
        # Remove any non-ASCII characters that might have been captured
        cleaned_email = re.sub(r'[^\x00-\x7F]', '', email)
        # Validate email format after cleaning
        if re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$', cleaned_email, re.IGNORECASE):
            cleaned_emails.append(cleaned_email)
    
    return list(set(cleaned_emails))  # Remove duplicates

def check_email_validity(email: str, api_key: Optional[str] = None) -> Dict:
    """
    Check email validity using external validation service.
    
    Args:
        email: Email address to validate
        api_key: API key for validation service (if None, uses env var)
        
    Returns:
        Dictionary with validation results
    """
    try:
        # Use provided API key or get from environment
        if api_key is None:
            api_key = config.get('VALIDATION_API_KEY')
            
        if not api_key:
            return {
                'email': email,
                'is_valid': None,
                'error': 'No API key configured for validation service',
                'confidence': 'unknown'
            }
        
        url = "https://validation-aws.silverlining.cloud/email-address"
        
        payload = json.dumps({
            "emailAddress": email
        })
        headers = {
            'x-api-key': api_key,
            'Content-Type': 'application/json'
        }
        
        response = requests.post(url, headers=headers, data=payload, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            # Check the validation result format to determine if email is valid
            validation_result = result.get('validationResult', {})
            status = validation_result.get('status', '').lower()
            is_valid = status == 'valid'
            
            return {
                'email': email,
                'is_valid': is_valid,
                'details': result,
                'confidence': 'high'
            }
        else:
            return {
                'email': email,
                'is_valid': None,
                'error': f"API returned status {response.status_code}",
                'confidence': 'unknown'
            }
            
    except Exception as e:
        return {
            'email': email,
            'is_valid': None,
            'error': str(e),
            'confidence': 'unknown'
        }

def check_multiple_emails(emails: List[str]) -> Dict:
    """
    Check multiple email addresses for validity.
    
    Args:
        emails: List of email addresses to check
        
    Returns:
        Dictionary with results for all emails
    """
    results = {
        'total_emails': len(emails),
        'valid_emails': 0,
        'invalid_emails': 0,
        'results': []
    }
    
    for email in emails:
        result = check_email_validity(email)
        results['results'].append(result)
        
        if result.get('is_valid') is True:
            results['valid_emails'] += 1
        elif result.get('is_valid') is False:
            results['invalid_emails'] += 1
    
    return results

# =============================================================================
# 3. PHONE NUMBER EXTRACTION AND VALIDATION
# =============================================================================

def extract_phone_numbers_from_text(text: str) -> List[str]:
    """
    Extract phone numbers from text content.
    Handles multilingual text by ensuring phone extraction stops at non-ASCII boundaries.
    
    Args:
        text: Text content to extract phone numbers from
        
    Returns:
        List of extracted phone numbers
    """
    # Multiple patterns to catch different phone number formats
    # Added word boundaries to prevent capturing numbers that are part of non-English text
    patterns = [
        r'(?<!\d)\+\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}(?!\d)',  # International format
        r'(?<!\d)\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)',  # (123) 456-7890
        r'(?<!\d)\d{3}[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)',      # 123-456-7890 or 123.456.7890
        r'(?<!\d)\d{10,15}(?!\d)',                          # Simple long number
    ]
    
    phone_numbers = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        phone_numbers.extend(matches)
    
    # Clean up phone numbers that might be mixed with non-ASCII text
    cleaned_phones = []
    for phone in phone_numbers:
        # Remove any non-ASCII characters and extra spaces
        cleaned_phone = re.sub(r'[^\x00-\x7F]', '', phone).strip()
        # Only keep if it still looks like a valid phone number
        if re.match(r'^[\+\d\(\)\-\.\s]{7,20}$', cleaned_phone) and len(re.sub(r'[^\d]', '', cleaned_phone)) >= 7:
            cleaned_phones.append(cleaned_phone)
    
    return list(set(cleaned_phones))  # Remove duplicates

def check_phone_number_validity(phone: str, api_key: Optional[str] = None) -> Dict:
    """
    Check phone number validity using external validation service.
    
    Args:
        phone: Phone number to validate
        api_key: API key for validation service (if None, uses env var)
        
    Returns:
        Dictionary with validation results
    """
    try:
        # Use provided API key or get from environment
        if api_key is None:
            api_key = config.get('VALIDATION_API_KEY')
            
        if not api_key:
            return {
                'phone': phone,
                'is_valid': None,
                'error': 'No API key configured for validation service',
                'confidence': 'unknown'
            }
        
        url = "https://validation-aws.silverlining.cloud/phone-number"
        
        payload = json.dumps({
            "phoneNumber": phone
        })
        headers = {
            'x-api-key': api_key,
            'Content-Type': 'application/json'
        }
        
        response = requests.post(url, headers=headers, data=payload, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            # Check the validation result format to determine if phone is valid
            validation_result = result.get('validationResult', {})
            is_valid = validation_result.get('is_valid', False)
            
            return {
                'phone': phone,
                'is_valid': is_valid,
                'details': result,
                'confidence': 'high'
            }
        else:
            return {
                'phone': phone,
                'is_valid': None,
                'error': f"API returned status {response.status_code}",
                'confidence': 'unknown'
            }
            
    except Exception as e:
        return {
            'phone': phone,
            'is_valid': None,
            'error': str(e),
            'confidence': 'unknown'
        }

def check_multiple_phone_numbers(phones: List[str]) -> Dict:
    """
    Check multiple phone numbers for validity.
    
    Args:
        phones: List of phone numbers to check
        
    Returns:
        Dictionary with results for all phone numbers
    """
    results = {
        'total_phones': len(phones),
        'valid_phones': 0,
        'invalid_phones': 0,
        'results': []
    }
    
    for phone in phones:
        result = check_phone_number_validity(phone)
        results['results'].append(result)
        
        if result.get('is_valid') is True:
            results['valid_phones'] += 1
        elif result.get('is_valid') is False:
            results['invalid_phones'] += 1
    
    return results

# =============================================================================
# 4. COMBINED CONTENT ANALYSIS
# =============================================================================

def extract_all_from_content(content: str) -> Dict:
    """
    Extract URLs, emails, and phone numbers from content.
    
    Args:
        content: Content to analyze
        
    Returns:
        Dictionary with all extracted elements
    """
    return {
        'urls': extract_urls_from_text(content),
        'emails': extract_emails_from_text(content),
        'phone_numbers': extract_phone_numbers_from_text(content)
    }

def check_all_content(content: str, sender_email: str = "", reply_to_email: str = "") -> Dict:
    """
    Extract and check all URLs, emails, and phone numbers from content and sender info.
    
    Args:
        content: Content to analyze
        sender_email: Sender email address to validate
        reply_to_email: Reply-to email address to validate
        
    Returns:
        Dictionary with extraction and validation results
    """
    logging.info("🔍 DEBUG: Starting check_all_content")
    logging.info(f"Sender email: {sender_email}, Reply-to email: {reply_to_email}")
    
    # Extract all elements from content
    extracted = extract_all_from_content(content)
    logging.info(f"Extracted elements from content: {extracted}")
    
    # Add sender and reply-to emails if they exist and aren't already in the list
    all_emails = extracted['emails'].copy()
    if sender_email and sender_email not in all_emails:
        all_emails.append(sender_email)
        logging.info(f"Added sender email for validation: {sender_email}")
    if reply_to_email and reply_to_email not in all_emails:
        all_emails.append(reply_to_email)
        logging.info(f"Added reply-to email for validation: {reply_to_email}")
    
    # Update extracted emails with sender/reply-to info
    extracted['emails'] = all_emails
    logging.info(f"Final emails to validate: {all_emails}")
    
    # Check all elements
    results = {
        'extraction': extracted,
        'validation': {}
    }
    
    if extracted['urls']:
        logging.info(f"Checking {len(extracted['urls'])} URLs")
        results['validation']['urls'] = check_multiple_urls(extracted['urls'])
        logging.info(f"URL validation results: {results['validation']['urls']}")
    
    if extracted['emails']:
        logging.info(f"Checking {len(extracted['emails'])} emails")
        results['validation']['emails'] = check_multiple_emails(extracted['emails'])
        logging.info(f"Email validation results: {results['validation']['emails']}")
    
    if extracted['phone_numbers']:
        logging.info(f"Checking {len(extracted['phone_numbers'])} phone numbers")
        results['validation']['phone_numbers'] = check_multiple_phone_numbers(extracted['phone_numbers'])
    
    logging.info(f"Final check_all_content results: {results}")
    return results

def format_checker_results_for_llm(checker_results: Dict) -> str:
    """
    Format checker results for inclusion in LLM analysis.
    
    Args:
        checker_results: Results from check_all_content()
        
    Returns:
        Formatted string for LLM input
    """
    if not checker_results:
        return ""
    
    formatted = []
    
    # URLs analysis
    url_validation = checker_results.get('validation', {}).get('urls', {})
    if url_validation:
        phishing_count = url_validation.get('phishing_detected', 0)
        total_urls = url_validation.get('total_urls', 0)
        
        if phishing_count > 0:
            formatted.append(f"⚠️ URL Analysis: {phishing_count}/{total_urls} URLs detected as phishing sites")
            for result in url_validation.get('results', []):
                if result.get('is_phishing'):
                    formatted.append(f"  - Phishing URL: {result['url']} (Target: {result.get('details', {}).get('target', 'Unknown')})")
        else:
            formatted.append(f"✓ URL Analysis: {total_urls} URLs checked, none identified as phishing")
    
    # Email validation
    email_validation = checker_results.get('validation', {}).get('emails', {})
    if email_validation:
        invalid_count = email_validation.get('invalid_emails', 0)
        total_emails = email_validation.get('total_emails', 0)
        
        if invalid_count > 0:
            formatted.append(f"⚠️ Email Analysis: {invalid_count}/{total_emails} email addresses are invalid")
        else:
            formatted.append(f"✓ Email Analysis: {total_emails} email addresses validated")
    
    # Phone validation
    phone_validation = checker_results.get('validation', {}).get('phone_numbers', {})
    if phone_validation:
        invalid_count = phone_validation.get('invalid_phones', 0)
        total_phones = phone_validation.get('total_phones', 0)
        
        if invalid_count > 0:
            formatted.append(f"⚠️ Phone Analysis: {invalid_count}/{total_phones} phone numbers are invalid")
        else:
            formatted.append(f"✓ Phone Analysis: {total_phones} phone numbers validated")
    
    return "\n".join(formatted) if formatted else ""