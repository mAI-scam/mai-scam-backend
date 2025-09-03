#!/usr/bin/env python3
"""
Simple PhishTank URL Checker
A lightweight script to check URLs against PhishTank database - easily convertible to API endpoint.
"""

import requests
import json
import gzip
import os
from typing import Dict, Optional

# Global variable to store phish data (for endpoint efficiency)
_phish_data = None

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
            print(f"Loaded {len(_phish_data)} phishing URLs from local database")
            return True
        except Exception as e:
            print(f"Error loading local database: {e}")
    
    # Download database
    try:
        base_url = "http://data.phishtank.com/data"
        headers = {'User-Agent': 'phishtank/simple-checker'}
        
        # Construct URL with app key if provided
        if app_key:
            url = f"{base_url}/{app_key}/online-valid.json.gz"
        else:
            url = f"{base_url}/online-valid.json.gz"
        
        print(f"Downloading PhishTank database...")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        # Decompress and parse
        data = gzip.decompress(response.content).decode('utf-8')
        _phish_data = json.loads(data)
        
        # Save to local file
        with open(local_file, 'w') as f:
            json.dump(_phish_data, f, indent=2)
        
        print(f"Successfully downloaded {len(_phish_data)} phishing URLs")
        return True
        
    except Exception as e:
        print(f"Error downloading database: {e}")
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
    This function is designed to be easily converted to an API endpoint.
    
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

def print_result(result: Dict):
    """
    Print formatted result for CLI usage.
    
    Args:
        result: Result dictionary from check_url_phishing()
    """
    print(f"\n{'='*50}")
    print(f"URL: {result['url']}")
    
    if result.get('error'):
        print(f"❌ ERROR: {result['error']}")
    elif result['is_phishing']:
        print("🚨 PHISHING DETECTED!")
        details = result.get('details', {})
        print(f"Target: {details.get('target', 'Unknown')}")
        print(f"PhishTank ID: {details.get('phish_id')}")
        print(f"Confidence: {result['confidence']}")
    else:
        print("✅ Not detected as phishing")
        print(f"Confidence: {result['confidence']}")
        if result.get('message'):
            print(f"Note: {result['message']}")

# Simple CLI interface
def main():
    import sys
    
    if len(sys.argv) < 2:
        print("PhishTank URL Checker")
        print("Usage: python phishtank_checker.py <url> [--update]")
        sys.exit(1)
    
    force_update = '--update' in sys.argv
    urls = [arg for arg in sys.argv[1:] if not arg.startswith('--')]
    
    # Load database
    if not load_phishtank_database(force_download=force_update):
        print("Failed to load PhishTank database")
        sys.exit(1)
    
    # Check URLs
    for url in urls:
        result = check_url_phishing(url)
        print_result(result)

if __name__ == "__main__":
    main()
