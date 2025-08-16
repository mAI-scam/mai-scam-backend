#!/usr/bin/env python3
"""
Test script for the /analyze-email endpoint
"""

import requests
import json


def test_email_analysis():
    """Test the /analyze-email endpoint with different languages"""

    # Test data
    test_email = {
        "subject": "Urgent: Your account has been suspended",
        "content": "Dear user, your account has been suspended due to suspicious activity. Please click the link below to verify your identity immediately.",
        "from_email": "security@fakebank.com",
        "reply_to_email": "support@fakebank.com",
        "target_language": "zh"  # Test with Chinese
    }

    try:
        print("🧪 Testing /analyze-email endpoint...")
        print(f"📧 Test email: {test_email['subject']}")
        print(f"🌐 Target language: {test_email['target_language']}")

        response = requests.post(
            "http://localhost:8000/analyze-email",
            json=test_email,
            headers={"Content-Type": "application/json"},
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            print("✅ Success!")
            print(f"📊 Risk Level: {result['data']['risk_level']}")
            print(f"🔍 Analysis: {result['data']['analysis']}")
            print(
                f"💡 Recommended Action: {result['data']['recommended_action']}")
        else:
            print(f"❌ Error: {response.status_code}")
            print(f"Response: {response.text}")

    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to backend. Make sure the server is running on localhost:8000")
    except Exception as e:
        print(f"❌ Error: {e}")


def test_backend_health():
    """Test if the backend is running"""
    try:
        response = requests.get("http://localhost:8000/", timeout=5)
        if response.status_code == 200:
            print("✅ Backend is running")
            return True
        else:
            print(f"❌ Backend responded with status: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Backend is not running")
        return False
    except Exception as e:
        print(f"❌ Error checking backend health: {e}")
        return False


if __name__ == "__main__":
    print("🚀 Testing Email Analysis Backend")
    print("=" * 40)

    # First check if backend is running
    if test_backend_health():
        print()
        test_email_analysis()
    else:
        print("\n💡 To start the backend, run:")
        print("   cd mai-scam-backend")
        print("   uv run python app.py")

