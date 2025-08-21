#!/usr/bin/env python3
"""
Test script for the email analysis endpoint.
Run this to verify the backend is working correctly.
"""

import requests
import json


def test_email_analysis():
    """Test the /analyze-email endpoint"""

    # Test data
    test_email = {
        "subject": "URGENT: Your account has been suspended",
        "content": "Dear user, your account has been suspended due to suspicious activity. Click here to verify your identity: http://fake-bank-verify.com",
        "from_email": "security@fakebank.com",
        "reply_to_email": "support@fakebank.com"
    }

    try:
        # Send request to backend
        response = requests.post(
            "http://localhost:8000/analyze-email",
            json=test_email,
            headers={"Content-Type": "application/json"}
        )

        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")

        if response.status_code == 200:
            result = response.json()
            print("✅ Success! Backend response:")
            print(json.dumps(result, indent=2))

            # Validate response structure
            if "data" in result and "risk_level" in result["data"]:
                print(f"🎯 Risk Level: {result['data']['risk_level']}")
                print(f"📊 Analysis: {result['data']['analysis']}")
                print(f"💡 Action: {result['data']['recommended_action']}")
            else:
                print("❌ Invalid response structure")

        else:
            print(f"❌ Error: {response.status_code}")
            print(f"Response: {response.text}")

    except requests.exceptions.ConnectionError:
        print(
            "❌ Connection Error: Make sure the backend is running on http://localhost:8000")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def test_backend_health():
    """Test if the backend is running"""

    try:
        response = requests.get("http://localhost:8000/")
        if response.status_code == 200:
            print("✅ Backend is running")
            return True
        else:
            print(f"❌ Backend health check failed: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Backend is not running on http://localhost:8000")
        return False


if __name__ == "__main__":
    print("🧪 Testing mAIscam Backend")
    print("=" * 50)

    # First check if backend is running
    if test_backend_health():
        print("\n📧 Testing Email Analysis Endpoint")
        print("-" * 40)
        test_email_analysis()
    else:
        print("\n💡 To start the backend:")
        print("cd mai-scam-backend")
        print("python app.py")

