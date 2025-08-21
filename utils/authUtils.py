"""
Authentication Utilities for MAI Scam Detection System

This module provides JWT-based authentication and API key validation for securing
API endpoints, ensuring only authorized clients (web extensions, chatbots, etc.) can access them.

TABLE OF CONTENTS:
==================

EXPORTED FUNCTIONS:
------------------
1. create_jwt_token
2. verify_jwt_token
3. create_api_key
4. verify_api_key
5. authenticate_request
6. get_client_info

USAGE EXAMPLES:
--------------
# Create JWT token for web extension
token = create_jwt_token(
    client_id="web_extension_v1",
    client_type="web_extension",
    permissions=["email_analysis", "website_analysis", "social_media_analysis"]
)

# Verify JWT token
payload = verify_jwt_token(token)

# Create API key for chatbot
api_key = create_api_key(
    client_id="chatbot_v1",
    client_type="chatbot",
    permissions=["email_analysis"]
)

# Verify API key
client_info = verify_api_key(api_key)

# Authenticate request (combines both methods)
auth_result = authenticate_request(request_headers)
"""

import jwt
import secrets
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Union
from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import json
import os
from utils.constant import (
    JWT_SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRY_HOURS,
    API_KEY_LENGTH, API_KEY_PREFIX, CLIENT_TYPES
)

# In-memory storage for API keys (in production, use database)
API_KEYS_DB = {}

# Rate limiting storage (in production, use Redis)
RATE_LIMIT_DB = {}

# Security scheme
security = HTTPBearer()


# =============================================================================
# HELPER FUNCTIONS FOR AUTHENTICATION
# =============================================================================

def _generate_api_key() -> str:
    """
    Generate a secure API key.

    Returns:
        str: Generated API key with prefix
    """
    random_bytes = secrets.token_bytes(API_KEY_LENGTH)
    api_key = API_KEY_PREFIX + random_bytes.hex()
    return api_key


def _hash_api_key(api_key: str) -> str:
    """
    Hash API key for secure storage.

    Args:
        api_key: Raw API key

    Returns:
        str: Hashed API key
    """
    return hashlib.sha256(api_key.encode()).hexdigest()


def _check_rate_limit(client_id: str, client_type: str) -> bool:
    """
    Check if client is within rate limits.

    Args:
        client_id: Client identifier
        client_type: Type of client

    Returns:
        bool: True if within rate limit, False otherwise
    """
    current_time = int(time.time())
    hour_ago = current_time - 3600

    # Get rate limit for client type
    rate_limit = CLIENT_TYPES.get(client_type, {}).get("rate_limit", 10)

    # Get current request count
    key = f"{client_id}:{current_time // 3600}"  # Hour-based key
    current_count = RATE_LIMIT_DB.get(key, 0)

    if current_count >= rate_limit:
        return False

    # Increment counter
    RATE_LIMIT_DB[key] = current_count + 1
    return True


# =============================================================================
# 1. JWT TOKEN CREATION FUNCTION
# =============================================================================

def create_jwt_token(client_id: str, client_type: str, permissions: List[str] = None,
                     custom_claims: Dict = None) -> str:
    """
    Create a JWT token for client authentication.

    This function generates a JWT token with client information and permissions,
    which can be used for stateless authentication.

    Args:
        client_id: Unique client identifier
        client_type: Type of client (web_extension, chatbot, etc.)
        permissions: List of permissions for this client
        custom_claims: Additional custom claims to include

    Returns:
        str: JWT token

    Example:
        token = create_jwt_token(
            client_id="web_extension_v1",
            client_type="web_extension",
            permissions=["email_analysis", "website_analysis"]
        )
    """
    if permissions is None:
        permissions = CLIENT_TYPES.get(client_type, {}).get("permissions", [])

    payload = {
        "client_id": client_id,
        "client_type": client_type,
        "permissions": permissions,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
        "iss": "mai-scam-detection",
        "aud": "mai-clients"
    }

    if custom_claims:
        payload.update(custom_claims)

    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


# =============================================================================
# 2. JWT TOKEN VERIFICATION FUNCTION
# =============================================================================

def verify_jwt_token(token: str) -> Dict:
    """
    Verify a JWT token and return the payload.

    This function validates the JWT token and returns the decoded payload
    containing client information and permissions.

    Args:
        token: JWT token to verify

    Returns:
        dict: Decoded token payload

    Raises:
        HTTPException: If token is invalid or expired

    Example:
        payload = verify_jwt_token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    """
    import logging
    logger = logging.getLogger(__name__)

    try:
        logger.debug("Verifying JWT token")
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        logger.debug(
            f"JWT token verified successfully for client: {payload.get('client_id', 'unknown')}")
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        import traceback
        logger.error(f"Error verifying JWT token: {str(e)}")
        logger.error(f"Error type: {type(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=401, detail="Token verification failed")


# =============================================================================
# 3. API KEY CREATION FUNCTION
# =============================================================================

def create_api_key(client_id: str, client_type: str, permissions: List[str] = None,
                   description: str = "") -> Dict[str, str]:
    """
    Create an API key for client authentication.

    This function generates a secure API key and stores it with client information.
    The raw API key is returned only once and should be stored securely by the client.

    Args:
        client_id: Unique client identifier
        client_type: Type of client (web_extension, chatbot, etc.)
        permissions: List of permissions for this client
        description: Optional description for the API key

    Returns:
        dict: Contains 'api_key' and 'client_info'

    Example:
        result = create_api_key(
            client_id="chatbot_v1",
            client_type="chatbot",
            permissions=["email_analysis"],
            description="Chatbot integration API key"
        )
    """
    if permissions is None:
        permissions = CLIENT_TYPES.get(client_type, {}).get("permissions", [])

    # Generate API key
    api_key = _generate_api_key()
    hashed_key = _hash_api_key(api_key)

    # Store client information
    client_info = {
        "client_id": client_id,
        "client_type": client_type,
        "permissions": permissions,
        "description": description,
        "created_at": datetime.utcnow().isoformat(),
        "last_used": None,
        "is_active": True
    }

    API_KEYS_DB[hashed_key] = client_info

    return {
        "api_key": api_key,
        "client_info": client_info
    }


# =============================================================================
# 4. API KEY VERIFICATION FUNCTION
# =============================================================================

def verify_api_key(api_key: str) -> Dict:
    """
    Verify an API key and return client information.

    This function validates the API key and returns the associated client information.

    Args:
        api_key: API key to verify

    Returns:
        dict: Client information if valid

    Raises:
        HTTPException: If API key is invalid or inactive

    Example:
        client_info = verify_api_key("mai_abc123...")
    """
    import logging
    logger = logging.getLogger(__name__)

    try:
        logger.debug("Verifying API key")

        if not api_key.startswith(API_KEY_PREFIX):
            logger.warning(f"Invalid API key format: {api_key[:10]}...")
            raise HTTPException(
                status_code=401, detail="Invalid API key format")

        hashed_key = _hash_api_key(api_key)
        client_info = API_KEYS_DB.get(hashed_key)

        if not client_info:
            logger.warning("API key not found in database")
            raise HTTPException(status_code=401, detail="Invalid API key")

        if not client_info.get("is_active", False):
            logger.warning(
                f"Inactive API key for client: {client_info.get('client_id', 'unknown')}")
            raise HTTPException(status_code=401, detail="API key is inactive")

        # Update last used timestamp
        client_info["last_used"] = datetime.utcnow().isoformat()
        API_KEYS_DB[hashed_key] = client_info

        # Check rate limiting
        if not _check_rate_limit(client_info["client_id"], client_info["client_type"]):
            logger.warning(
                f"Rate limit exceeded for client: {client_info.get('client_id', 'unknown')}")
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        logger.debug(
            f"API key verified successfully for client: {client_info.get('client_id', 'unknown')}")
        return client_info

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        logger.error(f"Error verifying API key: {str(e)}")
        logger.error(f"Error type: {type(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=401, detail="API key verification failed")


# =============================================================================
# 5. REQUEST AUTHENTICATION FUNCTION
# =============================================================================

def authenticate_request(request: Request) -> Dict:
    """
    Authenticate a request using either JWT token or API key.

    This function checks for authentication credentials in the request headers
    and validates them using the appropriate method.

    Args:
        request: FastAPI request object

    Returns:
        dict: Authentication result with client information

    Raises:
        HTTPException: If authentication fails

    Example:
        auth_result = authenticate_request(request)
    """
    import logging
    logger = logging.getLogger(__name__)

    try:
        logger.debug(f"Authenticating request to {request.url.path}")

        # Check for JWT token in Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            logger.debug("Found JWT token in Authorization header")
            token = auth_header.split(" ")[1]
            payload = verify_jwt_token(token)
            logger.debug(
                f"JWT token verified for client: {payload.get('client_id', 'unknown')}")
            return {
                "authenticated": True,
                "method": "jwt",
                "client_id": payload["client_id"],
                "client_type": payload["client_type"],
                "permissions": payload["permissions"],
                "payload": payload
            }

        # Check for API key in X-API-Key header
        api_key = request.headers.get("X-API-Key")
        if api_key:
            logger.debug("Found API key in X-API-Key header")
            client_info = verify_api_key(api_key)
            logger.debug(
                f"API key verified for client: {client_info.get('client_id', 'unknown')}")
            return {
                "authenticated": True,
                "method": "api_key",
                "client_id": client_info["client_id"],
                "client_type": client_info["client_type"],
                "permissions": client_info["permissions"],
                "client_info": client_info
            }

        # No authentication found
        logger.debug("No authentication credentials found")
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Provide either JWT token in Authorization header or API key in X-API-Key header"
        )

    except Exception as e:
        import traceback
        logger.error(f"Error in authenticate_request: {str(e)}")
        logger.error(f"Error type: {type(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise


# =============================================================================
# 6. CLIENT INFO RETRIEVAL FUNCTION
# =============================================================================

def get_client_info(client_id: str) -> Optional[Dict]:
    """
    Get information about a specific client.

    Args:
        client_id: Client identifier

    Returns:
        dict: Client information if found, None otherwise

    Example:
        client_info = get_client_info("web_extension_v1")
    """
    # Search in API keys database
    for hashed_key, info in API_KEYS_DB.items():
        if info["client_id"] == client_id:
            return info

    return None


# =============================================================================
# FASTAPI DEPENDENCY FUNCTIONS
# =============================================================================

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    """
    FastAPI dependency for JWT authentication.

    Args:
        credentials: HTTP authorization credentials

    Returns:
        dict: User/client information

    Raises:
        HTTPException: If authentication fails
    """
    return verify_jwt_token(credentials.credentials)


async def require_permission(required_permission: str):
    """
    FastAPI dependency factory for permission checking.

    Args:
        required_permission: Permission required to access the endpoint

    Returns:
        function: Dependency function that checks permissions
    """
    async def check_permission(request: Request):
        auth_result = authenticate_request(request)
        permissions = auth_result.get("permissions", [])

        if required_permission not in permissions:
            raise HTTPException(
                status_code=403,
                detail=f"Permission '{required_permission}' required"
            )

        return auth_result

    return check_permission


# =============================================================================
# UTILITY FUNCTIONS FOR MANAGEMENT
# =============================================================================

def list_api_keys() -> List[Dict]:
    """
    List all API keys (for management purposes).

    Returns:
        list: List of API key information (without actual keys)
    """
    keys_info = []
    for hashed_key, client_info in API_KEYS_DB.items():
        keys_info.append({
            "hashed_key": hashed_key[:8] + "...",  # Show only first 8 chars
            "client_id": client_info["client_id"],
            "client_type": client_info["client_type"],
            "permissions": client_info["permissions"],
            "description": client_info["description"],
            "created_at": client_info["created_at"],
            "last_used": client_info["last_used"],
            "is_active": client_info["is_active"]
        })
    return keys_info


def revoke_api_key(api_key: str) -> bool:
    """
    Revoke an API key.

    Args:
        api_key: API key to revoke

    Returns:
        bool: True if revoked successfully, False if not found
    """
    hashed_key = _hash_api_key(api_key)
    if hashed_key in API_KEYS_DB:
        API_KEYS_DB[hashed_key]["is_active"] = False
        return True
    return False


def update_client_permissions(client_id: str, new_permissions: List[str]) -> bool:
    """
    Update permissions for a client.

    Args:
        client_id: Client identifier
        new_permissions: New list of permissions

    Returns:
        bool: True if updated successfully, False if not found
    """
    for hashed_key, client_info in API_KEYS_DB.items():
        if client_info["client_id"] == client_id:
            client_info["permissions"] = new_permissions
            API_KEYS_DB[hashed_key] = client_info
            return True
    return False
