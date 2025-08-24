"""
Authentication API Endpoints for MAI Scam Detection System

This module provides endpoints for authentication, token management, and API key operations.

TABLE OF CONTENTS:
==================

EXPORTED ENDPOINTS:
------------------
1. POST /auth/token - Create JWT token
2. POST /auth/api-key - Create API key
3. GET /auth/verify - Verify authentication
4. GET /auth/keys - List API keys (admin)
5. DELETE /auth/keys/{key_id} - Revoke API key (admin)
6. PUT /auth/keys/{key_id}/permissions - Update permissions (admin)

USAGE EXAMPLES:
--------------
# Create JWT token
curl -X POST "http://localhost:8000/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"client_id": "web_extension_v1", "client_type": "web_extension"}'

# Create API key
curl -X POST "http://localhost:8000/auth/api-key" \
  -H "Content-Type: application/json" \
  -d '{"client_id": "chatbot_v1", "client_type": "chatbot"}'

# Verify authentication
curl -X GET "http://localhost:8000/auth/verify" \
  -H "Authorization: Bearer <jwt_token>"
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import List, Optional, Dict
from models.customResponse import resp_200, resp_201, resp_400, resp_401, resp_403
from utils.authUtils import (
    create_jwt_token, verify_jwt_token, create_api_key, verify_api_key,
    authenticate_request, list_api_keys, revoke_api_key, update_client_permissions
)
from utils.constant import CLIENT_TYPES
from middleware.auth_middleware import require_auth

router = APIRouter(prefix="/auth", tags=["Authentication"])


# =============================================================================
# REQUEST MODELS
# =============================================================================

class TokenRequest(BaseModel):
    client_id: str
    client_type: str
    permissions: Optional[List[str]] = None
    custom_claims: Optional[Dict] = None


class TokenResponse(BaseModel):
    token: str
    expires_in: int
    token_type: str = "Bearer"
    client_id: str
    client_type: str
    permissions: List[str]


class ApiKeyRequest(BaseModel):
    client_id: str
    client_type: str
    permissions: Optional[List[str]] = None
    description: Optional[str] = ""


class ApiKeyResponse(BaseModel):
    api_key: str
    client_id: str
    client_type: str
    permissions: List[str]
    description: str
    created_at: str
    warning: str = "Store this API key securely. It will not be shown again."


class VerifyResponse(BaseModel):
    authenticated: bool
    client_id: str
    client_type: str
    permissions: List[str]
    method: str


class ApiKeyInfo(BaseModel):
    key_id: str
    client_id: str
    client_type: str
    permissions: List[str]
    description: str
    created_at: str
    last_used: Optional[str]
    is_active: bool


class UpdatePermissionsRequest(BaseModel):
    permissions: List[str]


# =============================================================================
# 1. JWT TOKEN CREATION ENDPOINT
# =============================================================================

@router.post("/token")
async def create_token(request: TokenRequest):
    """
    Create a JWT token for client authentication.

    This endpoint generates a JWT token that can be used for stateless authentication.
    The token includes client information and permissions.

    Args:
        request: Token creation request with client details

    Returns:
        TokenResponse: JWT token and metadata

    Raises:
        HTTPException: If client type is invalid or creation fails
    """
    try:
        # Validate client type
        valid_client_types = ["web_extension",
                              "chatbot", "mobile_app", "api_client"]
        if request.client_type not in valid_client_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid client_type. Must be one of: {valid_client_types}"
            )

        # Create JWT token
        token = create_jwt_token(
            client_id=request.client_id,
            client_type=request.client_type,
            permissions=request.permissions,
            custom_claims=request.custom_claims
        )

        # Get default permissions if not specified
        if not request.permissions:
            request.permissions = CLIENT_TYPES.get(
                request.client_type, {}).get("permissions", [])

        return resp_201(
            data={
                "token": token,
                "expires_in": 24 * 3600,  # 24 hours in seconds
                "token_type": "Bearer",
                "client_id": request.client_id,
                "client_type": request.client_type,
                "permissions": request.permissions
            },
            message="JWT token created successfully"
        )

    except Exception as e:
        raise HTTPException(
            status_code=400, detail=f"Token creation failed: {str(e)}")


# =============================================================================
# 2. API KEY CREATION ENDPOINT
# =============================================================================

@router.post("/api-key",
             summary="Create API Key",
             description="""
    Create a new API key for accessing the MAI Scam Detection API.
    
    **Client Types:**
    - web_extension: Browser extension (100 req/hour)
    - chatbot: Chatbot integration (50 req/hour)
    - mobile_app: Mobile application (200 req/hour)
    - api_client: Third-party API (1000 req/hour)
    
    **Permissions:**
    - email_analysis: Analyze emails for scams
    - website_analysis: Analyze websites for scams
    - social_media_analysis: Analyze social media posts for scams
    
    **Security:**
    - API key is shown only once
    - Store securely - it cannot be retrieved later
    """,
             response_description="New API key with permissions and usage limits")
async def create_api_key_endpoint(request: ApiKeyRequest):
    """
    Create an API key for client authentication.

    This endpoint generates a secure API key that can be used for authentication.
    The API key is returned only once and should be stored securely by the client.

    Args:
        request: API key creation request with client details

    Returns:
        ApiKeyResponse: API key and metadata

    Raises:
        HTTPException: If client type is invalid or creation fails
    """
    try:
        # Validate client type
        valid_client_types = ["web_extension",
                              "chatbot", "mobile_app", "api_client"]
        if request.client_type not in valid_client_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid client_type. Must be one of: {valid_client_types}"
            )

        # Create API key
        result = create_api_key(
            client_id=request.client_id,
            client_type=request.client_type,
            permissions=request.permissions,
            description=request.description
        )

        return resp_201(
            data={
                "api_key": result["api_key"],
                "client_id": result["client_info"]["client_id"],
                "client_type": result["client_info"]["client_type"],
                "permissions": result["client_info"]["permissions"],
                "description": result["client_info"]["description"],
                "created_at": result["client_info"]["created_at"],
                "warning": "Store this API key securely. It will not be shown again."
            },
            message="API key created successfully"
        )

    except Exception as e:
        raise HTTPException(
            status_code=400, detail=f"API key creation failed: {str(e)}")


# =============================================================================
# 3. AUTHENTICATION VERIFICATION ENDPOINT
# =============================================================================

@router.get("/verify")
async def verify_authentication(request: Request):
    """
    Verify authentication credentials.

    This endpoint verifies the authentication credentials provided in the request
    and returns information about the authenticated client.

    Args:
        request: FastAPI request object

    Returns:
        VerifyResponse: Authentication verification result

    Raises:
        HTTPException: If authentication fails
    """
    try:
        auth_result = authenticate_request(request)

        return resp_200(
            data={
                "authenticated": True,
                "client_id": auth_result["client_id"],
                "client_type": auth_result["client_type"],
                "permissions": auth_result["permissions"],
                "method": auth_result["method"]
            },
            message="Authentication verified successfully"
        )

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=401, detail=f"Authentication verification failed: {str(e)}")


# =============================================================================
# 4. API KEY LISTING ENDPOINT (ADMIN)
# =============================================================================

@router.get("/keys")
async def list_api_keys_endpoint(request: Request):
    """
    List all API keys (admin only).

    This endpoint returns information about all API keys in the system.
    This is an admin-only endpoint for management purposes.

    Args:
        request: FastAPI request object

    Returns:
        List[ApiKeyInfo]: List of API key information

    Raises:
        HTTPException: If not authorized or operation fails
    """
    try:
        # Verify admin permissions (you can customize this check)
        auth_result = authenticate_request(request)
        if auth_result["client_type"] != "api_client":
            raise HTTPException(
                status_code=403, detail="Admin access required")

        keys_info = list_api_keys()

        return resp_200(
            data=keys_info,
            message="API keys retrieved successfully"
        )

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to list API keys: {str(e)}")


# =============================================================================
# 5. API KEY REVOCATION ENDPOINT (ADMIN)
# =============================================================================

@router.delete("/keys/{key_id}")
async def revoke_api_key_endpoint(key_id: str, request: Request):
    """
    Revoke an API key (admin only).

    This endpoint revokes an API key, making it inactive.
    This is an admin-only endpoint for security management.

    Args:
        key_id: API key identifier
        request: FastAPI request object

    Returns:
        dict: Revocation result

    Raises:
        HTTPException: If not authorized or operation fails
    """
    try:
        # Verify admin permissions
        auth_result = authenticate_request(request)
        if auth_result["client_type"] != "api_client":
            raise HTTPException(
                status_code=403, detail="Admin access required")

        # For this example, we'll use the key_id as the API key
        # In production, you'd have a proper key management system
        success = revoke_api_key(key_id)

        if success:
            return resp_200(
                data={"revoked": True, "key_id": key_id},
                message="API key revoked successfully"
            )
        else:
            raise HTTPException(status_code=404, detail="API key not found")

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to revoke API key: {str(e)}")


# =============================================================================
# 6. PERMISSIONS UPDATE ENDPOINT (ADMIN)
# =============================================================================

@router.put("/keys/{key_id}/permissions")
async def update_permissions_endpoint(
    key_id: str,
    request: UpdatePermissionsRequest,
    auth_request: Request
):
    """
    Update permissions for an API key (admin only).

    This endpoint updates the permissions associated with an API key.
    This is an admin-only endpoint for permission management.

    Args:
        key_id: API key identifier
        request: Permission update request
        auth_request: FastAPI request object for authentication

    Returns:
        dict: Update result

    Raises:
        HTTPException: If not authorized or operation fails
    """
    try:
        # Verify admin permissions
        auth_result = authenticate_request(auth_request)
        if auth_result["client_type"] != "api_client":
            raise HTTPException(
                status_code=403, detail="Admin access required")

        # Update permissions
        success = update_client_permissions(key_id, request.permissions)

        if success:
            return resp_200(
                data={
                    "updated": True,
                    "key_id": key_id,
                    "new_permissions": request.permissions
                },
                message="Permissions updated successfully"
            )
        else:
            raise HTTPException(status_code=404, detail="API key not found")

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to update permissions: {str(e)}")


# =============================================================================
# 7. HEALTH CHECK ENDPOINT
# =============================================================================

@router.get("/health")
async def health_check():
    """
    Health check endpoint.

    This endpoint provides a simple health check for the authentication service.

    Returns:
        dict: Health status
    """
    return resp_200(
        data={
            "status": "healthy",
            "service": "authentication",
            "timestamp": "2025-01-16T12:00:00Z"
        },
        message="Authentication service is healthy"
    )
