"""
Main API Routes for MAI Scam Detection System

This module contains core API endpoints including root, health check, and debug endpoints
for the MAI Scam Detection API.

ENDPOINTS:
------
1. GET / - Get API information and status
2. GET /health - Check API health status
3. GET /debug/auth - Debug authentication (development only)
"""

from fastapi import APIRouter, Request, HTTPException, UploadFile, File
from models.customResponse import resp_200, health_success_response
from models.clients import get_sea_lion_client, get_mistral_client
from utils.authUtils import authenticate_request
from setting import Setting
import json
import base64
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime

config = Setting()

router = APIRouter()

# =============================================================================
# 1. ROOT ENDPOINT
# =============================================================================


class RootResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the request was successful")
    message: str = Field(..., description="Response message")
    data: Dict[str, Any] = Field(...,
                                 description="API information and endpoints")
    timestamp: str = Field(..., description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")


@router.get("/", response_model=RootResponse)
async def root():
    """
    Root endpoint providing API information.

    Returns:
        dict: API information and available endpoints
    """
    return resp_200(
        data={
            "message": "MAI Scam Detection API",
            "version": "1.0.0",
            "description": "API for detecting scams in emails, social media, and websites",
            "endpoints": {
                "authentication": "/api/v1/auth",
                "email_analysis": "/api/v1/email",
                "social_media_analysis": "/api/v1/socialmedia",
                "website_analysis": "/api/v1/website",
                "v2_email_analysis": "/email/v2/analyze"
            },
            "documentation": {
                "swagger": "/docs",
                "redoc": "/redoc"
            },
            "authentication": {
                "methods": ["JWT Token", "API Key"],
                "headers": {
                    "jwt": "Authorization: Bearer <token>",
                    "api_key": "X-API-Key: <api_key>"
                }
            }
        },
        message="MAI Scam Detection API is running"
    )

# =============================================================================
# 2. HEALTH CHECK ENDPOINT
# =============================================================================


class HealthResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the request was successful")
    message: str = Field(..., description="Response message")
    data: Dict[str, Any] = Field(..., description="Health status information")
    timestamp: str = Field(..., description="Response timestamp")


@router.get("/health", response_model=HealthResponse)
async def health():
    """
    Health check endpoint.

    Returns:
        dict: Health status information
    """
    return health_success_response(
        data={
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "services": {
                "api": "running",
                "database": "connected",
                "ai_models": "available"
            }
        }
    )

# =============================================================================
# 3. DEBUG AUTHENTICATION ENDPOINT
# =============================================================================


class DebugAuthResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the request was successful")
    message: str = Field(..., description="Response message")
    data: Dict[str, Any] = Field(...,
                                 description="Debug authentication information")
    timestamp: str = Field(..., description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")


@router.get("/debug/auth", response_model=DebugAuthResponse)
async def debug_auth(request: Request):
    """
    Debug authentication endpoint (development only).

    This endpoint helps debug authentication issues by showing
    the current authentication state and available credentials.

    Returns:
        dict: Debug authentication information
    """
    try:
        # Try to authenticate the request
        auth_result = authenticate_request(request)

        return resp_200(
            data={
                "authentication": "success",
                "client_id": auth_result.get("client_id"),
                "client_type": auth_result.get("client_type"),
                "permissions": auth_result.get("permissions", []),
                "auth_method": auth_result.get("auth_method"),
                "request_headers": dict(request.headers),
                "timestamp": datetime.utcnow().isoformat()
            },
            message="Authentication successful"
        )

    except HTTPException as e:
        return resp_200(
            data={
                "authentication": "failed",
                "error": e.detail,
                "status_code": e.status_code,
                "request_headers": dict(request.headers),
                "timestamp": datetime.utcnow().isoformat()
            },
            message="Authentication failed"
        )
    except Exception as e:
        return resp_200(
            data={
                "authentication": "error",
                "error": str(e),
                "error_type": type(e).__name__,
                "request_headers": dict(request.headers),
                "timestamp": datetime.utcnow().isoformat()
            },
            message="Authentication error"
        )

