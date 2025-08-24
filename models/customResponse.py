"""
Custom Response Models for MAI Scam Detection System

This module provides standardized response models and helper functions for
consistent API responses across all endpoints.

TABLE OF CONTENTS:
==================

EXPORTED FUNCTIONS:
------------------
1. resp_200 - Success response
2. resp_201 - Created response
3. resp_400 - Bad request response
4. resp_401 - Unauthorized response
5. resp_403 - Forbidden response
6. resp_404 - Not found response
5. resp_429 - Rate limit exceeded response
6. resp_500 - Internal server error response

RESPONSE MODELS:
---------------
1. BaseResponse - Base response structure
2. AnalysisResponse - Analysis results response
3. TranslationResponse - Translation results response
4. ErrorResponse - Error response structure
5. HealthResponse - Health check response
6. AuthResponse - Authentication response

USAGE EXAMPLES:
--------------
# Success response
return resp_200(data=result, message="Analysis completed successfully")

# Error response
return resp_400(message="Invalid input data", details={"field": "error"})

# Analysis response
return AnalysisResponse(
    success=True,
    data=analysis_result,
    message="Email analyzed successfully"
)
"""

from typing import Dict, Any, Optional, List, Union
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


# =============================================================================
# RESPONSE STATUS ENUM
# =============================================================================

class ResponseStatus(str, Enum):
    """Response status enumeration."""
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


# =============================================================================
# BASE RESPONSE MODELS
# =============================================================================

class BaseResponse(BaseModel):
    """
    Base response model for all API responses.

    This model provides a consistent structure for all API responses
    with standard fields for success status, data, message, and metadata.
    """
    success: bool = Field(...,
                          description="Whether the request was successful")
    message: str = Field(..., description="Human-readable message")
    data: Optional[Dict[str, Any]] = Field(None, description="Response data")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow(
    ).isoformat(), description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ErrorResponse(BaseModel):
    """
    Error response model for detailed error information.

    This model provides structured error information including
    error code, message, details, and suggestions for resolution.
    """
    success: bool = Field(
        False, description="Always false for error responses")
    error_code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[Dict[str, Any]] = Field(
        None, description="Additional error details")
    suggestions: Optional[List[str]] = Field(
        None, description="Suggestions for resolving the error")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow(
    ).isoformat(), description="Error timestamp")
    status_code: int = Field(..., description="HTTP status code")


# =============================================================================
# ANALYSIS RESPONSE MODELS
# =============================================================================

class AnalysisResult(BaseModel):
    """
    Analysis result model for scam detection results.

    This model contains the core analysis results including
    risk assessment, confidence scores, and detected signals.
    """
    risk_level: str = Field(..., description="Risk level: high, medium, low")
    confidence_score: float = Field(...,
                                    description="Confidence score (0.0 to 1.0)")
    detected_signals: Dict[str,
                           Any] = Field(..., description="Detected scam signals")
    analysis_summary: str = Field(...,
                                  description="Human-readable analysis summary")
    recommendations: List[str] = Field(..., description="Recommended actions")
    language_detected: Optional[str] = Field(
        None, description="Detected language code")
    processing_time: Optional[float] = Field(
        None, description="Processing time in seconds")


class AnalysisResponse(BaseModel):
    """
    Complete analysis response model.

    This model wraps analysis results with metadata and response information.
    """
    success: bool = Field(
        True, description="Whether the analysis was successful")
    message: str = Field(..., description="Analysis result message")
    data: AnalysisResult = Field(..., description="Analysis results")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow(
    ).isoformat(), description="Response timestamp")
    request_id: Optional[str] = Field(
        None, description="Unique request identifier")
    reused: bool = Field(
        False, description="Whether result was reused from cache")


# =============================================================================
# TRANSLATION RESPONSE MODELS
# =============================================================================

class TranslationResult(BaseModel):
    """
    Translation result model for analysis translations.

    This model contains translated analysis results and metadata.
    """
    original_language: str = Field(..., description="Original language code")
    target_language: str = Field(..., description="Target language code")
    translated_summary: str = Field(...,
                                    description="Translated analysis summary")
    translated_recommendations: List[str] = Field(
        ..., description="Translated recommendations")
    translation_confidence: float = Field(...,
                                          description="Translation confidence score")
    processing_time: Optional[float] = Field(
        None, description="Translation processing time")


class TranslationResponse(BaseModel):
    """
    Complete translation response model.

    This model wraps translation results with metadata and response information.
    """
    success: bool = Field(
        True, description="Whether the translation was successful")
    message: str = Field(..., description="Translation result message")
    data: TranslationResult = Field(..., description="Translation results")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow(
    ).isoformat(), description="Response timestamp")
    request_id: Optional[str] = Field(
        None, description="Unique request identifier")


# =============================================================================
# AUTHENTICATION RESPONSE MODELS
# =============================================================================

class AuthResult(BaseModel):
    """
    Authentication result model.

    This model contains authentication information and client details.
    """
    authenticated: bool = Field(...,
                                description="Whether authentication was successful")
    client_id: str = Field(..., description="Client identifier")
    client_type: str = Field(..., description="Type of client")
    permissions: List[str] = Field(..., description="Client permissions")
    method: str = Field(..., description="Authentication method used")
    expires_at: Optional[str] = Field(
        None, description="Token expiration time")


class AuthResponse(BaseModel):
    """
    Authentication response model.

    This model wraps authentication results with metadata.
    """
    success: bool = Field(
        True, description="Whether the authentication was successful")
    message: str = Field(..., description="Authentication result message")
    data: AuthResult = Field(..., description="Authentication results")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow(
    ).isoformat(), description="Response timestamp")


# =============================================================================
# HEALTH AND STATUS RESPONSE MODELS
# =============================================================================

class HealthStatus(BaseModel):
    """
    Health status model for system health checks.

    This model contains system health information and component status.
    """
    status: str = Field(..., description="Overall system status")
    service: str = Field(..., description="Service name")
    version: str = Field(..., description="Service version")
    uptime: Optional[float] = Field(
        None, description="Service uptime in seconds")
    components: Dict[str, str] = Field(
        default_factory=dict, description="Component status")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow(
    ).isoformat(), description="Health check timestamp")


class HealthResponse(BaseModel):
    """
    Health check response model.

    This model wraps health status information.
    """
    success: bool = Field(
        True, description="Whether the health check was successful")
    message: str = Field(..., description="Health check message")
    data: HealthStatus = Field(..., description="Health status information")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow(
    ).isoformat(), description="Response timestamp")


# =============================================================================
# RATE LIMIT RESPONSE MODELS
# =============================================================================

class RateLimitInfo(BaseModel):
    """
    Rate limit information model.

    This model contains rate limiting details and usage information.
    """
    limit: int = Field(..., description="Rate limit (requests per hour)")
    remaining: int = Field(..., description="Remaining requests")
    reset_time: str = Field(..., description="Rate limit reset time")
    client_id: str = Field(..., description="Client identifier")
    client_type: str = Field(..., description="Client type")


class RateLimitResponse(BaseModel):
    """
    Rate limit response model.

    This model wraps rate limit information for exceeded limits.
    """
    success: bool = Field(
        False, description="Always false for rate limit exceeded")
    message: str = Field(..., description="Rate limit exceeded message")
    data: RateLimitInfo = Field(..., description="Rate limit information")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow(
    ).isoformat(), description="Response timestamp")


# =============================================================================
# HELPER FUNCTIONS FOR COMMON RESPONSES
# =============================================================================

def resp_200(data: Optional[Dict[str, Any]] = None, message: str = "Success") -> Dict[str, Any]:
    """
    Create a standard 200 OK response.

    Args:
        data: Response data
        message: Success message

    Returns:
        dict: Standardized success response
    """
    return {
        "success": True,
        "message": message,
        "data": data,
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": 200
    }


def resp_201(data: Optional[Dict[str, Any]] = None, message: str = "Created successfully") -> Dict[str, Any]:
    """
    Create a standard 201 Created response.

    Args:
        data: Response data
        message: Success message

    Returns:
        dict: Standardized created response
    """
    return {
        "success": True,
        "message": message,
        "data": data,
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": 201
    }


def resp_400(message: str = "Bad request", details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Create a standard 400 Bad Request response.

    Args:
        message: Error message
        details: Additional error details

    Returns:
        dict: Standardized bad request response
    """
    return {
        "success": False,
        "error_code": "BAD_REQUEST",
        "message": message,
        "details": details,
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": 400
    }


def resp_401(message: str = "Unauthorized", details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Create a standard 401 Unauthorized response.

    Args:
        message: Error message
        details: Additional error details

    Returns:
        dict: Standardized unauthorized response
    """
    return {
        "success": False,
        "error_code": "UNAUTHORIZED",
        "message": message,
        "details": details,
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": 401
    }


def resp_403(message: str = "Forbidden", details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Create a standard 403 Forbidden response.

    Args:
        message: Error message
        details: Additional error details

    Returns:
        dict: Standardized forbidden response
    """
    return {
        "success": False,
        "error_code": "FORBIDDEN",
        "message": message,
        "details": details,
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": 403
    }


def resp_404(message: str = "Not found", details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Create a standard 404 Not Found response.

    Args:
        message: Error message
        details: Additional error details

    Returns:
        dict: Standardized not found response
    """
    return {
        "success": False,
        "error_code": "NOT_FOUND",
        "message": message,
        "details": details,
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": 404
    }


def resp_429(limit: int, remaining: int, reset_time: str, client_id: str, client_type: str) -> Dict[str, Any]:
    """
    Create a standard 429 Too Many Requests response.

    Args:
        limit: Rate limit
        remaining: Remaining requests
        reset_time: Reset time
        client_id: Client identifier
        client_type: Client type

    Returns:
        dict: Standardized rate limit response
    """
    return {
        "success": False,
        "error_code": "RATE_LIMIT_EXCEEDED",
        "message": "Rate limit exceeded",
        "data": {
            "limit": limit,
            "remaining": remaining,
            "reset_time": reset_time,
            "client_id": client_id,
            "client_type": client_type
        },
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": 429
    }


def resp_500(message: str = "Internal server error", details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Create a standard 500 Internal Server Error response.

    Args:
        message: Error message
        details: Additional error details

    Returns:
        dict: Standardized server error response
    """
    return {
        "success": False,
        "error_code": "INTERNAL_SERVER_ERROR",
        "message": message,
        "details": details,
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": 500
    }


# =============================================================================
# SPECIALIZED RESPONSE FUNCTIONS
# =============================================================================

def analysis_success_response(
    risk_level: str,
    confidence_score: float,
    detected_signals: Dict[str, Any],
    analysis_summary: str,
    recommendations: List[str],
    language_detected: Optional[str] = None,
    processing_time: Optional[float] = None,
    request_id: Optional[str] = None,
    reused: bool = False
) -> Dict[str, Any]:
    """
    Create a standardized analysis success response.

    Args:
        risk_level: Risk level (high, medium, low)
        confidence_score: Confidence score (0.0 to 1.0)
        detected_signals: Detected scam signals
        analysis_summary: Human-readable summary
        recommendations: Recommended actions
        language_detected: Detected language code
        processing_time: Processing time in seconds
        request_id: Unique request identifier
        reused: Whether result was reused from cache

    Returns:
        dict: Standardized analysis response
    """
    return {
        "success": True,
        "message": "Analysis completed successfully",
        "data": {
            "risk_level": risk_level,
            "confidence_score": confidence_score,
            "detected_signals": detected_signals,
            "analysis_summary": analysis_summary,
            "recommendations": recommendations,
            "language_detected": language_detected,
            "processing_time": processing_time
        },
        "metadata": {
            "request_id": request_id,
            "reused": reused
        },
        "timestamp": datetime.utcnow().isoformat()
    }


def translation_success_response(
    original_language: str,
    target_language: str,
    translated_summary: str,
    translated_recommendations: List[str],
    translation_confidence: float,
    processing_time: Optional[float] = None,
    request_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a standardized translation success response.

    Args:
        original_language: Original language code
        target_language: Target language code
        translated_summary: Translated analysis summary
        translated_recommendations: Translated recommendations
        translation_confidence: Translation confidence score
        processing_time: Translation processing time
        request_id: Unique request identifier

    Returns:
        dict: Standardized translation response
    """
    return {
        "success": True,
        "message": "Translation completed successfully",
        "data": {
            "original_language": original_language,
            "target_language": target_language,
            "translated_summary": translated_summary,
            "translated_recommendations": translated_recommendations,
            "translation_confidence": translation_confidence,
            "processing_time": processing_time
        },
        "metadata": {
            "request_id": request_id
        },
        "timestamp": datetime.utcnow().isoformat()
    }


def auth_success_response(
    client_id: str,
    client_type: str,
    permissions: List[str],
    method: str,
    expires_at: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a standardized authentication success response.

    Args:
        client_id: Client identifier
        client_type: Type of client
        permissions: Client permissions
        method: Authentication method used
        expires_at: Token expiration time

    Returns:
        dict: Standardized authentication response
    """
    return {
        "success": True,
        "message": "Authentication successful",
        "data": {
            "authenticated": True,
            "client_id": client_id,
            "client_type": client_type,
            "permissions": permissions,
            "method": method,
            "expires_at": expires_at
        },
        "timestamp": datetime.utcnow().isoformat()
    }


def health_success_response(
    service: str,
    version: str,
    uptime: Optional[float] = None,
    components: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Create a standardized health check success response.

    Args:
        service: Service name
        version: Service version
        uptime: Service uptime in seconds
        components: Component status dictionary

    Returns:
        dict: Standardized health response
    """
    return {
        "success": True,
        "message": "Service is healthy",
        "data": {
            "status": "healthy",
            "service": service,
            "version": version,
            "uptime": uptime,
            "components": components or {},
            "timestamp": datetime.utcnow().isoformat()
        },
        "timestamp": datetime.utcnow().isoformat()
    }


# =============================================================================
# ERROR RESPONSE FUNCTIONS
# =============================================================================

def validation_error_response(field_errors: Dict[str, str]) -> Dict[str, Any]:
    """
    Create a validation error response.

    Args:
        field_errors: Dictionary of field names and error messages

    Returns:
        dict: Validation error response
    """
    return {
        "success": False,
        "error_code": "VALIDATION_ERROR",
        "message": "Validation failed",
        "details": {"field_errors": field_errors},
        "suggestions": ["Check the input data format", "Ensure all required fields are provided"],
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": 400
    }


def database_error_response(operation: str, details: Optional[str] = None) -> Dict[str, Any]:
    """
    Create a database error response.

    Args:
        operation: Database operation that failed
        details: Additional error details

    Returns:
        dict: Database error response
    """
    return {
        "success": False,
        "error_code": "DATABASE_ERROR",
        "message": f"Database operation failed: {operation}",
        "details": {"operation": operation, "details": details},
        "suggestions": ["Try again later", "Contact support if the problem persists"],
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": 500
    }


def llm_error_response(operation: str, details: Optional[str] = None) -> Dict[str, Any]:
    """
    Create an LLM error response.

    Args:
        operation: LLM operation that failed
        details: Additional error details

    Returns:
        dict: LLM error response
    """
    return {
        "success": False,
        "error_code": "LLM_ERROR",
        "message": f"Language model operation failed: {operation}",
        "details": {"operation": operation, "details": details},
        "suggestions": ["Try again later", "Check input content", "Contact support if the problem persists"],
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": 500
    }


def permission_error_response(required_permission: str, client_permissions: List[str]) -> Dict[str, Any]:
    """
    Create a permission error response.

    Args:
        required_permission: Required permission
        client_permissions: Client's current permissions

    Returns:
        dict: Permission error response
    """
    return {
        "success": False,
        "error_code": "PERMISSION_DENIED",
        "message": f"Permission '{required_permission}' required",
        "details": {
            "required_permission": required_permission,
            "client_permissions": client_permissions
        },
        "suggestions": ["Contact administrator to request additional permissions"],
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": 403
    }
