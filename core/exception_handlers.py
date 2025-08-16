"""
Exception Handlers for MAI Scam Detection System

This module provides centralized exception handling for the FastAPI application,
ensuring consistent error responses across all endpoints.

TABLE OF CONTENTS:
==================

EXPORTED FUNCTIONS:
------------------
1. setup_exception_handlers - Configure exception handlers for FastAPI app
2. not_found_handler - Handle 404 errors
3. internal_error_handler - Handle 500 errors
4. validation_error_handler - Handle validation errors
5. authentication_error_handler - Handle authentication errors

USAGE EXAMPLES:
--------------
# In app.py
from core.exception_handlers import setup_exception_handlers

app = FastAPI()
setup_exception_handlers(app)
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


# =============================================================================
# EXCEPTION HANDLER FUNCTIONS
# =============================================================================

def not_found_handler(request: Request, exc):
    """
    Handle 404 errors.

    Args:
        request: FastAPI request object
        exc: Exception that was raised

    Returns:
        JSONResponse: Standardized 404 error response
    """
    return JSONResponse(
        status_code=404,
        content={
            "success": False,
            "error_code": "NOT_FOUND",
            "message": "The requested resource was not found",
            "path": request.url.path,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    )


def internal_error_handler(request: Request, exc):
    """
    Handle 500 errors.

    Args:
        request: FastAPI request object
        exc: Exception that was raised

    Returns:
        JSONResponse: Standardized 500 error response
    """
    logger.error(f"Internal server error: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error_code": "INTERNAL_SERVER_ERROR",
            "message": "An internal server error occurred",
            "path": request.url.path,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    )


def validation_error_handler(request: Request, exc: RequestValidationError):
    """
    Handle validation errors (422).

    Args:
        request: FastAPI request object
        exc: RequestValidationError that was raised

    Returns:
        JSONResponse: Standardized validation error response
    """
    errors = []
    for error in exc.errors():
        errors.append({
            "field": " -> ".join(str(loc) for loc in error["loc"]),
            "message": error["msg"],
            "type": error["type"]
        })

    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "error_code": "VALIDATION_ERROR",
            "message": "Request validation failed",
            "errors": errors,
            "path": request.url.path,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    )


def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """
    Handle HTTP exceptions.

    Args:
        request: FastAPI request object
        exc: StarletteHTTPException that was raised

    Returns:
        JSONResponse: Standardized HTTP error response
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error_code": f"HTTP_{exc.status_code}",
            "message": exc.detail,
            "path": request.url.path,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    )


def authentication_error_handler(request: Request, exc: HTTPException):
    """
    Handle authentication errors (401, 403).

    Args:
        request: FastAPI request object
        exc: HTTPException that was raised

    Returns:
        JSONResponse: Standardized authentication error response
    """
    error_code = "UNAUTHORIZED" if exc.status_code == 401 else "FORBIDDEN"

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error_code": error_code,
            "message": exc.detail,
            "path": request.url.path,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    )


# =============================================================================
# SETUP FUNCTION
# =============================================================================

def setup_exception_handlers(app: FastAPI) -> None:
    """
    Setup all exception handlers for the FastAPI application.

    This function registers all the exception handlers to ensure
    consistent error responses across the application.

    Args:
        app: FastAPI application instance
    """
    # Register exception handlers
    app.add_exception_handler(404, not_found_handler)
    app.add_exception_handler(500, internal_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)

    # Register specific HTTP exception handlers
    app.add_exception_handler(401, authentication_error_handler)
    app.add_exception_handler(403, authentication_error_handler)

    logger.info("Exception handlers configured successfully")


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def create_error_response(
    error_code: str,
    message: str,
    path: str,
    details: dict = None
) -> dict:
    """
    Create a standardized error response.

    Args:
        error_code: Error code identifier
        message: Error message
        path: Request path
        details: Additional error details

    Returns:
        dict: Standardized error response
    """
    response = {
        "success": False,
        "error_code": error_code,
        "message": message,
        "path": path,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    if details:
        response["details"] = details

    return response


def log_exception(request: Request, exc: Exception, context: str = "Unknown") -> None:
    """
    Log exception details for debugging.

    Args:
        request: FastAPI request object
        exc: Exception that was raised
        context: Context where the exception occurred
    """
    logger.error(
        f"Exception in {context}: {str(exc)} | "
        f"Path: {request.url.path} | "
        f"Method: {request.method} | "
        f"Client: {request.client.host if request.client else 'Unknown'}"
    )
