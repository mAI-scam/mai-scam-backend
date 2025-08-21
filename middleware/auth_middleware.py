"""
Authentication Middleware for MAI Scam Detection System

This module provides middleware for securing FastAPI routes with authentication
and permission checking.

TABLE OF CONTENTS:
==================

EXPORTED FUNCTIONS:
------------------
1. auth_middleware
2. require_auth
3. require_permission
4. rate_limit_middleware

USAGE EXAMPLES:
--------------
# Apply authentication to all routes
app.add_middleware(auth_middleware)

# Require authentication for specific endpoint
@app.post("/analyze")
@require_auth
async def analyze_endpoint(request: Request):
    pass

# Require specific permission
@app.post("/analyze")
@require_permission("email_analysis")
async def analyze_endpoint(request: Request):
    pass
"""

from datetime import datetime
import logging
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request, HTTPException, Depends
from starlette.responses import JSONResponse
from typing import Callable, Optional
import time
from utils.authUtils import authenticate_request, verify_jwt_token, verify_api_key
from utils.constant import PUBLIC_ENDPOINTS, AUTH_REQUIRED_ENDPOINTS, PERMISSION_PROTECTED_ENDPOINTS, ADMIN_ENDPOINTS


# =============================================================================
# 1. AUTHENTICATION MIDDLEWARE
# =============================================================================

class AuthMiddleware:
    """
    Middleware for authenticating requests.

    This middleware checks for authentication credentials in all requests
    and validates them before allowing access to protected endpoints.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            request = Request(scope, receive)

            # Skip authentication for certain paths
            if self._should_skip_auth(request.url.path):
                await self.app(scope, receive, send)
                return

            try:
                # Authenticate the request
                auth_result = authenticate_request(request)

                # Add authentication info to request state
                scope["auth"] = auth_result

            except HTTPException as e:
                # Return authentication error
                response = JSONResponse(
                    status_code=e.status_code,
                    content={"detail": e.detail}
                )
                await response(scope, receive, send)
                return
            except Exception as e:
                # Get verbosity level from config
                from setting import Setting
                config = Setting()
                debug_verbose = int(config.get("DEBUG_VERBOSE", "2"))

                # Log detailed error information based on verbosity
                if debug_verbose >= 3:  # Verbose mode - show full traceback
                    import traceback
                    logger.error(
                        f"Unhandled error in {request.method} {request.url.path}: {str(e)}")
                    logger.error(f"Error type: {type(e).__name__}")
                    logger.error(f"Full traceback:\n{traceback.format_exc()}")
                elif debug_verbose == 2:  # Normal mode - show error and type
                    logger.error(
                        f"Unhandled error in {request.method} {request.url.path}: {str(e)}")
                    logger.error(f"Error type: {type(e).__name__}")
                else:  # Minimal mode - just the error message
                    logger.error(
                        f"Unhandled error in {request.method} {request.url.path}: {str(e)}")

                # Return generic error response
                response = JSONResponse(
                    status_code=500,
                    content={"detail": "Internal server error"}
                )
                await response(scope, receive, send)
                return

        await self.app(scope, receive, send)

    def _should_skip_auth(self, path: str) -> bool:
        """
        Check if authentication should be skipped for this path.

        Args:
            path: Request path

        Returns:
            bool: True if auth should be skipped
        """
        # Use central configuration from utils/constant.py
        # Check for exact matches first, then startswith for path patterns
        for skip_path in PUBLIC_ENDPOINTS:
            # For exact paths like /docs, /redoc, /openapi.json
            if path == skip_path:
                return True
            # For path patterns like /auth/token, /auth/api-key
            if skip_path.endswith('/') and path.startswith(skip_path):
                return True
            # For root path
            if skip_path == "/" and path == "/":
                return True
        return False


# =============================================================================
# 2. AUTHENTICATION DEPENDENCY
# =============================================================================

async def require_auth(request: Request) -> dict:
    """
    FastAPI dependency that requires authentication.

    Args:
        request: FastAPI request object

    Returns:
        dict: Authentication result

    Raises:
        HTTPException: If authentication fails
    """
    return authenticate_request(request)


# =============================================================================
# 3. PERMISSION DEPENDENCY FACTORY
# =============================================================================

def require_permission(required_permission: str):
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

        # Check if user has admin permissions (wildcard)
        if "*" in permissions:
            return auth_result

        if required_permission not in permissions:
            raise HTTPException(
                status_code=403,
                detail=f"Permission '{required_permission}' required"
            )

        return auth_result

    return check_permission


# =============================================================================
# 4. ENDPOINT-SPECIFIC PERMISSION CHECKING
# =============================================================================

def require_endpoint_permission():
    """
    FastAPI dependency that checks permissions based on the endpoint path.

    This function automatically determines the required permission based on
    the PERMISSION_PROTECTED_ENDPOINTS configuration.
    """
    async def check_endpoint_permission(request: Request):
        path = request.url.path

        # Check if endpoint requires specific permissions
        if path in PERMISSION_PROTECTED_ENDPOINTS:
            required_permissions = PERMISSION_PROTECTED_ENDPOINTS[path]
            auth_result = authenticate_request(request)
            user_permissions = auth_result.get("permissions", [])

            # Check if user has admin permissions (wildcard)
            if "*" in user_permissions:
                return auth_result

            # Check if user has any of the required permissions
            if not any(perm in user_permissions for perm in required_permissions):
                raise HTTPException(
                    status_code=403,
                    detail=f"One of these permissions required: {', '.join(required_permissions)}"
                )

            return auth_result

        # For endpoints not in PERMISSION_PROTECTED_ENDPOINTS, just require authentication
        return authenticate_request(request)

    return check_endpoint_permission


# =============================================================================
# 5. ADMIN-ONLY ENDPOINT CHECKING
# =============================================================================

def require_admin():
    """
    FastAPI dependency that requires admin permissions.
    """
    async def check_admin_permission(request: Request):
        auth_result = authenticate_request(request)
        permissions = auth_result.get("permissions", [])

        if "*" not in permissions:
            raise HTTPException(
                status_code=403,
                detail="Admin permissions required"
            )

        return auth_result

    return check_admin_permission


# =============================================================================
# 6. RATE LIMITING MIDDLEWARE
# =============================================================================

class RateLimitMiddleware:
    """
    Middleware for rate limiting requests.

    This middleware tracks request counts and enforces rate limits
    based on client type and configuration.
    """

    def __init__(self, app):
        self.app = app
        self.request_counts = {}

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            request = Request(scope, receive)

            # Get client info from authentication
            auth_info = scope.get("auth")
            if auth_info:
                client_id = auth_info.get("client_id")
                client_type = auth_info.get("client_type")

                if client_id and client_type:
                    # Check rate limit
                    if not self._check_rate_limit(client_id, client_type):
                        response = JSONResponse(
                            status_code=429,
                            content={"detail": "Rate limit exceeded"}
                        )
                        await response(scope, receive, send)
                        return

        await self.app(scope, receive, send)

    def _check_rate_limit(self, client_id: str, client_type: str) -> bool:
        """
        Check if client is within rate limits.

        Args:
            client_id: Client identifier
            client_type: Type of client

        Returns:
            bool: True if within rate limit, False otherwise
        """
        current_time = int(time.time())
        hour_key = current_time // 3600

        # Get rate limit for client type
        rate_limits = {
            "web_extension": 100,
            "chatbot": 50,
            "mobile_app": 200,
            "api_client": 1000
        }

        rate_limit = rate_limits.get(client_type, 10)
        key = f"{client_id}:{hour_key}"

        current_count = self.request_counts.get(key, 0)

        if current_count >= rate_limit:
            return False

        self.request_counts[key] = current_count + 1
        return True


# =============================================================================
# 7. CORS MIDDLEWARE CONFIGURATION
# =============================================================================


def configure_cors(app):
    """
    Configure CORS middleware for the application.

    Args:
        app: FastAPI application instance
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "chrome-extension://*",  # Chrome extensions
            "moz-extension://*",     # Firefox extensions
            "http://localhost:3000",  # Local development
            "https://your-domain.com"  # Your production domain
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )


# =============================================================================
# 8. SECURITY HEADERS MIDDLEWARE
# =============================================================================

class SecurityHeadersMiddleware:
    """
    Middleware for adding security headers to responses.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Add security headers
            async def send_with_headers(message):
                if message["type"] == "http.response.start":
                    headers = message.get("headers", [])
                    
                    # Check if this is a docs endpoint that needs more permissive CSP
                    path = scope.get("path", "")
                    is_docs_endpoint = path in ["/docs", "/redoc", "/openapi.json"]
                    
                    # Add basic security headers
                    headers.extend([
                        (b"X-Content-Type-Options", b"nosniff"),
                        (b"X-Frame-Options", b"DENY"),
                        (b"X-XSS-Protection", b"1; mode=block"),
                        (b"Strict-Transport-Security",
                         b"max-age=31536000; includeSubDomains"),
                    ])
                    
                    # Add appropriate CSP based on endpoint
                    if is_docs_endpoint:
                        # More permissive CSP for docs to allow Swagger UI and ReDoc to work
                        csp = (
                            b"default-src 'self'; "
                            b"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
                            b"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://fonts.googleapis.com; "
                            b"font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net https://unpkg.com; "
                            b"img-src 'self' data: https:; "
                            b"connect-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
                            b"frame-ancestors 'none'"
                        )
                    else:
                        # Strict CSP for regular endpoints
                        csp = b"default-src 'self'; frame-ancestors 'none'"
                    
                    headers.append((b"Content-Security-Policy", csp))
                    message["headers"] = headers
                await send(message)

            await self.app(scope, receive, send_with_headers)
        else:
            await self.app(scope, receive, send)


# =============================================================================
# 9. LOGGING MIDDLEWARE
# =============================================================================


logger = logging.getLogger(__name__)


class LoggingMiddleware:
    """
    Middleware for logging requests and responses.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            request = Request(scope, receive)
            start_time = time.time()

            # Track response
            async def send_with_logging(message):
                if message["type"] == "http.response.start":
                    end_time = time.time()
                    duration = end_time - start_time
                    status_code = message.get("status", 200)

                    # Get verbosity level from config
                    from setting import Setting
                    config = Setting()
                    debug_verbose = int(config.get("DEBUG_VERBOSE", "2"))

                    # Log based on verbosity level
                    if debug_verbose == 1:  # Minimal - only errors and slow requests
                        if status_code >= 400 or duration > 5.0:
                            logger.warning(
                                f"{request.method} {request.url.path} - {status_code} ({duration:.2f}s)")
                    elif debug_verbose == 2:  # Normal - errors and moderately slow requests
                        if status_code >= 400 or duration > 1.0:
                            logger.info(
                                f"{request.method} {request.url.path} - {status_code} ({duration:.2f}s)")
                    else:  # Verbose (3) - log everything
                        logger.info(
                            f"{request.method} {request.url.path} - {status_code} ({duration:.2f}s)")

                await send(message)

            await self.app(scope, receive, send_with_logging)
        else:
            await self.app(scope, receive, send)


# =============================================================================
# 10. ERROR HANDLING MIDDLEWARE
# =============================================================================

class ErrorHandlingMiddleware:
    """
    Middleware for handling and logging errors.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        try:
            await self.app(scope, receive, send)
        except Exception as e:
            import traceback

            # Log essential error information
            logger.error(
                f"Error in {scope.get('method', 'unknown')} {scope.get('path', 'unknown')}: {str(e)}")

            # Return error response
            response = JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"}
            )
            await response(scope, receive, send)
