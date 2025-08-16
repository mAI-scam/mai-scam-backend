"""
Main Application Entry Point for MAI Scam Detection System

This module creates and configures the FastAPI application with all necessary
middleware, event handlers, and routes.

TABLE OF CONTENTS:
==================

MAIN FUNCTIONS:
--------------
1. get_application - Create and configure FastAPI application
2. main - Application entry point

USAGE EXAMPLES:
--------------
# Run the application
python app.py

# Or with uvicorn directly
uvicorn app:app --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI
from setting import Setting
from router import router as api_router
from core.event_handlers import start_app_handler, stop_app_handler
from core.exception_handlers import setup_exception_handlers
from middleware.auth_middleware import (
    AuthMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware,
    LoggingMiddleware, ErrorHandlingMiddleware, configure_cors
)
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
import logging

config = Setting()
logger = logging.getLogger(__name__)


def setup_middleware(app: FastAPI) -> None:
    """
    Setup all middleware for the FastAPI application.

    This function configures all middleware components including security,
    authentication, rate limiting, and CORS.

    Args:
        app: FastAPI application instance
    """
    # Add security middleware
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(ErrorHandlingMiddleware)
    app.add_middleware(LoggingMiddleware)

    # Add authentication middleware (applies to all routes)
    app.add_middleware(AuthMiddleware)

    # Add rate limiting middleware
    app.add_middleware(RateLimitMiddleware)

    # Configure CORS
    configure_cors(app)

    # Add trusted host middleware for production
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", "your-domain.com"]
    )


def get_application() -> FastAPI:
    """
    Create and configure the FastAPI application.

    This function sets up the FastAPI app with all necessary middleware,
    event handlers, and routes.

    Returns:
        FastAPI: Configured FastAPI application instance
    """
    # Create FastAPI application
    application = FastAPI(
        title="MAI Scam Detection API",
        description="API for detecting scams in emails, social media, and websites",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        debug=config.get("DEBUG", "False").lower() == "true"
    )

    # Setup middleware (must be done before event handlers)
    setup_middleware(application)

    # Register lifecycle event handlers
    # These will handle logging and application state
    application.add_event_handler("startup", start_app_handler(application))
    application.add_event_handler("shutdown", stop_app_handler(application))

    # Setup exception handlers
    setup_exception_handlers(application)

    # Include all API routes from router.py
    application.include_router(api_router)

    # Enforce OpenAPI spec version
    application.openapi_version = "3.0.2"

    return application


# Create the application instance
app = get_application()


def main():
    """
    Main application entry point.

    Runs the FastAPI application using uvicorn with configuration
    from the settings.
    """
    server_host = config.get("SERVER_HOST", "0.0.0.0")
    server_port = int(config.get("SERVER_PORT", "8000"))

    print(f"Starting MAI Scam Detection API on {server_host}:{server_port}")
    print("Press Ctrl+C to stop the server")

    uvicorn.run(
        app,
        host=server_host,
        port=server_port,
        log_level="info"
    )


if __name__ == "__main__":
    main()
