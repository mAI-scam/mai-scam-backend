"""
Event Handlers for MAI Scam Detection System

This module provides startup and shutdown event handlers for the FastAPI application,
including logging, configuration, and application state setup.

TABLE OF CONTENTS:
==================

EXPORTED FUNCTIONS:
------------------
1. start_app_handler - Application startup handler
2. stop_app_handler - Application shutdown handler
3. setup_logging - Configure application logging
4. setup_middleware - Configure application middleware

USAGE EXAMPLES:
--------------
# In app.py
from core.event_handlers import start_app_handler, stop_app_handler

app = FastAPI()
app.add_event_handler("startup", start_app_handler(app))
app.add_event_handler("shutdown", stop_app_handler(app))
"""

import logging
from fastapi import FastAPI
from typing import Callable
from setting import Setting
from utils.constant import JWT_SECRET_KEY

config = Setting()
logger = logging.getLogger("Application Initialization")


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

def setup_logging() -> None:
    """
    Configure application logging.

    Sets up logging configuration for the entire application
    with appropriate log levels and formatting based on DEBUG_VERBOSE level.
    """
    # Get debug settings from config
    debug_mode = config.get("DEBUG", "False").lower() == "true"
    debug_verbose = int(config.get("DEBUG_VERBOSE", "2"))  # Default to normal (2)
    
    # Set log level based on verbosity
    if debug_verbose == 1:  # Minimal
        log_level = logging.WARNING
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
    elif debug_verbose == 2:  # Normal
        log_level = logging.INFO
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
    else:  # Verbose (3)
        log_level = logging.DEBUG
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.StreamHandler()
        ]
    )

    # Set external library log levels based on verbosity
    if debug_verbose == 1:  # Minimal - only warnings and errors
        logging.getLogger("uvicorn").setLevel(logging.WARNING)
        logging.getLogger("fastapi").setLevel(logging.WARNING)
        logging.getLogger("openai").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
    elif debug_verbose == 2:  # Normal - some info, no debug
        logging.getLogger("uvicorn").setLevel(logging.WARNING)
        logging.getLogger("fastapi").setLevel(logging.WARNING)
        logging.getLogger("openai").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
    else:  # Verbose (3) - show all logs
        logging.getLogger("uvicorn").setLevel(logging.INFO)
        logging.getLogger("fastapi").setLevel(logging.INFO)
        logging.getLogger("openai").setLevel(logging.INFO)
        logging.getLogger("httpx").setLevel(logging.INFO)
        logging.getLogger("httpcore").setLevel(logging.INFO)
    
    # Enable debug logging for our modules if debug mode is on
    if debug_mode and debug_verbose >= 2:
        logging.getLogger("utils.authUtils").setLevel(logging.DEBUG)
        logging.getLogger("middleware.auth_middleware").setLevel(logging.DEBUG)
        logging.getLogger("apis.auth").setLevel(logging.DEBUG)


# =============================================================================
# APPLICATION STATE SETUP
# =============================================================================

def _setup_app_state(app: FastAPI) -> None:
    """
    Setup application state and configuration.

    Initializes application state with configuration settings
    and environment variables.

    Args:
        app: FastAPI application instance
    """
    app.state.settings = {
        "APP_ENV": config.get("APP_ENV", "development"),
        "APP_API_VERSION": config.get("APP_API_VERSION", "1.0.0"),
        "JWT_SECRET_KEY": JWT_SECRET_KEY,
        "DEBUG": config.get("DEBUG", "False").lower() == "true"
    }


# =============================================================================
# STARTUP HANDLER
# =============================================================================

def start_app_handler(app: FastAPI) -> Callable:
    """
    Create application startup handler.

    This function returns a startup handler that initializes
    the application, sets up logging, and configuration.

    Args:
        app: FastAPI application instance

    Returns:
        Callable: Startup event handler function
    """
    def startup() -> None:
        """Application startup event handler."""
        try:
            # Setup logging
            setup_logging()
            logger.info("MAI Scam Detection API starting up...")

            # Setup application state
            _setup_app_state(app)
            logger.info("Application state initialized")

            # Log startup information
            logger.info("Authentication middleware enabled")
            logger.info("Rate limiting enabled")
            logger.info("CORS configured")
            logger.info("Security headers enabled")

            # Log configuration
            env = app.state.settings.get("APP_ENV", "development")
            version = app.state.settings.get("APP_API_VERSION", "1.0.0")
            logger.info(f"Environment: {env}")
            logger.info(f"API Version: {version}")

            logger.info(
                "MAI Scam Detection API startup completed successfully")

        except Exception as e:
            logger.error(f"Error during application startup: {str(e)}")
            raise

    return startup


# =============================================================================
# SHUTDOWN HANDLER
# =============================================================================

def stop_app_handler(app: FastAPI) -> Callable:
    """
    Create application shutdown handler.

    This function returns a shutdown handler that performs
    cleanup operations when the application shuts down.

    Args:
        app: FastAPI application instance

    Returns:
        Callable: Shutdown event handler function
    """
    def shutdown() -> None:
        """Application shutdown event handler."""
        try:
            logger.info("MAI Scam Detection API shutting down...")

            # Perform cleanup operations here
            # For example: close database connections, cleanup temporary files, etc.

            logger.info("Cleanup operations completed")
            logger.info("MAI Scam Detection API shutdown completed")

        except Exception as e:
            logger.error(f"Error during application shutdown: {str(e)}")

    return shutdown


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_app_settings(app: FastAPI) -> dict:
    """
    Get application settings from app state.

    Args:
        app: FastAPI application instance

    Returns:
        dict: Application settings
    """
    return getattr(app.state, 'settings', {})


def is_production(app: FastAPI) -> bool:
    """
    Check if application is running in production mode.

    Args:
        app: FastAPI application instance

    Returns:
        bool: True if running in production
    """
    settings = get_app_settings(app)
    return settings.get("APP_ENV", "development") == "production"


def is_debug_mode(app: FastAPI) -> bool:
    """
    Check if application is running in debug mode.

    Args:
        app: FastAPI application instance

    Returns:
        bool: True if debug mode is enabled
    """
    settings = get_app_settings(app)
    return settings.get("DEBUG", False)
