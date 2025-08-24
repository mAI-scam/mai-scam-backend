# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Running the Application
```bash
# Primary method
python app.py

# Alternative with uvicorn directly
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

### Testing
```bash
# Test specific components
python test.py         # General tests
python test-ocr.py     # OCR functionality
python test_swagger.py # API documentation
```

### Dependencies
```bash
# Install dependencies
pip install -r requirements.txt

# For UV package manager users
uv pip install -r requirements.txt
```

## Project Architecture

### FastAPI Application Structure
The application follows a modular FastAPI architecture with clear separation of concerns:

- **`app.py`** - Main application entry point with middleware setup
- **`router.py`** - Central router that includes all API route modules
- **`setting.py`** - Environment configuration management using YAML files from `env/` directory

### API Module Organization
API endpoints are organized by domain in the `apis/` directory:
- **`main.py`** - Core endpoints (health, debug, root)
- **`auth.py`** - Authentication and authorization
- **`email.py`** - Email spam/scam detection
- **`socialmedia.py`** - Social media content analysis
- **`website.py`** - Website analysis
- **`ocr.py`** - Optical Character Recognition

### Core Components
- **`core/`** - Application lifecycle handlers and exception management
- **`middleware/`** - Authentication, rate limiting, security headers, CORS, logging
- **`models/`** - Pydantic models and API client configurations
- **`utils/`** - Utility functions for authentication, database, LLM interactions
- **`prompts/`** - AI model prompts for different analysis types

### Authentication System
The application implements a comprehensive authentication system:
- **JWT tokens** for stateless authentication
- **API keys** for long-term client access
- **Permission-based access control** with granular permissions
- **Rate limiting** per client type
- **Client types**: web_extension, chatbot, mobile_app, admin

Authentication configuration is centrally managed in `utils/constant.py` with endpoint-specific protection levels.

### Environment Configuration
Configuration uses environment-specific YAML files in `env/`:
- `env/prd.yaml` - Production settings
- `env/uat.yaml` - UAT environment settings

The `APP_ENV` environment variable determines which config file to load.

### AI Integration
The application integrates with multiple AI services:
- **Sea-Lion AI** for spam/scam detection with multilingual support
- **Mistral AI** for OCR text extraction from images
- **OpenAI** client for additional LLM capabilities

## Key Development Notes

### Middleware Order
Middleware is configured in a specific order in `app.py:setup_middleware()` - maintain this order for proper functionality.

### API Documentation
- Interactive docs available at `/docs` (Swagger UI)
- Alternative docs at `/redoc`
- Auto-generated OpenAPI 3.0.2 specification

### Security Features
- TrustedHostMiddleware for production deployment
- Security headers middleware (X-Frame-Options, HSTS, etc.)
- CORS configuration for cross-origin requests
- Comprehensive logging and error handling

### Database Integration
Uses MongoDB with PyMongo for data persistence, configured via `MONGODB_URI` environment variable.

### Testing Strategy
The codebase includes domain-specific test files rather than a unified test framework - run individual test files as needed for specific components.