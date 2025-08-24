# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

mAIScam API is a FastAPI-based backend service that provides intelligent spam detection and OCR (Optical Character Recognition) capabilities. The service uses Sea-Lion AI for multilingual spam/scam detection and Mistral AI for OCR processing.

## Development Commands

### Environment Setup
```bash
# Create and activate virtual environment (Python 3.10+ required)
python3.10 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Application
```bash
# Run with Python (uses settings from app.py)
python app.py

# Run with uvicorn directly (development mode with auto-reload)
uvicorn app:app --host 0.0.0.0 --port 8000 --reload

# Production mode
uvicorn app:app --host 0.0.0.0 --port 8000
```

### Testing and Development
```bash
# Test spam detection functionality
python test.py

# Test OCR functionality  
python test-ocr.py

# Access interactive API documentation
# http://localhost:8000/docs (Swagger UI)
# http://localhost:8000/redoc (ReDoc)
```

### Environment Configuration
```bash
# Set environment (defaults to 'uat')
export APP_ENV=uat  # or 'prd' for production

# Required API keys (set in .env file)
export SEA_LION_API_KEY="your-sea-lion-api-key"
export MISTRAL_API_KEY="your-mistral-api-key"
```

## Architecture Overview

### Core Components

**FastAPI Application (`app.py`)**
- Main application factory with CORS middleware
- Lifecycle event handlers for startup/shutdown
- OpenAPI 3.0.2 specification

**Settings Management (`setting.py`)**
- Environment-based configuration loading
- Supports `.env` files and YAML configs (`env/uat.yaml`, `env/prd.yaml`)
- Environment variables override YAML settings

**API Layer (`apis/main.py`, `router.py`)**
- RESTful endpoints for spam detection and OCR
- Pydantic models for request/response validation
- JSON response parsing and error handling

**AI Service Clients (`models/clients.py`)**
- Singleton pattern for managing external AI service connections
- Sea-Lion AI client (OpenAI-compatible API)
- Mistral AI client for OCR processing
- Centralized error handling and API key validation

**Response Models (`models/customResponse.py`)**
- Standardized JSON response format
- HTTP status code helpers (200, 400, 403, 500)
- Consistent success/error structure

### Key Endpoints

- `GET /` - Health check and version info
- `POST /detect-spam` - Multilingual spam/scam detection using Sea-Lion AI
- `POST /ocr` - Text extraction from images via URL or base64
- `POST /ocr-upload` - Text extraction from uploaded image files

### External Dependencies

**AI Services:**
- Sea-Lion AI (aisingapore/Llama-SEA-LION-v3.5-8B-R) for spam detection with multilingual support
- Mistral AI OCR for image text extraction

**Core Libraries:**
- FastAPI + Uvicorn for web framework and ASGI server
- Pydantic for data validation and serialization
- python-dotenv + PyYAML for configuration management

### Configuration Strategy

The application uses a hierarchical configuration approach:

1. Environment variables from `.env` file (highest priority)
2. YAML configuration files (`env/uat.yaml`, `env/prd.yaml`)
3. Default values in code

Environment switching via `APP_ENV` variable determines which YAML config to load.

### Error Handling Patterns

- Custom `ClientError` exceptions for AI service initialization
- JSON parsing with fallback for AI responses (handles markdown code blocks)
- HTTP exception mapping with detailed error messages
- Input validation using Pydantic models

### AI Integration Patterns

**Spam Detection:**
- Uses detailed prompts for language-specific responses
- JSON response parsing with multiple fallback strategies
- Multilingual support (English, Malay, Chinese, Thai, Vietnamese)
- "Thinking mode" enabled for better reasoning

**OCR Processing:**
- Supports multiple input formats (URL, base64, file upload)
- Automatic image type detection
- Markdown output parsing from OCR results
