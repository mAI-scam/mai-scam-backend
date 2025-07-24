# mAIScam API

A FastAPI-based backend service that provides intelligent spam detection and OCR (Optical Character Recognition) capabilities using AI models.

## Features

- **Spam Detection**: Detect spam/scam messages using Sea-Lion AI model with multilingual support
- **OCR Processing**: Extract text from images using Mistral AI OCR
- **Multiple Input Methods**: Support for image URLs, base64 encoded images, and file uploads
- **CORS Enabled**: Cross-origin resource sharing for frontend integration

## API Endpoints

### Health Check
- `GET /` - Returns API version and environment information

### Spam Detection
- `POST /detect-spam` - Analyze messages for spam/scam content
  - Supports multiple languages (English, Malay, Chinese, Thai, Vietnamese)
  - Returns classification and warning signs explanation

### OCR Processing
- `POST /ocr` - Extract text from images via URL or base64
- `POST /ocr-upload` - Upload image files for text extraction

## Requirements

- **Python**: 3.10 or higher
- **pip**: Package installer for Python

## Setup Instructions

### 1. Clone the Repository

```bash
git clone <repository-url>
cd mai-scam-backend
```

### 2. Create Virtual Environment

It's recommended to use a virtual environment to isolate project dependencies:

```bash
# Create virtual environment
python3.10 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
# venv\Scripts\activate
```

### 3. Install Dependencies

Install all required packages using pip:

```bash
pip install -r requirements.txt
```

### 4. Environment Configuration

Configure your environment settings by creating appropriate YAML files in the `env/` directory:

- `env/prd.yaml` - Production environment settings
- `env/uat.yaml` - UAT environment settings

### 5. API Keys Setup

Ensure you have the necessary API keys configured for:
- Sea-Lion AI model (for spam detection)
- Mistral AI (for OCR processing)

### 6. Run the Application

Start the FastAPI server:

```bash
# Run with default settings
python app.py

# Or use uvicorn directly
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at `http://localhost:8000`

### 7. API Documentation

Once the server is running, you can access:
- **Interactive API docs**: `http://localhost:8000/docs`
- **ReDoc documentation**: `http://localhost:8000/redoc`

## Development

### Project Structure

```
mai-scam-backend/
├── apis/
│   └── main.py          # API endpoints
├── app.py              # FastAPI application entry point
├── core/
│   └── event_handlers.py # Application lifecycle handlers
├── env/                # Environment configuration files
├── models/             # Data models and client configurations
├── router.py           # API routing
├── setting.py          # Settings management
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

### Key Dependencies

- **FastAPI**: Modern web framework for building APIs
- **uvicorn**: ASGI server for running FastAPI applications
- **mistralai**: Mistral AI client for OCR processing
- **openai**: OpenAI client for AI model interactions
- **pymongo**: MongoDB driver for database operations
- **pydantic**: Data validation and serialization

## Usage Examples

### Spam Detection

```bash
curl -X POST "http://localhost:8000/detect-spam" \
  -H "Content-Type: application/json" \
  -d '{"message": "Congratulations! You won $1000! Click here to claim your prize!"}'
```

### OCR Processing

```bash
# Using image URL
curl -X POST "http://localhost:8000/ocr" \
  -H "Content-Type: application/json" \
  -d '{"image_url": "https://example.com/image.jpg"}'

# Using file upload
curl -X POST "http://localhost:8000/ocr-upload" \
  -F "file=@path/to/your/image.jpg"
```
