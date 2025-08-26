"""
Main Router for MAI Scam Detection System

This module defines all API routes as an APIRouter that can be included
in the main FastAPI application.

TABLE OF CONTENTS:
==================

INCLUDED ROUTERS:
----------------
1. / - Root endpoint with API information
2. /auth - Authentication endpoints
3. /email - Email analysis endpoints
4. /socialmedia - Social media analysis endpoints
5. /website - Website analysis endpoints
6. /api/v1/ocr - OCR (Optical Character Recognition) endpoints
7. /email/v2/analyze - V2 Email analysis endpoint (SEA-LION v4)
8. /health - Health check endpoint
9. /debug/auth - Debug authentication endpoint (development only)

SECURITY FEATURES:
-----------------
- JWT token authentication
- API key authentication
- Rate limiting
- Permission-based access control
- CORS configuration
- Security headers

USAGE EXAMPLES:
--------------
# With JWT token
curl -X POST "http://localhost:8000/email/analyze" \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{"subject": "Test", "content": "Hello"}'

# With API key
curl -X POST "http://localhost:8000/email/analyze" \
  -H "X-API-Key: <api_key>" \
  -H "Content-Type: application/json" \
  -d '{"subject": "Test", "content": "Hello"}'
"""

from fastapi import APIRouter
from apis import email, socialmedia, website, auth, main, ocr

# Create main router
router = APIRouter()

# =============================================================================
# ROUTE INCLUSION
# =============================================================================

# Include main routes (root, health, debug)
router.include_router(main.router)

# Include authentication routes (no auth required for these)
router.include_router(auth.router)

# Include analysis routes (auth required)
router.include_router(email.router)
router.include_router(socialmedia.router)
router.include_router(website.router)
router.include_router(ocr.router)
