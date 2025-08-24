"""
OCR API Endpoints for MAI Scam Detection System

This module provides OCR (Optical Character Recognition) endpoints for extracting text
from images using Mistral AI's OCR model. Supports both URL-based and file upload processing.

ENDPOINTS:
----------
1. POST /api/v1/ocr/process - Process images via URL or base64
2. POST /api/v1/ocr/upload - Upload image files for processing

FEATURES:
---------
- Mistral OCR model integration
- Support for multiple image formats (JPEG, PNG, GIF, WebP)
- URL and base64 image processing
- File upload with size validation
- Detailed processing metrics
- Error handling and validation

USAGE EXAMPLES:
--------------
# Process image from URL
curl -X POST "http://localhost:8000/api/v1/ocr/process" \
  -H "Content-Type: application/json" \
  -d '{"image_url": "https://example.com/image.jpg"}'

# Process base64 image
curl -X POST "http://localhost:8000/api/v1/ocr/process" \
  -H "Content-Type: application/json" \
  -d '{"image_base64": "base64string...", "image_type": "png"}'

# Upload image file
curl -X POST "http://localhost:8000/api/v1/ocr/upload" \
  -F "file=@image.jpg"
"""

from fastapi import APIRouter, HTTPException, File, UploadFile, Request
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from models.clients import get_mistral_client
from models.customResponse import resp_200, resp_400, resp_500
import base64
import time

router = APIRouter(prefix="/api/v1/ocr", tags=["OCR"])

# =============================================================================
# REQUEST AND RESPONSE MODELS
# =============================================================================

class OCRRequest(BaseModel):
    """OCR request model for image processing."""
    image_url: Optional[str] = Field(None, description="URL of the image to process")
    image_base64: Optional[str] = Field(None, description="Base64 encoded image data")
    image_type: Optional[str] = Field(default="jpeg", description="Image type: jpeg, png, gif, webp")


class OCRResponse(BaseModel):
    """OCR response model."""
    success: bool = Field(..., description="Whether the OCR was successful")
    message: str = Field(..., description="Response message")
    data: Dict[str, Any] = Field(..., description="OCR results")
    timestamp: str = Field(..., description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def encode_image_from_bytes(image_bytes):
    """Encode image bytes to base64."""
    try:
        return base64.b64encode(image_bytes).decode('utf-8')
    except Exception as e:
        raise HTTPException(
            status_code=400, detail=f"Error encoding image: {e}")

# =============================================================================
# OCR ENDPOINTS
# =============================================================================

@router.post("/process", response_model=OCRResponse)
def ocr_process(request: OCRRequest):
    """
    Extract text from images using Mistral OCR.
    
    This endpoint processes images and extracts text content using Mistral's OCR model.
    Supports both image URLs and base64 encoded images.
    
    Args:
        request: OCR request with image data
        
    Returns:
        OCRResponse: Extracted text and metadata
        
    Raises:
        HTTPException: If processing fails or input is invalid
    """
    start_time = time.time()
    
    try:
        # Validate input - must have either image_url or image_base64
        if not request.image_url and not request.image_base64:
            return resp_400(
                message="Either image_url or image_base64 must be provided",
                details={"error_type": "missing_input"}
            )

        if request.image_url and request.image_base64:
            return resp_400(
                message="Provide either image_url or image_base64, not both",
                details={"error_type": "conflicting_input"}
            )

        client = get_mistral_client()

        # Prepare document for OCR
        if request.image_url:
            # Handle URL input
            document = {
                "type": "image_url",
                "image_url": request.image_url
            }
        else:
            # Handle base64 input
            image_type = request.image_type or "jpeg"
            document = {
                "type": "image_url",
                "image_url": f"data:image/{image_type};base64,{request.image_base64}"
            }

        # Process with Mistral OCR
        ocr_response = client.ocr.process(
            model="mistral-ocr-latest",
            document=document,
            include_image_base64=True
        )

        # Extract text from all pages
        extracted_text = ""
        pages_processed = []
        
        for i, page in enumerate(ocr_response.pages):
            page_text = page.markdown.strip()
            extracted_text += page_text + "\n"
            pages_processed.append({
                "page_number": i + 1,
                "text": page_text,
                "text_length": len(page_text)
            })
        
        processing_time = time.time() - start_time

        return resp_200(
            data={
                "extracted_text": extracted_text.strip(),
                "pages_processed": len(pages_processed),
                "page_details": pages_processed,
                "processing_time": round(processing_time, 2),
                "model_used": "mistral-ocr-latest",
                "input_type": "url" if request.image_url else "base64"
            },
            message="OCR processing completed successfully"
        )

    except HTTPException as he:
        # Re-raise HTTP exceptions (validation errors)
        raise he
    except Exception as e:
        processing_time = time.time() - start_time
        return resp_500(
            message="OCR processing failed",
            details={
                "error": str(e),
                "error_type": type(e).__name__,
                "processing_time": round(processing_time, 2)
            }
        )


@router.post("/upload", response_model=OCRResponse)
async def ocr_upload(file: UploadFile = File(...)):
    """
    Upload and process image files for OCR text extraction.
    
    This endpoint accepts image file uploads and extracts text content using Mistral's OCR model.
    Supports common image formats (JPEG, PNG, GIF, WebP).
    
    Args:
        file: Uploaded image file
        
    Returns:
        OCRResponse: Extracted text and metadata
        
    Raises:
        HTTPException: If file processing fails or format is unsupported
    """
    start_time = time.time()
    
    try:
        # Validate file type
        if not file.content_type or not file.content_type.startswith('image/'):
            return resp_400(
                message="Only image files are supported",
                details={"content_type": file.content_type, "error_type": "invalid_file_type"}
            )
        
        # Check file size (limit to 10MB)
        file_size = 0
        file_content = await file.read()
        file_size = len(file_content)
        
        if file_size > 10 * 1024 * 1024:  # 10MB limit
            return resp_400(
                message="File size too large. Maximum size is 10MB",
                details={"file_size": file_size, "max_size": 10485760}
            )
        
        # Convert to base64
        image_base64 = base64.b64encode(file_content).decode('utf-8')
        
        # Determine image type from content type
        image_type = file.content_type.split('/')[-1]
        if image_type == 'jpeg':
            image_type = 'jpeg'
        elif image_type not in ['png', 'gif', 'webp']:
            image_type = 'jpeg'  # Default fallback
        
        # Get Mistral client
        client = get_mistral_client()
        
        # Prepare document for OCR
        document = {
            "type": "image_url",
            "image_url": f"data:image/{image_type};base64,{image_base64}"
        }
        
        # Process with Mistral OCR
        ocr_response = client.ocr.process(
            model="mistral-ocr-latest",
            document=document,
            include_image_base64=True
        )
        
        # Extract text from all pages
        extracted_text = ""
        pages_processed = []
        
        for i, page in enumerate(ocr_response.pages):
            page_text = page.markdown.strip()
            extracted_text += page_text + "\n"
            pages_processed.append({
                "page_number": i + 1,
                "text": page_text,
                "text_length": len(page_text)
            })
        
        processing_time = time.time() - start_time
        
        return resp_200(
            data={
                "extracted_text": extracted_text.strip(),
                "pages_processed": len(pages_processed),
                "page_details": pages_processed,
                "processing_time": round(processing_time, 2),
                "model_used": "mistral-ocr-latest",
                "input_type": "upload",
                "file_info": {
                    "filename": file.filename,
                    "content_type": file.content_type,
                    "size_bytes": file_size
                }
            },
            message="OCR processing completed successfully"
        )
        
    except HTTPException as he:
        # Re-raise HTTP exceptions (validation errors)
        raise he
    except Exception as e:
        processing_time = time.time() - start_time
        return resp_500(
            message="OCR upload processing failed",
            details={
                "error": str(e),
                "error_type": type(e).__name__,
                "processing_time": round(processing_time, 2),
                "filename": file.filename if file else None
            }
        )