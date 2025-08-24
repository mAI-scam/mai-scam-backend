from fastapi import APIRouter, HTTPException, File, UploadFile
from pydantic import BaseModel
from utils.mistral import get_mistral_client
from utils.response import resp_200

router = APIRouter(prefix="/ocr", tags=["OCR"])


# =============================================================================
# REQUEST AND RESPONSE MODELS
# =============================================================================

class OCRRequest(BaseModel):
    image_url: Optional[str] = None
    image_base64: Optional[str] = None
    image_type: Optional[str] = "jpeg"  # jpeg, png, gif, webp


class OCRRequest(BaseModel):
    image_url: Optional[str] = None
    image_base64: Optional[str] = None
    image_type: Optional[str] = "jpeg"  # jpeg, png, gif, webp

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
# LEGACY ENDPOINTS (KEPT FOR BACKWARD COMPATIBILITY)
# =============================================================================


@router.post("/ocr", response_model=dict)
def ocr_process(request: OCRRequest):
    """
    Extract text from images using Mistral OCR.
    Supports both image URLs and base64 encoded images.
    """
    try:
        # Validate input - must have either image_url or image_base64
        if not request.image_url and not request.image_base64:
            raise HTTPException(
                status_code=400,
                detail="Either image_url or image_base64 must be provided"
            )

        if request.image_url and request.image_base64:
            raise HTTPException(
                status_code=400,
                detail="Provide either image_url or image_base64, not both"
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
        for page in ocr_response.pages:
            extracted_text += page.markdown + "\n"

        return resp_200(
            data={
                "extracted_text": extracted_text.strip()
            },
            message="OCR processing completed successfully"
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error during OCR processing: {str(e)}")


@router.post("/ocr-upload", response_model=dict)
async def ocr_upload(file: UploadFile = File(...)):
