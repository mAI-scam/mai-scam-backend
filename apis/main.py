from fastapi import APIRouter, Request, HTTPException, UploadFile, File
from models.customResponse import resp_200
from models.clients import get_sea_lion_client, get_mistral_client
from setting import Setting
import json
import base64
from pydantic import BaseModel
from typing import Optional

config = Setting()

router = APIRouter()

# Request and Response models
class SpamDetectionRequest(BaseModel):
    message: str

class SpamDetectionResponse(BaseModel):
    classification: str
    warning_signs: str

class OCRRequest(BaseModel):
    image_url: Optional[str] = None
    image_base64: Optional[str] = None
    image_type: Optional[str] = "jpeg"  # jpeg, png, gif, webp

def encode_image_from_bytes(image_bytes):
    """Encode image bytes to base64."""
    try:
        return base64.b64encode(image_bytes).decode('utf-8')
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error encoding image: {e}")

@router.get("/")
def api_version(request: Request):
    environment = request.app.state.settings.get("APP_ENV")
    version = request.app.state.settings.get("APP_API_VERSION")

    return resp_200(data={"environment": environment, "version": version}, message="success")

@router.post("/detect-spam", response_model=dict)
def detect_spam(request: SpamDetectionRequest):
    """
    Detect if a message is spam using Sea-Lion AI model.
    Returns classification (spam/not spam) and warning signs explanation.
    """
    try:
        client = get_sea_lion_client()
        
        completion = client.chat.completions.create(
            model="aisingapore/Llama-SEA-LION-v3.5-8B-R",
            messages=[
                {
                    "role": "user",
                    "content": f"CRITICAL INSTRUCTION: You MUST respond in the EXACT SAME LANGUAGE as the input message. Do NOT use English if the input is in another language.\n\nAnalyze this message for spam/scams. Respond ONLY in valid JSON format with two fields:\n\n1. 'classification': either 'spam' or 'not spam'\n2. 'warning_signs': a SHORT, SIMPLE explanation written in the EXACT SAME LANGUAGE as the input message below. Use everyday words that anyone can understand. Keep it under 2 sentences.\n\nLANGUAGE MATCHING RULES:\n- If input is in Malay/Bahasa → Respond in Malay/Bahasa\n- If input is in Chinese → Respond in Chinese\n- If input is in Thai → Respond in Thai  \n- If input is in Vietnamese → Respond in Vietnamese\n- If input is in English → Respond in English\n- NEVER default to English unless the input message is in English\n\nFor spam messages, use a PROTECTIVE WARNING tone with brief explanation:\n- \"STOP! This is a fake prize/money offer. Do NOT click any links or reply.\"\n- \"WARNING! This message asks for your personal details to steal your information. Do NOT share anything.\"\n- \"DANGER! This is trying to rush you into clicking suspicious links. Delete it immediately.\"\n- \"SCAM ALERT! This asks you to send money or personal information. Do NOT respond.\"\n\nFor safe messages, reassure them it's okay:\n- \"This looks like a normal notification from a real service.\"\n- \"This appears to be a genuine conversation with someone you know.\"\n- \"This message seems safe and legitimate.\"\n\nMessage to analyze: {request.message}\n\nREMEMBER: Your 'warning_signs' explanation MUST be in the same language as the message above. Do NOT use English unless the message is in English.\n\nResponse format:\n{{\n  \"classification\": \"spam\" or \"not spam\",\n  \"warning_signs\": \"short simple explanation matching the input message language\"\n}}"
                }
            ],
            extra_body={
                "chat_template_kwargs": {
                    "thinking_mode": "on"
                }, 
                "cache": {
                    "no-cache": True
                }
            },
        )
        
        # Parse the JSON response
        response_content = completion.choices[0].message.content.strip()
        
        # Extract JSON from response (handle cases where AI includes reasoning text)
        json_content = response_content
        
        # Look for JSON block markers
        if "```json" in response_content:
            # Extract content between ```json and ```
            start_idx = response_content.find("```json") + 7
            end_idx = response_content.find("```", start_idx)
            if end_idx != -1:
                json_content = response_content[start_idx:end_idx].strip()
        elif response_content.startswith("{") and response_content.endswith("}"):
            # Response is already pure JSON
            json_content = response_content
        else:
            # Try to find JSON object in the response
            start_idx = response_content.find("{")
            end_idx = response_content.rfind("}")
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                json_content = response_content[start_idx:end_idx + 1]
        
        try:
            result = json.loads(json_content)
            
            # Validate the response structure
            if "classification" not in result or "warning_signs" not in result:
                raise ValueError("Invalid response structure from AI model")
            
            # Determine if it's spam
            is_spam = result["classification"].lower() == "spam"
            
            return resp_200(
                data={
                    "message": request.message,
                    "is_spam": is_spam,
                    "explanation": result["warning_signs"]
                },
                message="Spam detection completed successfully"
            )
            
        except json.JSONDecodeError:
            # If JSON parsing fails, return error with raw response for debugging
            raise HTTPException(
                status_code=500, 
                detail=f"Could not parse AI response as JSON. Raw response: {response_content}"
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during spam detection: {str(e)}")

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
        raise HTTPException(status_code=500, detail=f"Error during OCR processing: {str(e)}")

@router.post("/ocr-upload", response_model=dict)
async def ocr_upload(file: UploadFile = File(...)):
    """
    Extract text from uploaded image files using Mistral OCR.
    """
    try:
        # Validate file type
        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="File must be an image")
        
        # Read the uploaded file bytes
        image_bytes = await file.read()
        
        # Convert to base64
        base64_image = encode_image_from_bytes(image_bytes)
        
        # Determine image type from content type
        image_type = "jpeg"  # default
        if file.content_type:
            if "png" in file.content_type:
                image_type = "png"
            elif "gif" in file.content_type:
                image_type = "gif"
            elif "webp" in file.content_type:
                image_type = "webp"
        
        client = get_mistral_client()
        
        # Process with Mistral OCR
        ocr_response = client.ocr.process(
            model="mistral-ocr-latest",
            document={
                "type": "image_url",
                "image_url": f"data:image/{image_type};base64,{base64_image}"
            },
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
        raise HTTPException(status_code=500, detail=f"Error during OCR upload processing: {str(e)}")
