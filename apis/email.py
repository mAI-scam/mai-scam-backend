from fastapi import APIRouter, Request, HTTPException, UploadFile, File
from models.customResponse import resp_200
from models.clients import get_sea_lion_client, get_mistral_client
from setting import Setting
import json
import base64
from pydantic import BaseModel
from typing import Optional, Dict

config = Setting()

router = APIRouter()

# Request and Response models


class EmailAnalysis(BaseModel):
    risk_level: str
    reasons: str
    recommended_action: str


class EmailDetectionRequest(BaseModel):
    title: str
    content: str
    from_email: str
    target_language: str
    reply_to_email: Optional[str] = None


class EmailDetectionResponse(BaseModel):
    email_id: str
    analysis: Dict[str, EmailAnalysis]


class EmailTranslationRequest(BaseModel):
    email_id: str
    target_language: str


class EmailTranslationResponse(BaseModel):
    email_id: str
    risk_level: str
    analysis: str
    recommended_action: str
    analysis_language: str


# Routes

# 0. Healthcheck
@router.get("/")
async def healthcheck():
    return {"status": "OK"}

# 1. Detect function
# a. Detect the base language of the email content
# b. Perform analysis in "base language" and "target language"
# c. Store title, content, emails, "base language", analysis in "base language" and analysis in "target language" in database
# d. Respond analysis in "target language" to user


@router.post("/detect")
def detect(request: EmailDetectionRequest) -> EmailDetectionResponse:
    # Read values from the request body
    title = request.title
    content = request.content
    from_email = request.from_email
    target_language = request.target_language
    reply_to_email = request.reply_to_email  # could be None if optional

    # a. Detect the base language of the email content
    base_language = "ms"

    # b. Perform analysis in "base language" and "target language"
    if base_language == target_language:
        base_language_analysis = {
            base_language: {
                "risk_level": "tinggi",
                "analysis": "spam",
                "recommended_action": "jangan buka"
            }
        }
    else:
        base_language_analysis = {
            base_language: {
                "risk_level": "tinggi",
                "analysis": "spam",
                "recommended_action": "jangan buka"
            }
        }

        target_language_analysis = {
            target_language: {
                "risk_level": "high",
                "analysis": "spam",
                "recommended_action": "do not open"
            }
        }

    # c. Store title, content, emails, "base language", analysis in "base language" and analysis in "target language" in database
    document = {
        "email_id": "uuid1234",
        "title": title,
        "content": content,
        "from_email": from_email,
        "base_language": base_language,
        "reply_to_email": reply_to_email,
        "analysis": [
            base_language_analysis,
            target_language_analysis
        ]
    }

    # d. Respond analysis in "target language" to user
    return resp_200(
        data={
            "email_id": "uuid1234",
            "analysis": target_language_analysis
        })


# 2. Translate function
# a. Retrieve email_id
# b. Map to database and retrieve analysis in base language
# c. Perform translation
@router.post("/translate")
def translate(request: EmailTranslationRequest) -> EmailTranslationResponse:

    return resp_200(
        data={
            "risk_level": "high",
            "analysis": "spam",
            "recommended_action": "block",
            "language": "en"
        })
