from fastapi import APIRouter, Request, HTTPException, UploadFile, File

from setting import Setting
import json
import base64
from pydantic import BaseModel
from typing import Optional, Dict

from models.customResponse import resp_200
from utils.emailUtils import detect_language, analyze_email, translate_analysis, prepare_document, save_to_mongodb

config = Setting()

router = APIRouter()

# Request and Response models


class EmailAnalysis(BaseModel):
    risk_level: str
    reasons: str
    recommended_action: str


class EmailAnalysisRequest(BaseModel):
    title: str
    content: str
    from_email: str
    target_language: str
    reply_to_email: Optional[str] = None


class EmailAnalysisResponse(BaseModel):
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


@router.post("/analyze")
async def detect(request: EmailAnalysisRequest) -> EmailAnalysisResponse:
    # [Step 0] Read values from the request body
    try:
        title = request.title
        content = request.content
        from_email = request.from_email
        target_language = request.target_language
        reply_to_email = None

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid request body")

    # [Step 1] Detect the base language of the email content
    base_language = await detect_language(content)

    # [Step 2] Perform analysis in "base language"
    base_language_analysis = await analyze_email(title, content, base_language)
    analysis = {
        base_language: base_language_analysis
    }

    # [Step 3] If "target language" is not the "base language"
    if base_language != target_language:
        target_language_analysis = await translate_analysis(base_language_analysis, base_language, target_language)
        analysis[target_language] = target_language_analysis

    # [Step 4] Store title, content, emails, "base language", analysis in "base language" and analysis in "target language" in database
    document = prepare_document(
        title, content, from_email, reply_to_email, base_language, analysis)
    email_id = await save_to_mongodb(document)

    # [Step 5] Respond analysis in "target language" to user
    return resp_200(
        data={
            "email_id": email_id,
            target_language: analysis[target_language]
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
