from fastapi import APIRouter, Request, HTTPException, UploadFile, File

from setting import Setting
import json
import base64
from pydantic import BaseModel
from typing import Optional, Dict

from models.customResponse import resp_200
from utils.emailUtils import detect_language, analyze_email, translate_analysis, extract_signals
from utils.dbUtils import create_content_hash, save_analysis_to_db, retrieve_analysis_from_db, update_analysis_in_db, find_analysis_by_hash, prepare_email_document

config = Setting()

router = APIRouter(prefix="/email", tags=["Email Analysis"])

# Request and Response models


class EmailAnalysis(BaseModel):
    risk_level: str
    reasons: str
    recommended_action: str


class EmailAnalysisRequest(BaseModel):
    subject: str
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
async def detect(request: EmailAnalysisRequest):
    # [Step 0] Read values from the request body
    try:
        subject = request.subject
        content = request.content
        from_email = request.from_email
        target_language = request.target_language
        reply_to_email = request.reply_to_email

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid request body")

    # [Step 1] Detect the base language of the email content
    base_language = await detect_language(content)

    # [Step 1.5] Extract auxiliary signals to support the agent
    signals = extract_signals(title=subject, content=content,
                              from_email=from_email, reply_to_email=reply_to_email or "")

    # [Step 2] Perform analysis in "base language"
    base_language_analysis = await analyze_email(subject, content, base_language, signals)
    analysis = {
        base_language: base_language_analysis
    }

    # [Step 3] If "target language" is not the "base language"
    if base_language != target_language:
        target_language_analysis = await translate_analysis(base_language_analysis, base_language, target_language)
        analysis[target_language] = target_language_analysis

    # [Step 4] Create unique content hash for reusability
    content_hash = create_content_hash(
        "email", subject=subject, content=content, from_email=from_email)

    # [Step 4.5] Check if we already have analysis for this content
    existing_analysis = await find_analysis_by_hash(content_hash, "email")
    if existing_analysis:
        # Return existing analysis if available
        existing_id = existing_analysis.get('_id')
        existing_analysis_data = existing_analysis.get('analysis', {})

        # If target language analysis exists, return it
        if target_language in existing_analysis_data:
            return resp_200(
                data={
                    "email_id": str(existing_id),
                    target_language: existing_analysis_data[target_language],
                    "reused": True
                }
            )

    # [Step 5] Store title, content, emails, "base language", analysis in "base language" and analysis in "target language" in database
    document = prepare_email_document(
        subject, content, from_email, reply_to_email, base_language, analysis, signals)
    document['content_hash'] = content_hash  # Add hash to document

    # Save to database using centralized function
    email_id = await save_analysis_to_db(document, "email")

    # [Step 5] Respond analysis in "target language" to user
    return resp_200(
        data={
            "email_id": email_id,
            target_language: analysis[target_language],
            "reused": False
        }
    )


# 2. Translate function
# a. Retrieve email_id
# b. Map to database and retrieve analysis in base language
# c. Perform translation
@router.post("/translate")
async def translate(request: EmailTranslationRequest):
    # [Step 0] Read values from the request body
    try:
        email_id = request.email_id
        target_language = request.target_language

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid request body")

    # [Step 1] Get base_language_analysis from database
    document = await retrieve_analysis_from_db(email_id, "email")
    if not document:
        raise HTTPException(
            status_code=404, detail="Email analysis not found in database")

    base_language = document.get('base_language')
    base_language_analysis = document.get('analysis').get(base_language)

    # [Step 2] Perform translation
    target_language_analysis = await translate_analysis(base_language_analysis, base_language, target_language)

    # [Step 3] Store target_language_analysis into database
    await update_analysis_in_db(email_id, target_language, target_language_analysis, "email")

    # [Step 4] Respond analysis in "target language" to user
    return resp_200(
        data={
            "email_id": email_id,
            target_language: target_language_analysis
        }
    )
