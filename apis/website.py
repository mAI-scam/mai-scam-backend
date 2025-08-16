from fastapi import APIRouter, Request, HTTPException, UploadFile, File

from setting import Setting
import json
import base64
from pydantic import BaseModel
from typing import Optional, Dict, List

from models.customResponse import resp_200
from utils.websiteUtils import detect_language, analyze_website_content, translate_analysis, extract_website_signals
from utils.dbUtils import create_content_hash, save_analysis_to_db, retrieve_analysis_from_db, update_analysis_in_db, find_analysis_by_hash, prepare_website_document

config = Setting()

router = APIRouter(prefix="/website", tags=["Website Analysis"])

# Request and Response models


class WebsiteAnalysis(BaseModel):
    risk_level: str
    reasons: str
    recommended_action: str


class WebsiteAnalysisRequest(BaseModel):
    url: str
    title: Optional[str] = None
    content: Optional[str] = None
    target_language: str
    screenshot_data: Optional[str] = None  # base64 encoded screenshot
    metadata: Optional[Dict] = None  # SSL info, domain age, etc.


class WebsiteAnalysisResponse(BaseModel):
    website_id: str
    analysis: Dict[str, WebsiteAnalysis]


class WebsiteTranslationRequest(BaseModel):
    website_id: str
    target_language: str


class WebsiteTranslationResponse(BaseModel):
    website_id: str
    risk_level: str
    analysis: str
    recommended_action: str
    analysis_language: str

# Routes

# 0. Healthcheck


@router.get("/")
async def healthcheck():
    return {"status": "OK"}

# 1. Analyze website content


@router.post("/analyze")
async def analyze_website(request: WebsiteAnalysisRequest):
    # [Step 0] Read values from the request body
    try:
        url = request.url
        title = request.title
        content = request.content
        target_language = request.target_language
        screenshot_data = request.screenshot_data
        metadata = request.metadata

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid request body")

    # [Step 1] Detect the base language of the website content
    # Use title + content for language detection
    text_for_language_detection = f"{title or ''} {content or ''}".strip()
    if not text_for_language_detection:
        # Fallback to English if no content provided
        base_language = "en"
    else:
        base_language = await detect_language(text_for_language_detection)

    # [Step 1.5] Extract auxiliary signals to support the analysis
    signals = extract_website_signals(
        url=url,
        title=title,
        content=content,
        screenshot_data=screenshot_data,
        metadata=metadata
    )

    # [Step 2] Perform analysis in "base language"
    base_language_analysis = await analyze_website_content(
        url, title, content, base_language, signals
    )
    analysis = {
        base_language: base_language_analysis
    }

    # [Step 3] If "target language" is not the "base language"
    if base_language != target_language:
        target_language_analysis = await translate_analysis(
            base_language_analysis, base_language, target_language
        )
        analysis[target_language] = target_language_analysis

        # [Step 4] Create unique content hash for reusability
    content_hash = create_content_hash(
        "website", url=url, title=title, content=content)

    # [Step 4.5] Check if we already have analysis for this content
    existing_analysis = await find_analysis_by_hash(content_hash, "website")
    if existing_analysis:
        # Return existing analysis if available
        existing_id = existing_analysis.get('_id')
        existing_analysis_data = existing_analysis.get('analysis', {})

        # If target language analysis exists, return it
        if target_language in existing_analysis_data:
            return resp_200(
                data={
                    "website_id": str(existing_id),
                    target_language: existing_analysis_data[target_language],
                    "reused": True
                }
            )

    # [Step 5] Store website data and analysis in database
    document = prepare_website_document(
        url, title, content, screenshot_data, metadata, base_language, analysis, signals
    )
    document['content_hash'] = content_hash  # Add hash to document

    # Save to database using centralized function
    website_id = await save_analysis_to_db(document, "website")

    # [Step 5] Respond analysis in "target language" to user
    return resp_200(
        data={
            "website_id": website_id,
            target_language: analysis[target_language],
            "reused": False
        }
    )

# 2. Translate analysis function


@router.post("/translate")
async def translate_website_analysis(request: WebsiteTranslationRequest):
    # [Step 0] Read values from the request body
    try:
        website_id = request.website_id
        target_language = request.target_language

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid request body")

    # [Step 1] Get base_language_analysis from database
    document = await retrieve_analysis_from_db(website_id, "website")
    if not document:
        raise HTTPException(
            status_code=404, detail="Website analysis not found in database")

    base_language = document.get('base_language')
    base_language_analysis = document.get('analysis').get(base_language)

    # [Step 2] Perform translation
    target_language_analysis = await translate_analysis(
        base_language_analysis, base_language, target_language
    )

    # [Step 3] Store target_language_analysis into database
    await update_analysis_in_db(website_id, target_language, target_language_analysis, "website")

    # [Step 4] Respond analysis in "target language" to user
    return resp_200(
        data={
            "website_id": website_id,
            target_language: target_language_analysis
        }
    )
