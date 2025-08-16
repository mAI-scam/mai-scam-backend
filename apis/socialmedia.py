from fastapi import APIRouter, Request, HTTPException, UploadFile, File

from setting import Setting
import json
import base64
from pydantic import BaseModel
from typing import Optional, Dict, List

from models.customResponse import resp_200
from utils.socialmediaUtils import detect_language, analyze_social_media_content, translate_analysis, extract_social_media_signals
from utils.dbUtils import create_content_hash, save_analysis_to_db, retrieve_analysis_from_db, update_analysis_in_db, find_analysis_by_hash, prepare_social_media_document

config = Setting()

router = APIRouter(prefix="/socialmedia", tags=["Social Media Analysis"])

# Request and Response models


class SocialMediaAnalysis(BaseModel):
    risk_level: str
    reasons: str
    recommended_action: str


class SocialMediaAnalysisRequest(BaseModel):
    platform: str  # e.g., "facebook", "instagram", "twitter", "tiktok"
    content: str
    author_username: str
    target_language: str
    post_url: Optional[str] = None
    author_followers_count: Optional[int] = None
    engagement_metrics: Optional[Dict] = None


class SocialMediaAnalysisResponse(BaseModel):
    post_id: str
    analysis: Dict[str, SocialMediaAnalysis]


class SocialMediaTranslationRequest(BaseModel):
    post_id: str
    target_language: str


class SocialMediaTranslationResponse(BaseModel):
    post_id: str
    risk_level: str
    analysis: str
    recommended_action: str
    analysis_language: str

# Routes

# 0. Healthcheck


@router.get("/")
async def healthcheck():
    return {"status": "OK"}

# 1. Analyze social media content


@router.post("/analyze",
             summary="Analyze Social Media Post for Scam Detection",
             description="""
    Analyze social media content for potential scam indicators using AI.
    
    **Supported Platforms:**
    - Facebook
    - Instagram
    - Twitter/X
    - TikTok
    - LinkedIn
    
    **Features:**
    - Platform-specific scam detection
    - Engagement metrics analysis
    - URL and domain analysis
    - Author credibility assessment
    - AI-powered risk assessment
    
    **Returns:**
    - Risk level assessment
    - Platform-specific analysis
    - Recommended actions
    - Content reuse indicator
    """,
             response_description="Social media analysis results with risk assessment")
async def analyze_social_media_post(request: SocialMediaAnalysisRequest):
    # [Step 0] Read values from the request body
    try:
        platform = request.platform
        content = request.content
        author_username = request.author_username
        target_language = request.target_language
        post_url = request.post_url
        author_followers_count = request.author_followers_count
        engagement_metrics = request.engagement_metrics

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid request body")

    # [Step 1] Detect the base language of the social media content
    base_language = await detect_language(content)

    # [Step 1.5] Extract auxiliary signals to support the analysis
    signals = extract_social_media_signals(
        platform=platform,
        content=content,
        author_username=author_username,
        post_url=post_url,
        author_followers_count=author_followers_count,
        engagement_metrics=engagement_metrics
    )

    # [Step 2] Perform analysis in "base language"
    base_language_analysis = await analyze_social_media_content(
        platform, content, base_language, signals
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
    content_hash = create_content_hash("socialmedia",
                                       platform=platform,
                                       content=content,
                                       author_username=author_username,
                                       post_url=post_url)

    # [Step 4.5] Check if we already have analysis for this content
    existing_analysis = await find_analysis_by_hash(content_hash, "socialmedia")
    if existing_analysis:
        # Return existing analysis if available
        existing_id = existing_analysis.get('_id')
        existing_analysis_data = existing_analysis.get('analysis', {})

        # If target language analysis exists, return it
        if target_language in existing_analysis_data:
            return resp_200(
                data={
                    "post_id": str(existing_id),
                    target_language: existing_analysis_data[target_language],
                    "reused": True
                }
            )

    # [Step 5] Store content and analysis in database
    document = prepare_social_media_document(
        platform, content, author_username, post_url,
        author_followers_count, engagement_metrics, base_language, analysis, signals
    )
    document['content_hash'] = content_hash  # Add hash to document

    # Save to database using centralized function
    post_id = await save_analysis_to_db(document, "socialmedia")

    # [Step 5] Respond analysis in "target language" to user
    return resp_200(
        data={
            "post_id": post_id,
            target_language: analysis[target_language],
            "reused": False
        }
    )

# 2. Translate analysis function


@router.post("/translate")
async def translate_social_media_analysis(request: SocialMediaTranslationRequest):
    # [Step 0] Read values from the request body
    try:
        post_id = request.post_id
        target_language = request.target_language

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid request body")

    # [Step 1] Get base_language_analysis from database
    document = await retrieve_analysis_from_db(post_id, "socialmedia")
    if not document:
        raise HTTPException(
            status_code=404, detail="Social media post analysis not found in database")

    base_language = document.get('base_language')
    base_language_analysis = document.get('analysis').get(base_language)

    # [Step 2] Perform translation
    target_language_analysis = await translate_analysis(
        base_language_analysis, base_language, target_language
    )

    # [Step 3] Store target_language_analysis into database
    await update_analysis_in_db(post_id, target_language, target_language_analysis, "socialmedia")

    # [Step 4] Respond analysis in "target language" to user
    return resp_200(
        data={
            "post_id": post_id,
            target_language: target_language_analysis
        }
    )
