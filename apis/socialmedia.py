"""
Social Media Analysis API for MAI Scam Detection System

This module provides endpoints for analyzing social media content to detect potential scams
using AI-powered platform-specific detection, engagement analysis, and risk assessment.

ENDPOINTS:
------
1. GET /socialmedia/ - Social Media API health check
2. POST /socialmedia/v1/analyze - Analyze social media post for scam detection (v1)
3. POST /socialmedia/v1/translate - Translate social media analysis to different language (v1)
"""

from fastapi import APIRouter, Request, HTTPException, UploadFile, File

from setting import Setting
import json
import base64
from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any

from models.customResponse import resp_200
from utils.socialmediaUtils import detect_language, analyze_social_media_content, translate_analysis, extract_social_media_signals
from utils.dbUtils import create_content_hash, save_analysis_to_db, retrieve_analysis_from_db, update_analysis_in_db, find_analysis_by_hash, prepare_social_media_document

config = Setting()

router = APIRouter(prefix="/socialmedia", tags=["Social Media Analysis"])

# =============================================================================
# 1. HEALTH CHECK ENDPOINT
# =============================================================================


class HealthResponse(BaseModel):
    status: str = Field(..., description="Health status")


@router.get("/", response_model=HealthResponse)
async def healthcheck():
    return {"status": "OK"}

# =============================================================================
# 2. SOCIAL MEDIA ANALYSIS ENDPOINT
# =============================================================================


class SocialMediaAnalysis(BaseModel):
    risk_level: str = Field(..., description="Risk level: high, medium, low")
    reasons: str = Field(...,
                         description="Detailed explanation of risk assessment")
    recommended_action: str = Field(...,
                                    description="Recommended action to take")


class SocialMediaAnalysisRequest(BaseModel):
    platform: str = Field(
        ..., description="Social media platform (facebook, instagram, twitter, tiktok, linkedin)")
    content: str = Field(..., description="Post content/text")
    author_username: str = Field(..., description="Author's username")
    target_language: str = Field(
        ..., description="Target language for analysis (en, zh, ms, th, vi)")
    post_url: Optional[str] = Field(None, description="URL of the post")
    author_followers_count: Optional[int] = Field(
        None, description="Number of followers")
    engagement_metrics: Optional[Dict[str, Any]] = Field(
        None, description="Engagement metrics (likes, shares, comments)")


class SocialMediaAnalysisResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the request was successful")
    message: str = Field(..., description="Response message")
    data: SocialMediaAnalysis = Field(
        ..., description="Analysis results including risk level, reasons, and recommended action")
    timestamp: str = Field(..., description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")


# V1 Analyze endpoint
analyze_v1_summary = "Analyze Social Media Post for Scam Detection (v1)"

analyze_v1_description = """
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
"""


@router.post("/v1/analyze",
             summary=analyze_v1_summary,
             description=analyze_v1_description,
             response_model=SocialMediaAnalysisResponse,
             response_description="Social media analysis results with risk assessment")
async def analyze_social_media_post_v1(request: SocialMediaAnalysisRequest):
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

# =============================================================================
# 3. SOCIAL MEDIA TRANSLATION ENDPOINT
# =============================================================================


class SocialMediaTranslationRequest(BaseModel):
    post_id: str = Field(..., description="Social media post analysis ID")
    target_language: str = Field(
        ..., description="Target language for translation (en, zh, ms, th, vi)")


class SocialMediaTranslationResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the request was successful")
    message: str = Field(..., description="Response message")
    data: SocialMediaAnalysis = Field(
        ..., description="Analysis results including risk level, reasons, and recommended action")
    timestamp: str = Field(..., description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")


# V1 Translate endpoint
translate_v1_summary = "Translate Social Media Analysis (v1)"

translate_v1_description = """
Translate social media analysis results to different languages.

**Features:**
- Multi-language translation support
- Preserves original analysis accuracy
- Maintains risk assessment integrity

**Supported Languages:**
- English (en)
- Chinese (zh)
- Malay (ms)
- Thai (th)
- Vietnamese (vi)
"""


@router.post("/v1/translate",
             summary=translate_v1_summary,
             description=translate_v1_description,
             response_model=SocialMediaTranslationResponse,
             response_description="Translated social media analysis results")
async def translate_social_media_analysis_v1(request: SocialMediaTranslationRequest):
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
