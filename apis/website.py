"""
Website Analysis API for MAI Scam Detection System

This module provides endpoints for analyzing website content to detect potential scams
using AI-powered URL analysis, content evaluation, and security assessment.

ENDPOINTS:
------
1. GET /website/ - Website API health check
2. POST /website/v1/analyze - Analyze website for scam detection (v1)
3. POST /website/v1/translate - Translate website analysis to different language (v1)
4. POST /website/v2/analyze - Analyze website for scam detection (v2 - SEA-LION v4)
"""

from fastapi import APIRouter, Request, HTTPException, UploadFile, File

from setting import Setting
import json
import base64
from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any

from models.customResponse import resp_200
from utils.websiteUtils import detect_language, analyze_website_content, translate_analysis, extract_website_signals, analyze_website_comprehensive, analyze_website_comprehensive_v2
from utils.dbUtils import create_content_hash, save_analysis_to_db, retrieve_analysis_from_db, update_analysis_in_db, find_analysis_by_hash, prepare_website_document

config = Setting()

router = APIRouter(prefix="/website", tags=["Website Analysis"])

# =============================================================================
# 1. HEALTH CHECK ENDPOINT
# =============================================================================


class HealthResponse(BaseModel):
    status: str = Field(..., description="Health status")


@router.get("/", response_model=HealthResponse)
async def healthcheck():
    return {"status": "OK"}

# =============================================================================
# 2. WEBSITE ANALYSIS ENDPOINT
# =============================================================================


class WebsiteAnalysis(BaseModel):
    risk_level: str = Field(..., description="Risk level: high, medium, low")
    reasons: str = Field(...,
                         description="Detailed explanation of risk assessment")
    recommended_action: str = Field(...,
                                    description="Recommended action to take")
    detected_language: str = Field(..., description="ISO-639-1 code of detected website language")


class WebsiteAnalysisRequest(BaseModel):
    url: str = Field(..., description="Website URL to analyze")
    title: Optional[str] = Field(None, description="Website title")
    content: Optional[str] = Field(None, description="Website content/text")
    target_language: str = Field(
        ..., description="Target language for analysis (en, zh, ms, th, vi)")
    screenshot_data: Optional[str] = Field(
        None, description="Base64 encoded screenshot")
    metadata: Optional[Dict[str, Any]] = Field(
        None, description="SSL info, domain age, etc.")


class WebsiteAnalysisV2Request(BaseModel):
    url: str = Field(..., description="Website URL to analyze")
    title: Optional[str] = Field(None, description="Website title")
    content: Optional[str] = Field(None, description="Website content/text")
    target_language: str = Field(
        ..., description="Target language for analysis (en, zh, ms, th, vi)")
    metadata: Optional[Dict[str, Any]] = Field(
        None, description="SSL info, domain age, etc.")


class WebsiteAnalysisResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the request was successful")
    message: str = Field(..., description="Response message")
    data: WebsiteAnalysis = Field(
        ..., description="Analysis results including risk level, reasons, and recommended action")
    timestamp: str = Field(..., description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")


# V1 Analyze endpoint
analyze_v1_summary = "Analyze Website for Scam Detection (v1)"

analyze_v1_description = """
Analyze website content for potential scam indicators using AI.

**Features:**
- URL and domain analysis
- Content text analysis
- Screenshot analysis (if provided)
- SSL and security metadata
- AI-powered risk assessment

**Input Options:**
- URL only (basic analysis)
- URL + title + content (enhanced analysis)
- URL + screenshot (visual analysis)
- Full metadata (comprehensive analysis)

**Returns:**
- Risk level assessment
- Detailed analysis explanation
- Recommended actions
- Content reuse indicator
"""


@router.post("/v1/analyze",
             summary=analyze_v1_summary,
             description=analyze_v1_description,
             response_model=WebsiteAnalysisResponse,
             response_description="Website analysis results with risk assessment")
async def analyze_website_v1(request: WebsiteAnalysisRequest):
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

    # [Step 1] Extract auxiliary signals to support the analysis
    signals = extract_website_signals(
        url=url,
        title=title,
        content=content,
        screenshot_data=screenshot_data,
        metadata=metadata
    )

    # [Step 2] Perform comprehensive analysis with single LLM call
    # This combines: language detection + analysis + target language output
    comprehensive_analysis = await analyze_website_comprehensive(
        url=url,
        title=title or "",
        content=content or "",
        target_language=target_language,
        signals=signals
    )
    
    # Extract detected language and prepare analysis structure for database
    base_language = comprehensive_analysis["detected_language"]
    analysis = {
        target_language: {
            "risk_level": comprehensive_analysis["risk_level"],
            "analysis": comprehensive_analysis["analysis"], 
            "recommended_action": comprehensive_analysis["recommended_action"]
        }
    }

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
            "risk_level": comprehensive_analysis["risk_level"],
            "reasons": comprehensive_analysis["analysis"],  # Map 'analysis' to 'reasons'
            "recommended_action": comprehensive_analysis["recommended_action"],
            "detected_language": comprehensive_analysis["detected_language"]
        }
    )

# =============================================================================
# 3. WEBSITE TRANSLATION ENDPOINT
# =============================================================================


class WebsiteTranslationRequest(BaseModel):
    website_id: str = Field(..., description="Website analysis ID")
    target_language: str = Field(
        ..., description="Target language for translation (en, zh, ms, th, vi)")


class WebsiteTranslationResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the request was successful")
    message: str = Field(..., description="Response message")
    data: WebsiteAnalysis = Field(
        ..., description="Analysis results including risk level, reasons, and recommended action")
    timestamp: str = Field(..., description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")


# V1 Translate endpoint
translate_v1_summary = "Translate Website Analysis (v1)"

translate_v1_description = """
Translate website analysis results to different languages.

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
             response_model=WebsiteTranslationResponse,
             response_description="Translated website analysis results")
async def translate_website_analysis_v1(request: WebsiteTranslationRequest):
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


# =============================================================================
# 4. WEBSITE V2 ANALYSIS ENDPOINT (SEA-LION V4)
# =============================================================================

# V2 Analyze endpoint with SEA-LION v4
analyze_v2_summary = "Analyze Website for Scam Detection (v2 - SEA-LION v4)"

analyze_v2_description = """
Analyze website content for potential scam indicators using AI with upgraded SEA-LION v4 model.

**V2 Features:**
- Upgraded SEA-LION v4 model (aisingapore/Gemma-SEA-LION-v4-27B-IT)
- **No reasoning toggle** (removed in v4)
- Enhanced multilingual support
- Language detection (English, Chinese, Malay, Thai, Vietnamese)
- URL and domain analysis
- Content and metadata evaluation
- AI-powered risk assessment (High/Medium/Low)
- Content hashing for reusability

**Returns:**
- Risk level assessment
- Detailed analysis explanation
- Recommended actions
- Content reuse indicator
"""


@router.post("/v2/analyze",
             summary=analyze_v2_summary,
             description=analyze_v2_description,
             response_model=WebsiteAnalysisResponse,
             response_description="Website analysis results with risk assessment using SEA-LION v4")
async def analyze_website_v2(request: WebsiteAnalysisV2Request):
    """
    V2 Website analysis endpoint using SEA-LION v4 model.
    
    This endpoint uses the upgraded SEA-LION v4 model without reasoning toggle
    functionality for improved website scam detection.
    """
    # [Step 0] Read values from the request body
    try:
        url = request.url
        title = request.title
        content = request.content
        target_language = request.target_language
        screenshot_data = None  # V2 doesn't use screenshot data
        metadata = request.metadata

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid request body")

    # [Step 1] Extract auxiliary signals to support the analysis
    signals = extract_website_signals(
        url=url,
        title=title or "",
        content=content or "",
        screenshot_data="",  # V2 doesn't use screenshot data
        metadata=metadata
    )

    # [Step 2] Perform comprehensive analysis with single SEA-LION v4 LLM call
    # This combines: language detection + analysis + target language output
    comprehensive_analysis = await analyze_website_comprehensive_v2(
        url=url,
        title=title or "",
        content=content or "",
        target_language=target_language,
        signals=signals
    )
    
    # Extract detected language and prepare analysis structure for database
    base_language = comprehensive_analysis["detected_language"]
    analysis = {
        target_language: {
            "risk_level": comprehensive_analysis["risk_level"],
            "analysis": comprehensive_analysis["analysis"], 
            "recommended_action": comprehensive_analysis["recommended_action"]
        }
    }

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
            target_analysis = existing_analysis_data[target_language]
            return resp_200(
                data={
                    "risk_level": target_analysis["risk_level"],
                    "reasons": target_analysis["analysis"],  # Map 'analysis' to 'reasons'
                    "recommended_action": target_analysis["recommended_action"]
                }
            )

    # [Step 5] Store URL, title, content, "base language", analysis in "base language" and analysis in "target language" in database
    document = prepare_website_document(
        url, title, content, "", metadata, base_language, analysis, signals)
    document['content_hash'] = content_hash  # Add hash to document

    # Save to database using centralized function
    website_id = await save_analysis_to_db(document, "website")

    # [Step 5] Respond analysis in "target language" to user  
    return resp_200(
        data={
            "risk_level": comprehensive_analysis["risk_level"],
            "reasons": comprehensive_analysis["analysis"],  # Map 'analysis' to 'reasons'
            "recommended_action": comprehensive_analysis["recommended_action"],
            "detected_language": comprehensive_analysis["detected_language"]
        }
    )
