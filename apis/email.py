"""
Email Analysis API for MAI Scam Detection System

This module provides endpoints for analyzing email content to detect potential scams
using AI-powered language detection, signal extraction, and risk assessment.

ENDPOINTS:
------
1. GET /email/ - Email API health check
2. POST /email/v1/analyze - Analyze email for scam detection (v1)
3. POST /email/v1/translate - Translate email analysis to different language (v1)
4. POST /email/v2/analyze - Analyze email for scam detection (v2 - SEA-LION v4)
"""

from fastapi import APIRouter, Request, HTTPException, UploadFile, File

from setting import Setting
import json
import base64
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

from models.customResponse import resp_200
from utils.emailUtils import detect_language, analyze_email, translate_analysis, extract_signals, analyze_email_comprehensive, analyze_email_comprehensive_v2
from utils.dbUtils import create_content_hash, save_analysis_to_db, retrieve_analysis_from_db, update_analysis_in_db, find_analysis_by_hash, prepare_email_document

config = Setting()

router = APIRouter(prefix="/email", tags=["Email Analysis"])

# =============================================================================
# 1. HEALTH CHECK ENDPOINT
# =============================================================================


class HealthResponse(BaseModel):
    status: str = Field(..., description="Health status")


@router.get("/", response_model=HealthResponse)
async def healthcheck():
    return {"status": "OK"}

@router.options("/")
async def options_healthcheck():
    """Handle OPTIONS requests for CORS preflight"""
    return {"status": "OK"}

@router.options("/v1/analyze")
async def options_analyze():
    """Handle OPTIONS requests for CORS preflight"""
    return {"status": "OK"}

# =============================================================================
# 2. EMAIL ANALYSIS ENDPOINT
# =============================================================================


class EmailAnalysis(BaseModel):
    risk_level: str = Field(..., description="Risk level: high, medium, low")
    reasons: str = Field(...,
                         description="Detailed explanation of risk assessment")
    recommended_action: str = Field(...,
                                    description="Recommended action to take")
    detected_language: str = Field(..., description="ISO-639-1 code of detected email language")


class EmailAnalysisRequest(BaseModel):
    subject: str = Field(..., description="Email subject line")
    content: str = Field(..., description="Email content/body")
    from_email: str = Field(..., description="Sender email address")
    target_language: str = Field(
        ..., description="Target language for analysis (en, zh, ms, th, vi)")
    reply_to_email: Optional[str] = Field(
        None, description="Reply-to email address")


class EmailAnalysisResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the request was successful")
    message: str = Field(..., description="Response message")
    data: EmailAnalysis = Field(
        ..., description="Analysis results including risk level, reasons, and recommended action")
    timestamp: str = Field(..., description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")


# V1 Analyze endpoint
analyze_v1_summary = "Analyze Email for Scam Detection (v1)"

analyze_v1_description = """
Analyze email content for potential scam indicators using AI.    
**Features:**
- Language detection (English, Chinese, Malay, Thai, Vietnamese)
- Signal extraction (URLs, domains, keywords, metadata)
- AI-powered risk assessment (High/Medium/Low)
- Content hashing for reusability

**Returns:**
- Risk level assessment
- Detailed analysis explanation
- Recommended actions
- Content reuse indicator
"""


@router.post("/v1/analyze",
             summary=analyze_v1_summary,
             description=analyze_v1_description,
             response_model=EmailAnalysisResponse,
             response_description="Email analysis results with risk assessment")
async def detect_v1(request: EmailAnalysisRequest):
    # [Step 0] Read values from the request body
    try:
        subject = request.subject
        content = request.content
        from_email = request.from_email
        target_language = request.target_language
        reply_to_email = request.reply_to_email

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid request body")

    # [Step 1] Extract auxiliary signals to support the analysis
    signals = extract_signals(title=subject, content=content,
                              from_email=from_email, reply_to_email=reply_to_email or "")

    # [Step 2] Perform comprehensive analysis with single LLM call
    # This combines: language detection + analysis + target language output
    comprehensive_analysis = await analyze_email_comprehensive(
        subject=subject,
        content=content, 
        from_email=from_email,
        reply_to_email=reply_to_email or "",
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
        "email", subject=subject, content=content, from_email=from_email)

    # [Step 4.5] Check if we already have analysis for this content
    existing_analysis = await find_analysis_by_hash(content_hash, "email")
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

    # [Step 5] Store title, content, emails, "base language", analysis in "base language" and analysis in "target language" in database
    document = prepare_email_document(
        subject, content, from_email, reply_to_email, base_language, analysis, signals)
    document['content_hash'] = content_hash  # Add hash to document

    # Save to database using centralized function
    email_id = await save_analysis_to_db(document, "email")

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
# 3. EMAIL TRANSLATION ENDPOINT
# =============================================================================


class EmailTranslationRequest(BaseModel):
    email_id: str = Field(..., description="Email analysis ID")
    target_language: str = Field(
        ..., description="Target language for translation (en, zh, ms, th, vi)")


class EmailTranslationResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the request was successful")
    message: str = Field(..., description="Response message")
    data: EmailAnalysis = Field(
        ..., description="Analysis results including risk level, reasons, and recommended action")
    timestamp: str = Field(..., description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")


# V1 Translate endpoint
translate_v1_summary = "Translate Email Analysis (v1)"

translate_v1_description = """
Translate email analysis results to different languages.

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
             response_model=EmailTranslationResponse,
             response_description="Translated email analysis results")
async def translate_v1(request: EmailTranslationRequest):
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
            "risk_level": target_language_analysis["risk_level"],
            "reasons": target_language_analysis["analysis"],  # Map 'analysis' to 'reasons'
            "recommended_action": target_language_analysis["recommended_action"]
        }
    )


# =============================================================================
# 4. EMAIL V2 ANALYSIS ENDPOINT (SEA-LION V4)
# =============================================================================

# V2 Analyze endpoint with SEA-LION v4
analyze_v2_summary = "Analyze Email for Scam Detection (v2 - SEA-LION v4)"

analyze_v2_description = """
Analyze email content for potential scam indicators using AI with upgraded SEA-LION v4 model.

**V2 Features:**
- Upgraded SEA-LION v4 model (aisingapore/Gemma-SEA-LION-v4-27B-IT)
- **No reasoning toggle** (removed in v4)
- Enhanced multilingual support
- Language detection (English, Chinese, Malay, Thai, Vietnamese)
- Signal extraction (URLs, domains, keywords, metadata)
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
             response_model=EmailAnalysisResponse,
             response_description="Email analysis results with risk assessment using SEA-LION v4")
async def analyze_email_v2(request: EmailAnalysisRequest):
    """
    V2 Email analysis endpoint using SEA-LION v4 model.
    
    This endpoint uses the upgraded SEA-LION v4 model without reasoning toggle
    functionality for improved email scam detection.
    """
    # [Step 0] Read values from the request body
    try:
        subject = request.subject
        content = request.content
        from_email = request.from_email
        target_language = request.target_language
        reply_to_email = request.reply_to_email

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid request body")

    # [Step 1] Extract auxiliary signals to support the analysis
    signals = extract_signals(title=subject, content=content,
                              from_email=from_email, reply_to_email=reply_to_email or "")

    # [Step 2] Perform comprehensive analysis with single SEA-LION v4 LLM call
    # This combines: language detection + analysis + target language output
    comprehensive_analysis = await analyze_email_comprehensive_v2(
        subject=subject,
        content=content, 
        from_email=from_email,
        reply_to_email=reply_to_email or "",
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
        "email", subject=subject, content=content, from_email=from_email)

    # [Step 4.5] Check if we already have analysis for this content
    existing_analysis = await find_analysis_by_hash(content_hash, "email")
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

    # [Step 5] Store title, content, emails, "base language", analysis in "base language" and analysis in "target language" in database
    document = prepare_email_document(
        subject, content, from_email, reply_to_email, base_language, analysis, signals)
    document['content_hash'] = content_hash  # Add hash to document

    # Save to database using centralized function
    email_id = await save_analysis_to_db(document, "email")

    # [Step 5] Respond analysis in "target language" to user  
    return resp_200(
        data={
            "risk_level": comprehensive_analysis["risk_level"],
            "reasons": comprehensive_analysis["analysis"],  # Map 'analysis' to 'reasons'
            "recommended_action": comprehensive_analysis["recommended_action"],
            "detected_language": comprehensive_analysis["detected_language"]
        }
    )

