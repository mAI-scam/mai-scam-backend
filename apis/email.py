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
from utils.dynamodbUtils import save_detection_result, find_result_by_hash
import hashlib
from utils.checkerUtils import check_url_phishing, check_email_validity, check_phone_number_validity, extract_urls_from_text, extract_emails_from_text, extract_phone_numbers_from_text, check_all_content, format_checker_results_for_llm

config = Setting()

router = APIRouter(prefix="/email", tags=["Email Analysis"])

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_email_content_hash(subject: str, content: str, from_email: str) -> str:
    """Create unique hash for email content to enable deduplication."""
    # Normalize text for consistent hashing
    def normalize_text(text):
        if not text:
            return ""
        return text.strip().lower()
    
    subject_norm = normalize_text(subject)
    content_norm = normalize_text(content)
    from_email_norm = normalize_text(from_email)
    
    hash_input = f"email:{subject_norm}|{content_norm}|{from_email_norm}"
    hash_object = hashlib.sha256(hash_input.encode('utf-8'))
    return hash_object.hexdigest()[:16]

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
    
    # [Step 1.5] Check URLs, emails, and phone numbers in the content
    full_content = f"{subject} {content}"
    checker_results = check_all_content(full_content, from_email, reply_to_email or "")
    
    # [Step 1.6] Check additional phone numbers found by email signal extraction
    email_phones = signals.get('artifacts', {}).get('phone_numbers', [])
    if email_phones:
        # Validate any phone numbers found by email extraction that weren't caught by checker utils
        from utils.checkerUtils import check_phone_number_validity
        additional_phone_results = []
        for phone in email_phones:
            # Clean phone number (remove formatting)
            clean_phone = phone.strip().replace('(', '').replace(')', '').replace('-', '').replace(' ', '')
            if clean_phone not in [p['phone'] for p in checker_results.get('validation', {}).get('phone_numbers', {}).get('results', [])]:
                result = check_phone_number_validity(clean_phone)
                additional_phone_results.append(result)
        
        # Merge additional phone results with checker results
        if additional_phone_results:
            if 'validation' not in checker_results:
                checker_results['validation'] = {}
            if 'phone_numbers' not in checker_results['validation']:
                checker_results['validation']['phone_numbers'] = {'total_phones': 0, 'valid_phones': 0, 'invalid_phones': 0, 'results': []}
            
            # Update phone validation results
            phone_validation = checker_results['validation']['phone_numbers']
            phone_validation['results'].extend(additional_phone_results)
            phone_validation['total_phones'] = len(phone_validation['results'])
            
            # Recount valid/invalid phones
            valid_count = sum(1 for r in phone_validation['results'] if r.get('is_valid') is True)
            invalid_count = sum(1 for r in phone_validation['results'] if r.get('is_valid') is False)
            phone_validation['valid_phones'] = valid_count
            phone_validation['invalid_phones'] = invalid_count
    
    # [Step 1.7] Format checker analysis for LLM
    checker_analysis = format_checker_results_for_llm(checker_results)
    
    # Add checker results to signals for LLM analysis
    if checker_analysis:
        signals['checker_analysis'] = checker_analysis

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
    content_hash = create_email_content_hash(subject, content, from_email)

    # [Step 4.5] Check if we already have analysis for this content
    existing_analysis = await find_result_by_hash(content_hash)
    if existing_analysis and existing_analysis.get('content_type') == 'email':
        # Return existing analysis if available and matches target language
        existing_result = existing_analysis.get('analysis_result', {})
        if existing_result:
            return resp_200(
                data={
                    "risk_level": existing_result.get("risk_level"),
                    "reasons": existing_result.get("analysis"),  # Map 'analysis' to 'reasons'
                    "recommended_action": existing_result.get("recommended_action"),
                    "detected_language": existing_result.get("detected_language")
                }
            )

    # [Step 5] Save detection result to DynamoDB (only LLM analysis, no email content)
    detection_id = await save_detection_result(
        content_type="email",
        content_hash=content_hash,
        analysis_result=comprehensive_analysis,
        target_language=target_language
    )

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


# Translation endpoint temporarily disabled during DynamoDB migration
# @router.post("/v1/translate",
#              summary=translate_v1_summary, 
#              description=translate_v1_description,
#              response_model=EmailTranslationResponse,
#              response_description="Translated email analysis results")
# async def translate_v1(request: EmailTranslationRequest):
#     # [Step 0] Read values from the request body
#     try:
#         email_id = request.email_id
#         target_language = request.target_language
# 
#     except Exception as e:
#         raise HTTPException(status_code=400, detail="Invalid request body")
# 
#     # [Step 1] Get base_language_analysis from database
#     document = await retrieve_analysis_from_db(email_id, "email")
#     if not document:
#         raise HTTPException(
#             status_code=404, detail="Email analysis not found in database")
# 
#     base_language = document.get('base_language')
#     base_language_analysis = document.get('analysis').get(base_language)
# 
#     # [Step 2] Perform translation
#     target_language_analysis = await translate_analysis(base_language_analysis, base_language, target_language)
# 
#     # [Step 3] Store target_language_analysis into database
#     await update_analysis_in_db(email_id, target_language, target_language_analysis, "email")
# 
#     # [Step 4] Respond analysis in "target language" to user
#     return resp_200(
#         data={
#             "risk_level": target_language_analysis["risk_level"],
#             "reasons": target_language_analysis["analysis"],  # Map 'analysis' to 'reasons'
#             "recommended_action": target_language_analysis["recommended_action"]
#         }
#     )


# =============================================================================
# 4. CHECKER ENDPOINTS
# =============================================================================

class URLCheckRequest(BaseModel):
    url: str = Field(..., description="URL to check for phishing")

class URLCheckResponse(BaseModel):
    success: bool = Field(..., description="Whether the request was successful")
    message: str = Field(..., description="Response message")
    data: Dict = Field(..., description="URL check results")
    timestamp: str = Field(..., description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")

@router.post("/check-url",
             summary="Check URL for Phishing",
             description="Check if a URL is a phishing site using PhishTank database",
             response_model=URLCheckResponse)
async def check_url(request: URLCheckRequest):
    try:
        result = check_url_phishing(request.url)
        return resp_200(data=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class EmailCheckRequest(BaseModel):
    email: str = Field(..., description="Email address to validate")

class EmailCheckResponse(BaseModel):
    success: bool = Field(..., description="Whether the request was successful")
    message: str = Field(..., description="Response message")
    data: Dict = Field(..., description="Email validation results")
    timestamp: str = Field(..., description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")

@router.post("/check-email",
             summary="Validate Email Address",
             description="Validate email address using external validation service",
             response_model=EmailCheckResponse)
async def check_email(request: EmailCheckRequest):
    try:
        result = check_email_validity(request.email)
        return resp_200(data=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class PhoneCheckRequest(BaseModel):
    phone: str = Field(..., description="Phone number to validate")

class PhoneCheckResponse(BaseModel):
    success: bool = Field(..., description="Whether the request was successful")
    message: str = Field(..., description="Response message")
    data: Dict = Field(..., description="Phone validation results")
    timestamp: str = Field(..., description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")

@router.post("/check-phone",
             summary="Validate Phone Number",
             description="Validate phone number using external validation service",
             response_model=PhoneCheckResponse)
async def check_phone(request: PhoneCheckRequest):
    try:
        result = check_phone_number_validity(request.phone)
        return resp_200(data=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# 5. EMAIL V2 ANALYSIS ENDPOINT (SEA-LION V4)
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
    
    # [Step 1.5] Check URLs, emails, and phone numbers in the content
    full_content = f"{subject} {content}"
    checker_results = check_all_content(full_content, from_email, reply_to_email or "")
    
    # [Step 1.6] Check additional phone numbers found by email signal extraction
    email_phones = signals.get('artifacts', {}).get('phone_numbers', [])
    if email_phones:
        # Validate any phone numbers found by email extraction that weren't caught by checker utils
        from utils.checkerUtils import check_phone_number_validity
        additional_phone_results = []
        for phone in email_phones:
            # Clean phone number (remove formatting)
            clean_phone = phone.strip().replace('(', '').replace(')', '').replace('-', '').replace(' ', '')
            if clean_phone not in [p['phone'] for p in checker_results.get('validation', {}).get('phone_numbers', {}).get('results', [])]:
                result = check_phone_number_validity(clean_phone)
                additional_phone_results.append(result)
        
        # Merge additional phone results with checker results
        if additional_phone_results:
            if 'validation' not in checker_results:
                checker_results['validation'] = {}
            if 'phone_numbers' not in checker_results['validation']:
                checker_results['validation']['phone_numbers'] = {'total_phones': 0, 'valid_phones': 0, 'invalid_phones': 0, 'results': []}
            
            # Update phone validation results
            phone_validation = checker_results['validation']['phone_numbers']
            phone_validation['results'].extend(additional_phone_results)
            phone_validation['total_phones'] = len(phone_validation['results'])
            
            # Recount valid/invalid phones
            valid_count = sum(1 for r in phone_validation['results'] if r.get('is_valid') is True)
            invalid_count = sum(1 for r in phone_validation['results'] if r.get('is_valid') is False)
            phone_validation['valid_phones'] = valid_count
            phone_validation['invalid_phones'] = invalid_count
    
    # [Step 1.7] Format checker analysis for LLM
    checker_analysis = format_checker_results_for_llm(checker_results)
    
    # Add checker results to signals for LLM analysis
    if checker_analysis:
        signals['checker_analysis'] = checker_analysis

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
    content_hash = create_email_content_hash(subject, content, from_email)

    # [Step 4.5] Check if we already have analysis for this content
    existing_analysis = await find_result_by_hash(content_hash)
    if existing_analysis and existing_analysis.get('content_type') == 'email':
        # Return existing analysis if available and matches target language
        existing_result = existing_analysis.get('analysis_result', {})
        if existing_result:
            print(f"Returning cached result for content hash: {content_hash}")
            return resp_200(
                data={
                    "risk_level": existing_result.get("risk_level"),
                    "reasons": existing_result.get("analysis"),  # Map 'analysis' to 'reasons'
                    "recommended_action": existing_result.get("recommended_action"),
                    "detected_language": existing_result.get("detected_language")
                }
            )

    # [Step 5] Save detection result to DynamoDB (only LLM analysis, no email content)
    print(f"Attempting to save email analysis to DynamoDB for content hash: {content_hash}")
    detection_id = await save_detection_result(
        content_type="email",
        content_hash=content_hash,
        analysis_result=comprehensive_analysis,
        target_language=target_language
    )
    
    # [Step 5.1] Verify save was successful before returning response
    if not detection_id or detection_id.startswith('temp_'):
        print(f"❌ CRITICAL: Failed to save email analysis to DynamoDB! Got ID: {detection_id}")
        print(f"Content hash: {content_hash}")
        print(f"Analysis result: {comprehensive_analysis}")
        # For now, continue with response (graceful degradation)
        # In production, you might want to raise an exception here
    else:
        print(f"✅ SUCCESS: Saved email analysis to DynamoDB with ID: {detection_id}")

    # [Step 6] Respond analysis in "target language" to user  
    return resp_200(
        data={
            "risk_level": comprehensive_analysis["risk_level"],
            "reasons": comprehensive_analysis["analysis"],  # Map 'analysis' to 'reasons'
            "recommended_action": comprehensive_analysis["recommended_action"],
            "detected_language": comprehensive_analysis["detected_language"]
        }
    )

