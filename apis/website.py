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
from utils.dynamodbUtils import save_detection_result, find_result_by_hash
import hashlib
from utils.checkerUtils import check_url_phishing, check_email_validity, check_phone_number_validity, extract_urls_from_text, extract_emails_from_text, extract_phone_numbers_from_text, check_all_content, format_checker_results_for_llm

config = Setting()

router = APIRouter(prefix="/website", tags=["Website Analysis"])

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_website_content_hash(url: str, title: str = "", content: str = "") -> str:
    """Create unique hash for website content to enable deduplication."""
    # Normalize text for consistent hashing
    def normalize_text(text):
        if not text:
            return ""
        return text.strip().lower()
    
    def normalize_url(url):
        if not url:
            return ""
        # Remove query parameters and fragments for consistency
        from urllib.parse import urlparse
        parsed = urlparse(url.lower())
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')
    
    url_norm = normalize_url(url)
    title_norm = normalize_text(title)
    content_norm = normalize_text(content)
    
    hash_input = f"website:{url_norm}|{title_norm}|{content_norm}"
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
    legitimate_url: Optional[str] = Field(None, description="Official website URL if brand impersonation detected")


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

    # [Step 1.5] Check URLs, emails, and phone numbers in the website content
    full_content = f"{url} {title or ''} {content or ''}"
    checker_results = check_all_content(full_content)
    
    # [Step 1.6] Check additional phone numbers found by website signal extraction
    website_phones = signals.get('artifacts', {}).get('phone_numbers', [])
    if website_phones:
        # Validate any phone numbers found by website extraction that weren't caught by checker utils
        from utils.checkerUtils import check_phone_number_validity
        additional_phone_results = []
        for phone in website_phones:
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
    document['checker_results'] = checker_results  # Add checker results to document

    # Save to database using centralized function
    website_id = await save_analysis_to_db(document, "website")

    # [Step 5] Respond analysis in "target language" to user
    return resp_200(
        data={
            "risk_level": comprehensive_analysis["risk_level"],
            "reasons": comprehensive_analysis["analysis"],  # Map 'analysis' to 'reasons'
            "recommended_action": comprehensive_analysis["recommended_action"],
            "detected_language": comprehensive_analysis["detected_language"],
            "legitimate_url": comprehensive_analysis.get("legitimate_url")
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

    # [Step 1.5] Check URLs, emails, and phone numbers in the website content
    full_content = f"{url} {title or ''} {content or ''}"
    checker_results = check_all_content(full_content)
    
    # [Step 1.6] Check additional phone numbers found by website signal extraction
    website_phones = signals.get('artifacts', {}).get('phone_numbers', [])
    if website_phones:
        # Validate any phone numbers found by website extraction that weren't caught by checker utils
        from utils.checkerUtils import check_phone_number_validity
        additional_phone_results = []
        for phone in website_phones:
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
    content_hash = create_website_content_hash(url, title, content)

    # [Step 4.5] Check if we already have analysis for this content
    existing_analysis = await find_result_by_hash(content_hash)
    if existing_analysis and existing_analysis.get('content_type') == 'website':
        # Return existing analysis if available and matches target language
        existing_result = existing_analysis.get('analysis_result', {})
        if existing_result:
            print(f"Returning cached website result for content hash: {content_hash}")
            return resp_200(
                data={
                    "risk_level": existing_result.get("risk_level"),
                    "reasons": existing_result.get("analysis"),  # Map 'analysis' to 'reasons'
                    "recommended_action": existing_result.get("recommended_action"),
                    "detected_language": existing_result.get("detected_language"),
                    "legitimate_url": existing_result.get("legitimate_url")
                }
            )

    # [Step 5] Prepare extracted data for DynamoDB storage
    extracted_data = {
        "url": url,
        "title": title or "",
        "content": content or "",
        "metadata": metadata or {},
        "signals": signals or {},
        "checker_results": checker_results or {}
    }

    # [Step 6] Save detection result to DynamoDB (extracted data + LLM analysis)
    print(f"Attempting to save website analysis to DynamoDB for content hash: {content_hash}")
    detection_id = await save_detection_result(
        content_type="website",
        content_hash=content_hash,
        analysis_result=comprehensive_analysis,
        extracted_data=extracted_data,
        target_language=target_language
    )
    
    # [Step 6.1] Verify save was successful before returning response
    if not detection_id or detection_id.startswith('temp_'):
        print(f"❌ CRITICAL: Failed to save website analysis to DynamoDB! Got ID: {detection_id}")
        print(f"Content hash: {content_hash}")
        print(f"URL: {url}")
        # For now, continue with response (graceful degradation)
        # In production, you might want to raise an exception here
    else:
        print(f"✅ SUCCESS: Saved website analysis to DynamoDB with ID: {detection_id}")

    # [Step 7] Respond analysis in "target language" to user  
    return resp_200(
        data={
            "risk_level": comprehensive_analysis["risk_level"],
            "reasons": comprehensive_analysis["analysis"],  # Map 'analysis' to 'reasons'
            "recommended_action": comprehensive_analysis["recommended_action"],
            "detected_language": comprehensive_analysis["detected_language"],
            "legitimate_url": comprehensive_analysis.get("legitimate_url")
        }
    )
