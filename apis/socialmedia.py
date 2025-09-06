"""
Social Media Analysis API for MAI Scam Detection System

This module provides endpoints for analyzing social media content to detect potential scams
using AI-powered platform-specific detection, engagement analysis, and risk assessment.

ENDPOINTS:
------
1. GET /socialmedia/ - Social Media API health check
2. POST /socialmedia/v1/analyze - Analyze social media post for scam detection (v1)
3. POST /socialmedia/v1/translate - Translate social media analysis to different language (v1)
4. POST /socialmedia/v2/analyze - Analyze social media post with multimodal support (v2)
"""

from fastapi import APIRouter, Request, HTTPException, UploadFile, File

from setting import Setting
import json
import base64
from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any

from models.customResponse import resp_200
from utils.socialmediaUtils import detect_language, analyze_social_media_content, translate_analysis, extract_social_media_signals, analyze_social_media_multimodal_v2, encode_image_to_base64
from utils.dynamodbUtils import save_detection_result, find_result_by_hash, get_detection_result
from utils.s3Utils import upload_image_to_s3
import hashlib
import base64
from utils.checkerUtils import check_url_phishing, check_email_validity, check_phone_number_validity, extract_urls_from_text, extract_emails_from_text, extract_phone_numbers_from_text, check_all_content, format_checker_results_for_llm

config = Setting()

router = APIRouter(prefix="/socialmedia", tags=["Social Media Analysis"])

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_socialmedia_content_hash(platform: str, content: str, author_username: str = "", post_url: str = "", has_image: bool = False) -> str:
    """Create unique hash for social media content to enable deduplication."""
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
    
    platform_norm = normalize_text(platform)
    content_norm = normalize_text(content)
    author_norm = normalize_text(author_username)
    url_norm = normalize_url(post_url)
    
    hash_input = f"socialmedia:{platform_norm}|{content_norm}|{author_norm}|{url_norm}|{has_image}"
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


class SocialMediaAnalysisV2Request(BaseModel):
    platform: str = Field(
        ..., description="Social media platform (facebook, instagram, twitter, tiktok, linkedin)")
    content: str = Field(..., description="Post content/text")
    author_username: str = Field(..., description="Author's username")
    target_language: str = Field(
        ..., description="Target language for analysis (en, zh, ms, th, vi)")
    image: Optional[str] = Field(None, description="Base64 encoded image string for multimodal analysis")
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

    # [Step 1.5] Check URLs, emails, and phone numbers in the content
    full_content = f"{content} {post_url or ''}"
    checker_results = check_all_content(full_content)
    
    # [Step 1.6] Extract auxiliary signals to support the analysis
    signals = extract_social_media_signals(
        platform=platform,
        content=content,
        author_username=author_username,
        post_url=post_url,
        author_followers_count=author_followers_count,
        engagement_metrics=engagement_metrics
    )
    
    # [Step 1.7] Check additional phone numbers found by social media signal extraction
    social_media_phones = signals.get('artifacts', {}).get('phone_numbers', [])
    if social_media_phones:
        # Validate any phone numbers found by social media extraction that weren't caught by checker utils
        from utils.checkerUtils import check_phone_number_validity
        additional_phone_results = []
        for phone in social_media_phones:
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
    
    # [Step 1.8] Format checker analysis for LLM
    checker_analysis = format_checker_results_for_llm(checker_results)
    
    # Add checker results to signals for LLM analysis
    if checker_analysis:
        signals['checker_analysis'] = checker_analysis

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
    content_hash = create_socialmedia_content_hash(platform, content, author_username, post_url)

    # [Step 4.5] Check if we already have analysis for this content
    existing_analysis = await find_result_by_hash(content_hash)
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
    extracted_data = {
        "platform": platform,
        "content": content,
        "author_username": author_username,
        "post_url": post_url,
        "author_followers_count": author_followers_count,
        "engagement_metrics": engagement_metrics,
        "signals": signals,
        "checker_results": checker_results
    }
    
    # Save to database using centralized function
    post_id = await save_detection_result("socialmedia", content_hash, analysis, extracted_data)

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
    document = await get_detection_result(post_id)
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

# =============================================================================
# 4. SOCIAL MEDIA ANALYSIS V2 ENDPOINT (MULTIMODAL)
# =============================================================================


class SocialMediaAnalysisV2Response(BaseModel):
    success: bool = Field(...,
                          description="Whether the request was successful")
    message: str = Field(..., description="Response message")
    data: Dict[str, Any] = Field(
        ..., description="Analysis results including risk level, reasons, recommended action, and multimodal analysis")
    timestamp: str = Field(..., description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")


# V2 Analyze endpoint
analyze_v2_summary = "Analyze Social Media Post for Scam Detection with Multimodal Support (v2)"

analyze_v2_description = """
Analyze social media content for potential scam indicators using AI with multimodal support (Sea-Lion v4).

**V2 Features:**
- **Multimodal Analysis**: Support for both text and image analysis
- **Sea-Lion v4 Model**: Upgraded to aisingapore/Gemma-SEA-LION-v4-27B-IT
- **Base64 Image Input**: Accept images as base64 encoded strings
- **Enhanced Analysis**: Combined text and visual scam detection
- **Image OCR**: Extract and analyze text within images
- **Visual Scam Detection**: Identify fake logos, poor design, misleading claims

**Supported Platforms:**
- Facebook
- Instagram
- Twitter/X
- TikTok
- LinkedIn

**New Capabilities:**
- Visual brand impersonation detection
- Fake screenshot analysis
- Combined text-image scam narrative detection
- OCR-based text extraction from images
- Visual quality assessment

**Response Format:**
```json
{
  "success": true,
  "message": "Request processed successfully",
  "data": {
    "post_id": "64a7f123456789abcdef0123",
    "en": {
      "risk_level": "high|medium|low",
      "analysis": "Comprehensive analysis covering both text and image elements",
      "recommended_action": "Specific action recommendation for users",
      "image_analysis": "Specific findings from image analysis (NEW in v2)",
      "text_analysis": "Specific findings from text analysis (NEW in v2)"
    },
    "reused": false,
    "version": "v2",
    "multimodal": true
  },
  "timestamp": "2025-08-26T13:30:45.123456Z",
  "status_code": 200
}
```

**Response Fields:**
- **`success`**: Whether the request was successful
- **`message`**: Response message
- **`data.post_id`**: Unique identifier for the analyzed post
- **`data.[language]`**: Analysis results in requested language
- **`data.[language].risk_level`**: Risk assessment (high/medium/low)
- **`data.[language].analysis`**: 🆕 Enhanced comprehensive analysis
- **`data.[language].recommended_action`**: Specific user recommendations
- **`data.[language].image_analysis`**: 🆕 Visual scam detection results
- **`data.[language].text_analysis`**: 🆕 Text content analysis results
- **`data.reused`**: Whether results were retrieved from cache
- **`data.version`**: API version identifier ("v2")
- **`data.multimodal`**: 🆕 Whether image analysis was performed
- **`timestamp`**: ISO format response timestamp
- **`status_code`**: HTTP status code

**Example Multimodal Response:**
```json
{
  "success": true,
  "message": "Request processed successfully",
  "data": {
    "post_id": "64a7f123456789abcdef0123",
    "en": {
      "risk_level": "high",
      "analysis": "This Facebook post exhibits multiple scam characteristics. The visual elements (logos, promotional design) combined with text promising unrealistic returns create a deceptive gambling promotion.",
      "recommended_action": "Do not engage with this post. Report to Facebook and block the account.",
      "image_analysis": "Features BK8 and CMD368 gambling logos with professional design intended to appear legitimate. Contains promotional button with foreign text and USD 100 offer.",
      "text_analysis": "Uses classic scam tactics: promise of money, urgency language, and promotional gambling content without clear terms."
    },
    "reused": false,
    "version": "v2",
    "multimodal": true
  },
  "timestamp": "2025-08-26T13:30:45.123456Z",
  "status_code": 200
}
```

**Returns:**
- Enhanced multimodal analysis (text + image)
- Detailed visual and textual scam detection
- Platform-specific risk assessment
- Comprehensive recommendations
- Content reuse indicators
"""


@router.post("/v2/analyze",
             summary=analyze_v2_summary,
             description=analyze_v2_description,
             response_model=SocialMediaAnalysisV2Response,
             response_description="Social media multimodal analysis results with risk assessment using Sea-Lion v4")
async def analyze_social_media_post_v2(request: SocialMediaAnalysisV2Request):
    """
    V2 Social media analysis endpoint with multimodal support using Sea-Lion v4 model.
    
    This endpoint can analyze both text content and images for comprehensive scam detection.
    If an image is provided, it performs multimodal analysis. Otherwise, it falls back to 
    enhanced text-only analysis using Sea-Lion v4.
    """
    # [Step 0] Read values from the request body
    try:
        platform = request.platform
        content = request.content
        author_username = request.author_username
        target_language = request.target_language
        image_base64 = request.image
        post_url = request.post_url
        author_followers_count = request.author_followers_count
        engagement_metrics = request.engagement_metrics

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid request body")

    # [Step 1] Check URLs, emails, and phone numbers in the content
    full_content = f"{content} {post_url or ''}"
    checker_results = check_all_content(full_content)
    
    # [Step 1.5] Extract auxiliary signals to support the analysis
    signals = extract_social_media_signals(
        platform=platform,
        content=content,
        author_username=author_username,
        post_url=post_url,
        author_followers_count=author_followers_count,
        engagement_metrics=engagement_metrics
    )
    
    # [Step 1.6] Check additional phone numbers found by social media signal extraction
    social_media_phones = signals.get('artifacts', {}).get('phone_numbers', [])
    if social_media_phones:
        # Validate any phone numbers found by social media extraction that weren't caught by checker utils
        from utils.checkerUtils import check_phone_number_validity
        additional_phone_results = []
        for phone in social_media_phones:
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

    # [Step 2] Perform multimodal or text-only analysis based on image availability
    if image_base64:
        # Multimodal analysis with Sea-Lion v4
        comprehensive_analysis = await analyze_social_media_multimodal_v2(
            platform=platform,
            content=content,
            base64_image=image_base64,
            target_language=target_language,
            signals=signals
        )
    else:
        # Text-only analysis with Sea-Lion v4
        from utils.socialmediaUtils import analyze_social_media_content_v2
        comprehensive_analysis = await analyze_social_media_content_v2(
            platform=platform,
            content=content,
            target_language=target_language,
            signals=signals
        )

    # Extract detected language and prepare analysis structure for database
    detected_language = comprehensive_analysis.get("detected_language", target_language)
    analysis = {
        target_language: {
            "risk_level": comprehensive_analysis.get("risk_level"),
            "analysis": comprehensive_analysis.get("analysis"),
            "recommended_action": comprehensive_analysis.get("recommended_action"),
            "image_analysis": comprehensive_analysis.get("image_analysis"),
            "text_analysis": comprehensive_analysis.get("text_analysis")
        }
    }

    # [Step 3] Create unique content hash for reusability (include image in hash if present)
    content_hash = create_socialmedia_content_hash(platform, content, author_username, post_url, bool(image_base64))

    # [Step 4] Check if we already have analysis for this content
    existing_analysis = await find_result_by_hash(content_hash)
    if existing_analysis and existing_analysis.get('content_type') == 'socialmedia':
        # Return existing analysis if available and matches target language
        existing_result = existing_analysis.get('analysis_result', {})
        if existing_result:
            print(f"Returning cached social media result for content hash: {content_hash}")
            return resp_200(
                data={
                    "post_id": existing_analysis.get('detection_id'),
                    target_language: {
                        "risk_level": existing_result.get("risk_level"),
                        "analysis": existing_result.get("analysis"),
                        "recommended_action": existing_result.get("recommended_action"),
                        "image_analysis": existing_result.get("image_analysis"),
                        "text_analysis": existing_result.get("text_analysis")
                    },
                    "reused": True,
                    "version": "v2",
                    "multimodal": bool(image_base64)
                }
            )

    # [Step 5] Process image and upload to S3 if present
    image_data = []
    if image_base64:
        print(f"Processing image for social media post with content hash: {content_hash}")
        try:
            # Decode base64 image
            image_bytes = base64.b64decode(image_base64)
            
            # Upload to S3
            s3_url = await upload_image_to_s3(image_bytes, content_hash, 0)
            
            if s3_url:
                image_data.append({
                    "original_data": "base64_encoded_image",  # Don't store actual base64 for privacy
                    "s3_url": s3_url,
                    "s3_key": f"social_media/{content_hash}_image_0.jpg",
                    "file_size": len(image_bytes),
                    "uploaded_at": "2025-09-06T16:36:00.000Z"  # This will be updated by S3 utils
                })
                print(f"✅ Successfully uploaded image to S3: {s3_url}")
            else:
                print(f"❌ Failed to upload image to S3")
        except Exception as e:
            print(f"❌ Error processing image: {e}")

    # [Step 6] Prepare extracted data for DynamoDB storage
    extracted_data = {
        "platform": platform,
        "content": content,
        "author_username": author_username,
        "post_url": post_url or "",
        "author_followers_count": author_followers_count or 0,
        "engagement_metrics": engagement_metrics or {},
        "images": image_data,  # S3 image data instead of base64
        "signals": signals or {},
        "checker_results": checker_results or {},
        "version": "v2",
        "multimodal": bool(image_base64)
    }

    # [Step 7] Save detection result to DynamoDB (extracted data + S3 URLs + LLM analysis)
    print(f"Attempting to save social media analysis to DynamoDB for content hash: {content_hash}")
    detection_id = await save_detection_result(
        content_type="socialmedia",
        content_hash=content_hash,
        analysis_result=comprehensive_analysis,
        extracted_data=extracted_data,
        target_language=target_language
    )
    
    # [Step 7.1] Verify save was successful before returning response
    if not detection_id or detection_id.startswith('temp_'):
        print(f"❌ CRITICAL: Failed to save social media analysis to DynamoDB! Got ID: {detection_id}")
        print(f"Content hash: {content_hash}")
        print(f"Platform: {platform}")
        # For now, continue with response (graceful degradation)
        # In production, you might want to raise an exception here
        post_id = f"temp_{content_hash[:8]}"
    else:
        print(f"✅ SUCCESS: Saved social media analysis to DynamoDB with ID: {detection_id}")
        post_id = detection_id

    # [Step 8] Respond analysis in "target language" to user
    return resp_200(
        data={
            "post_id": post_id,
            target_language: {
                "risk_level": comprehensive_analysis.get("risk_level"),
                "analysis": comprehensive_analysis.get("analysis"),
                "recommended_action": comprehensive_analysis.get("recommended_action"),
                "image_analysis": comprehensive_analysis.get("image_analysis"),
                "text_analysis": comprehensive_analysis.get("text_analysis")
            },
            "reused": False,
            "version": "v2",
            "multimodal": bool(image_base64)
        }
    )
