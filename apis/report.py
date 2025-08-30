"""
Reporting API for MAI Scam Detection System

This module provides endpoints for reporting detected scams to authorities.
Users can submit scam reports which are automatically emailed to authorities
for investigation and action.

ENDPOINTS:
------
1. GET /report/ - Report API health check  
2. POST /report/v2/submit - Submit scam report to authorities (v2)
"""

from fastapi import APIRouter, Request, HTTPException
from setting import Setting
import json
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, Union
from datetime import datetime

from models.customResponse import resp_200
from utils.reportUtils import send_email_report
# Authentication utilities (not used in this implementation but available if needed)

config = Setting()

router = APIRouter(prefix="/report", tags=["Scam Reporting"])

# =============================================================================
# 1. HEALTH CHECK ENDPOINT
# =============================================================================

class HealthResponse(BaseModel):
    status: str = Field(..., description="Health status")

@router.get("/", response_model=HealthResponse)
async def healthcheck():
    return {"status": "OK"}

# =============================================================================
# 2. SCAM REPORT MODELS
# =============================================================================

class EmailScamReportData(BaseModel):
    """Email scam report data"""
    subject: str = Field(..., description="Email subject line")
    content: str = Field(..., description="Email content/body")
    from_email: str = Field(..., description="Sender email address")
    reply_to_email: Optional[str] = Field(None, description="Reply-to email address")
    risk_level: str = Field(..., description="AI assessed risk level")
    analysis: str = Field(..., description="AI analysis results")
    recommended_action: str = Field(..., description="AI recommended action")
    detected_language: Optional[str] = Field(None, description="Detected content language")
    content_hash: Optional[str] = Field(None, description="Content hash for tracking")

class WebsiteScamReportData(BaseModel):
    """Website scam report data"""
    url: str = Field(..., description="Website URL")
    title: Optional[str] = Field(None, description="Website title")
    content: Optional[str] = Field(None, description="Website content/text")
    risk_level: str = Field(..., description="AI assessed risk level")
    analysis: str = Field(..., description="AI analysis results")
    recommended_action: str = Field(..., description="AI recommended action")
    detected_language: Optional[str] = Field(None, description="Detected content language")
    content_hash: Optional[str] = Field(None, description="Content hash for tracking")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional website metadata")

class SocialMediaScamReportData(BaseModel):
    """Social media scam report data"""
    platform: str = Field(..., description="Social media platform")
    content: str = Field(..., description="Post content/text")
    author_username: str = Field(..., description="Author's username")
    post_url: Optional[str] = Field(None, description="URL of the post")
    author_followers_count: Optional[int] = Field(None, description="Number of followers")
    engagement_metrics: Optional[Dict[str, Any]] = Field(None, description="Engagement metrics")
    risk_level: str = Field(..., description="AI assessed risk level")
    analysis: str = Field(..., description="AI analysis results")
    recommended_action: str = Field(..., description="AI recommended action")
    text_analysis: Optional[str] = Field(None, description="Specific text analysis (v2)")
    image_analysis: Optional[str] = Field(None, description="Specific image analysis (v2)")
    multimodal: Optional[bool] = Field(False, description="Whether multimodal analysis was performed")
    content_hash: Optional[str] = Field(None, description="Content hash for tracking")

class ScamReportRequest(BaseModel):
    """Universal scam report request"""
    scam_type: str = Field(..., description="Type of scam: email, website, or socialmedia")
    email_data: Optional[EmailScamReportData] = Field(None, description="Email scam data (required if scam_type=email)")
    website_data: Optional[WebsiteScamReportData] = Field(None, description="Website scam data (required if scam_type=website)")  
    socialmedia_data: Optional[SocialMediaScamReportData] = Field(None, description="Social media scam data (required if scam_type=socialmedia)")
    user_comment: Optional[str] = Field(None, description="Optional user comment about the scam")
    contact_email: Optional[str] = Field(None, description="Optional user contact email")

class ScamReportResponse(BaseModel):
    """Scam report submission response"""
    success: bool = Field(..., description="Whether the report was sent successfully")
    message: str = Field(..., description="Response message")
    data: Dict[str, Any] = Field(..., description="Report submission results")
    timestamp: str = Field(..., description="Response timestamp")
    status_code: int = Field(..., description="HTTP status code")

# =============================================================================
# 3. REPORT SUBMISSION ENDPOINT
# =============================================================================

# V2 Submit endpoint
submit_v2_summary = "Submit Scam Report to Authorities (v2)"

submit_v2_description = """
Submit a detected scam report to authorities for investigation and action.

**Supported Scam Types:**
- **email**: Email phishing, fraud, or malicious messages
- **website**: Fraudulent, phishing, or malicious websites  
- **socialmedia**: Scam posts on Facebook, Instagram, Twitter, TikTok, LinkedIn

**Features:**
- Automatic email formatting for authorities
- Unique report ID generation for tracking
- Professional report templates tailored for each scam type
- Secure submission with authentication
- Comprehensive analysis inclusion

**Email Recipients:**
- Primary: report.maiscam@gmail.com (authorities)

**Report Contents:**
Each report includes:
- Executive summary with risk assessment
- Original scam content (properly formatted)
- Complete AI analysis results
- Recommended actions for authorities
- Technical metadata and timestamps
- Unique report ID for tracking

**Authentication:**
- Requires valid JWT token or API key
- Reports are associated with the submitting client

**Example Request - Email Scam:**
```json
{
  "scam_type": "email",
  "email_data": {
    "subject": "URGENT: Verify Your Account Now!",
    "content": "Dear Customer, Your account will be suspended...",
    "from_email": "no-reply@suspicious-bank.com",
    "risk_level": "high",
    "analysis": "This email exhibits classic phishing characteristics...",
    "recommended_action": "Do not click any links. Report to your bank."
  },
  "user_comment": "Received this suspicious email claiming to be from my bank"
}
```

**Example Request - Website Scam:**
```json
{
  "scam_type": "website",
  "website_data": {
    "url": "https://fake-bank-login.com",
    "title": "Secure Bank Login",
    "content": "Enter your credentials to access account...",
    "risk_level": "high", 
    "analysis": "Website mimics legitimate bank interface...",
    "recommended_action": "Do not enter credentials. Report to authorities."
  }
}
```

**Example Request - Social Media Scam:**
```json
{
  "scam_type": "socialmedia",
  "socialmedia_data": {
    "platform": "facebook",
    "content": "Get rich quick! Invest $100, earn $1000 in 24 hours!",
    "author_username": "quick_money_guru",
    "risk_level": "high",
    "analysis": "Classic get-rich-quick scheme with unrealistic promises...",
    "recommended_action": "Report post to Facebook and block user."
  }
}
```

**Example Response:**
```json
{
  "success": true,
  "message": "Scam report submitted successfully",
  "data": {
    "report_id": "RPT-20240830-A1B2C3D4", 
    "scam_type": "email",
    "sent_to": "report.maiscam@gmail.com",
    "timestamp": "2024-08-30T14:30:45.123Z"
  },
  "timestamp": "2024-08-30T14:30:45.123456Z",
  "status_code": 200
}
```

**Error Handling:**
- Invalid scam_type: Returns 400 with error message
- Missing required data: Returns 400 with specific field requirements
- Email sending failure: Returns 500 with retry instructions
- Authentication failure: Returns 401 with auth requirements

**Returns:**
- Success confirmation with unique report ID
- Report submission timestamp
- Email delivery status
- Instructions for follow-up if needed
"""

@router.post("/v2/submit",
             summary=submit_v2_summary,
             description=submit_v2_description,
             response_model=ScamReportResponse,
             response_description="Scam report submission results with confirmation and tracking ID")
async def submit_scam_report_v2(request: ScamReportRequest):
    """
    Submit a scam report to authorities via email.
    
    This endpoint accepts scam analysis data from email, website, or social media
    detection endpoints and formats it into a professional report that gets
    emailed to the appropriate authorities for investigation.
    """
    
    # [Step 0] Validate request data
    try:
        scam_type = request.scam_type.lower()
        user_comment = request.user_comment
        contact_email = request.contact_email
        
        # Validate scam_type
        if scam_type not in ["email", "website", "socialmedia"]:
            raise HTTPException(
                status_code=400, 
                detail="Invalid scam_type. Must be 'email', 'website', or 'socialmedia'"
            )
            
        # Validate required data based on scam type
        scam_data = None
        if scam_type == "email":
            if not request.email_data:
                raise HTTPException(
                    status_code=400,
                    detail="email_data is required when scam_type is 'email'"
                )
            scam_data = request.email_data.dict()
            
        elif scam_type == "website":
            if not request.website_data:
                raise HTTPException(
                    status_code=400,
                    detail="website_data is required when scam_type is 'website'"
                )
            scam_data = request.website_data.dict()
            
        elif scam_type == "socialmedia":
            if not request.socialmedia_data:
                raise HTTPException(
                    status_code=400,
                    detail="socialmedia_data is required when scam_type is 'socialmedia'"
                )
            scam_data = request.socialmedia_data.dict()
        
        # Add user comment and contact to scam data if provided
        if user_comment:
            scam_data["user_comment"] = user_comment
        if contact_email:
            scam_data["contact_email"] = contact_email
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid request data: {str(e)}")
    
    # [Step 1] Send email report to authorities  
    try:
        report_result = await send_email_report(scam_type, scam_data)
        
        if report_result["success"]:
            return resp_200(
                data={
                    "report_id": report_result["report_id"],
                    "scam_type": scam_type,
                    "sent_to": config.get('REPORT_EMAIL'),
                    "message": report_result["message"],
                    "timestamp": datetime.now().isoformat()
                }
            )
        else:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to send report: {report_result['message']}"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error processing report: {str(e)}"
        )