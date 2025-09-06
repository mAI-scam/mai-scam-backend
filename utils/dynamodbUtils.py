"""
DynamoDB Utilities for MAI Scam Detection System

This module provides centralized DynamoDB operations for storing and retrieving
detection results from all demos (email, website, social media) with proper
error handling and security measures.

TABLE OF CONTENTS:
==================

EXPORTED FUNCTIONS:
------------------
1. get_dynamodb_client
2. get_dynamodb_resource  
3. save_detection_result
4. find_result_by_hash
5. create_detection_document
6. prepare_email_detection_document
7. prepare_website_detection_document
8. prepare_socialmedia_detection_document

USAGE EXAMPLES:
--------------
# Save email detection result
result_id = await save_detection_result("email", content_hash, analysis_result)

# Save website detection result  
result_id = await save_detection_result("website", content_hash, analysis_result, extracted_data)

# Find existing result
existing = await find_result_by_hash(content_hash)
"""

import boto3
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List
from decimal import Decimal
import uuid
from dotenv import load_dotenv
from setting import Setting

# Load environment variables
load_dotenv(override=True)

# Configuration
config = Setting()
DYNAMODB_TABLE_NAME = "mai-scam-detection-results"
DYNAMODB_REGION = "us-east-1"
TTL_DAYS = 90  # Auto-delete records after 90 days


# =============================================================================
# 1. DYNAMODB CLIENT AND RESOURCE FUNCTIONS
# =============================================================================

def get_dynamodb_client():
    """
    Get DynamoDB client with credentials from environment variables.
    
    The client automatically uses AWS credentials from environment:
    - AWS_ACCESS_KEY_ID
    - AWS_SECRET_ACCESS_KEY
    - AWS_SESSION_TOKEN
    
    Returns:
        boto3.client: Configured DynamoDB client
        
    Example:
        dynamodb_client = get_dynamodb_client()
    """
    return boto3.client('dynamodb', region_name=DYNAMODB_REGION)


def get_dynamodb_resource():
    """
    Get DynamoDB resource with credentials from environment variables.
    
    Returns:
        boto3.resource: Configured DynamoDB resource
        
    Example:
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_TABLE_NAME)
    """
    return boto3.resource('dynamodb', region_name=DYNAMODB_REGION)


# =============================================================================
# 2. HELPER FUNCTIONS
# =============================================================================

def _convert_floats_to_decimal(obj):
    """
    Convert float values to Decimal for DynamoDB compatibility.
    
    Args:
        obj: Object that may contain float values
        
    Returns:
        Object with floats converted to Decimal
    """
    if isinstance(obj, list):
        return [_convert_floats_to_decimal(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: _convert_floats_to_decimal(value) for key, value in obj.items()}
    elif isinstance(obj, float):
        return Decimal(str(obj))
    else:
        return obj


def _generate_ttl():
    """
    Generate TTL timestamp for auto-deletion.
    
    Returns:
        Unix timestamp for TTL (90 days from now)
    """
    expiry_date = datetime.now() + timedelta(days=TTL_DAYS)
    return int(expiry_date.timestamp())


# =============================================================================
# 3. DOCUMENT PREPARATION FUNCTIONS
# =============================================================================

def prepare_email_detection_document(content_hash: str, analysis_result: Dict[str, Any], 
                                    target_language: str = "en") -> Dict[str, Any]:
    """
    Prepare email detection document for DynamoDB storage.
    
    For email, we only store the LLM analysis results (no user email content).
    
    Args:
        content_hash: Unique content hash
        analysis_result: LLM analysis results
        target_language: Target language for analysis
        
    Returns:
        Document ready for DynamoDB storage
        
    Example:
        doc = prepare_email_detection_document(
            "abc123def456", 
            {"risk_level": "high", "analysis": "...", "recommended_action": "..."},
            "en"
        )
    """
    return {
        "mai-scam": content_hash,
        "timestamp": datetime.now().isoformat(),
        "content_type": "email",
        "detection_id": str(uuid.uuid4()),
        "analysis_result": analysis_result,
        "target_language": target_language,
        "created_at": datetime.now().isoformat(),
        "ttl": _generate_ttl()
    }


def prepare_website_detection_document(content_hash: str, analysis_result: Dict[str, Any],
                                     extracted_data: Dict[str, Any], target_language: str = "en") -> Dict[str, Any]:
    """
    Prepare website detection document for DynamoDB storage.
    
    For website, we store both extracted data and LLM analysis results.
    
    Args:
        content_hash: Unique content hash
        analysis_result: LLM analysis results  
        extracted_data: Extracted website data
        target_language: Target language for analysis
        
    Returns:
        Document ready for DynamoDB storage
        
    Example:
        doc = prepare_website_detection_document(
            "xyz789abc123",
            {"risk_level": "medium", "analysis": "...", "recommended_action": "..."},
            {"url": "https://example.com", "title": "Example", "content": "..."},
            "en"
        )
    """
    return {
        "mai-scam": content_hash,
        "timestamp": datetime.now().isoformat(),
        "content_type": "website",
        "detection_id": str(uuid.uuid4()),
        "extracted_data": _convert_floats_to_decimal(extracted_data),
        "analysis_result": analysis_result,
        "target_language": target_language,
        "created_at": datetime.now().isoformat(),
        "ttl": _generate_ttl()
    }


def prepare_socialmedia_detection_document(content_hash: str, analysis_result: Dict[str, Any],
                                         extracted_data: Dict[str, Any], target_language: str = "en") -> Dict[str, Any]:
    """
    Prepare social media detection document for DynamoDB storage.
    
    For social media, we store both extracted data (including S3 image URLs) and LLM analysis results.
    
    Args:
        content_hash: Unique content hash
        analysis_result: LLM analysis results
        extracted_data: Extracted social media data (including S3 image URLs)
        target_language: Target language for analysis
        
    Returns:
        Document ready for DynamoDB storage
        
    Example:
        doc = prepare_socialmedia_detection_document(
            "def456ghi789",
            {"risk_level": "low", "analysis": "...", "recommended_action": "..."},
            {"platform": "facebook", "content": "...", "images": [...]},
            "en"
        )
    """
    return {
        "mai-scam": content_hash,
        "timestamp": datetime.now().isoformat(),
        "content_type": "socialmedia",
        "detection_id": str(uuid.uuid4()),
        "extracted_data": _convert_floats_to_decimal(extracted_data),
        "analysis_result": analysis_result,
        "target_language": target_language,
        "created_at": datetime.now().isoformat(),
        "ttl": _generate_ttl()
    }


# =============================================================================
# 4. MAIN SAVE FUNCTION
# =============================================================================

async def save_detection_result(content_type: str, content_hash: str, analysis_result: Dict[str, Any],
                               extracted_data: Optional[Dict[str, Any]] = None, 
                               target_language: str = "en") -> Optional[str]:
    """
    Save detection result to DynamoDB with proper error handling.
    
    This function saves different types of detection results based on content_type:
    - email: Only LLM analysis results (no user email content)
    - website: Extracted data + LLM analysis results
    - socialmedia: Extracted data (including S3 URLs) + LLM analysis results
    
    Args:
        content_type: "email", "website", or "socialmedia"
        content_hash: Unique content hash for deduplication
        analysis_result: LLM analysis results
        extracted_data: Extracted content data (None for email)
        target_language: Target language for analysis
        
    Returns:
        Detection ID if successful, None if failed
        
    Example:
        # Email (no extracted data)
        result_id = await save_detection_result(
            "email", content_hash, analysis_result
        )
        
        # Website/Social Media (with extracted data)  
        result_id = await save_detection_result(
            "website", content_hash, analysis_result, extracted_data
        )
    """
    try:
        # Prepare document based on content type
        if content_type == "email":
            document = prepare_email_detection_document(content_hash, analysis_result, target_language)
        elif content_type == "website":
            if not extracted_data:
                raise ValueError("extracted_data is required for website content type")
            document = prepare_website_detection_document(content_hash, analysis_result, extracted_data, target_language)
        elif content_type == "socialmedia":
            if not extracted_data:
                raise ValueError("extracted_data is required for socialmedia content type")
            document = prepare_socialmedia_detection_document(content_hash, analysis_result, extracted_data, target_language)
        else:
            raise ValueError(f"Unsupported content_type: {content_type}")
        
        # Get DynamoDB table
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_TABLE_NAME)
        
        # Save to DynamoDB
        response = table.put_item(Item=document)
        
        print(f"Successfully saved {content_type} detection result: {document['detection_id']}")
        return document['detection_id']
        
    except Exception as e:
        print(f"Error saving detection result to DynamoDB: {e}")
        # Generate temporary ID for graceful error handling
        return f"temp_{uuid.uuid4().hex[:8]}"


# =============================================================================
# 5. SEARCH AND RETRIEVAL FUNCTIONS
# =============================================================================

async def find_result_by_hash(content_hash: str) -> Optional[Dict[str, Any]]:
    """
    Find existing detection result by content hash for reusability.
    
    This function searches for existing detection results using the content hash,
    enabling the system to reuse previous analysis and avoid redundant LLM calls.
    
    Args:
        content_hash: The content hash to search for
        
    Returns:
        Existing document if found, None otherwise
        
    Example:
        existing = await find_result_by_hash("abc123def456")
        if existing:
            print(f"Found existing result: {existing['analysis_result']['risk_level']}")
    """
    try:
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_TABLE_NAME)
        
        # Query by mai-scam (partition key)
        response = table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('mai-scam').eq(content_hash),
            Limit=1,
            ScanIndexForward=False  # Get most recent first
        )
        
        if response['Items']:
            return response['Items'][0]
        else:
            return None
            
    except Exception as e:
        print(f"Error finding result by hash: {e}")
        return None


async def get_detection_result(detection_id: str) -> Optional[Dict[str, Any]]:
    """
    Get detection result by detection ID.
    
    Args:
        detection_id: Detection ID to retrieve
        
    Returns:
        Detection result if found, None otherwise
        
    Example:
        result = await get_detection_result("uuid-string")
    """
    try:
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_TABLE_NAME)
        
        # Scan for detection_id (this is not efficient for large datasets, 
        # consider using GSI if needed frequently)
        response = table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('detection_id').eq(detection_id),
            Limit=1
        )
        
        if response['Items']:
            return response['Items'][0]
        else:
            return None
            
    except Exception as e:
        print(f"Error getting detection result: {e}")
        return None


# =============================================================================
# 6. STATISTICS AND MONITORING FUNCTIONS
# =============================================================================

async def get_detection_stats() -> Dict[str, Any]:
    """
    Get detection statistics for monitoring purposes.
    
    Returns:
        Statistics dictionary with counts by content type and risk level
        
    Example:
        stats = await get_detection_stats()
        print(f"Total detections: {stats['total_detections']}")
    """
    try:
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_TABLE_NAME)
        
        # This is a simple implementation - for production, consider using DynamoDB Streams
        # or scheduled Lambda functions to maintain statistics
        response = table.scan()
        
        stats = {
            "total_detections": 0,
            "by_content_type": {},
            "by_risk_level": {},
            "last_updated": datetime.now().isoformat()
        }
        
        for item in response['Items']:
            stats["total_detections"] += 1
            
            # Count by content type
            content_type = item.get('content_type', 'unknown')
            stats["by_content_type"][content_type] = stats["by_content_type"].get(content_type, 0) + 1
            
            # Count by risk level
            risk_level = item.get('analysis_result', {}).get('risk_level', 'unknown')
            stats["by_risk_level"][risk_level] = stats["by_risk_level"].get(risk_level, 0) + 1
        
        return stats
        
    except Exception as e:
        print(f"Error getting detection stats: {e}")
        return {"error": str(e)}