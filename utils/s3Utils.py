"""
S3 Utilities for MAI Scam Detection System

This module provides centralized S3 operations for storing and retrieving
images from social media analysis, with proper error handling and security.

TABLE OF CONTENTS:
==================

EXPORTED FUNCTIONS:
------------------
1. get_s3_client
2. upload_image_to_s3
3. download_image_from_url
4. generate_s3_key
5. delete_image_from_s3

USAGE EXAMPLES:
--------------
# Upload image to S3
s3_url = await upload_image_to_s3(image_data, content_hash, 0)

# Download image from URL
image_data = await download_image_from_url("https://example.com/image.jpg")

# Generate S3 key
key = generate_s3_key(content_hash, 0)
"""

import boto3
import aiohttp
import asyncio
from datetime import datetime
from typing import Optional, Tuple
from PIL import Image
import io
import uuid
from setting import Setting

# Configuration
config = Setting()
S3_BUCKET_NAME = "mai-scam-detected-images"
S3_REGION = "us-east-1"
MAX_IMAGE_SIZE_MB = 10
ALLOWED_FORMATS = ['JPEG', 'PNG', 'WEBP']


# =============================================================================
# 1. S3 CLIENT FUNCTION
# =============================================================================

def get_s3_client():
    """
    Get S3 client with credentials from environment variables.
    
    The client automatically uses AWS credentials from environment:
    - AWS_ACCESS_KEY_ID
    - AWS_SECRET_ACCESS_KEY  
    - AWS_SESSION_TOKEN
    
    Returns:
        boto3.client: Configured S3 client
        
    Example:
        s3_client = get_s3_client()
    """
    return boto3.client('s3', region_name=S3_REGION)


# =============================================================================
# 2. S3 KEY GENERATION FUNCTION
# =============================================================================

def generate_s3_key(content_hash: str, image_index: int, file_extension: str = "jpg") -> str:
    """
    Generate S3 key for storing image files.
    
    Args:
        content_hash: Unique content hash
        image_index: Index of image in the post (0, 1, 2, etc.)
        file_extension: File extension (jpg, png, webp)
        
    Returns:
        S3 key string
        
    Example:
        key = generate_s3_key("abc123def456", 0, "jpg")
        # Returns: "social_media/abc123def456_image_0.jpg"
    """
    timestamp = datetime.now().strftime("%Y%m%d")
    return f"social_media/{timestamp}/{content_hash}_image_{image_index}.{file_extension}"


# =============================================================================
# 3. IMAGE DOWNLOAD FUNCTION  
# =============================================================================

async def download_image_from_url(image_url: str, timeout: int = 30) -> Optional[bytes]:
    """
    Download image from URL with error handling and size limits.
    
    Args:
        image_url: URL of the image to download
        timeout: Request timeout in seconds
        
    Returns:
        Image bytes if successful, None if failed
        
    Example:
        image_data = await download_image_from_url("https://example.com/image.jpg")
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(image_url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                if response.status == 200:
                    # Check content length
                    content_length = response.headers.get('content-length')
                    if content_length and int(content_length) > MAX_IMAGE_SIZE_MB * 1024 * 1024:
                        print(f"Image too large: {content_length} bytes")
                        return None
                    
                    image_data = await response.read()
                    
                    # Verify it's a valid image
                    try:
                        with Image.open(io.BytesIO(image_data)) as img:
                            if img.format not in ALLOWED_FORMATS:
                                print(f"Unsupported image format: {img.format}")
                                return None
                        return image_data
                    except Exception as img_error:
                        print(f"Invalid image data: {img_error}")
                        return None
                else:
                    print(f"Failed to download image: {response.status}")
                    return None
                    
    except Exception as e:
        print(f"Error downloading image from {image_url}: {e}")
        return None


# =============================================================================
# 4. IMAGE UPLOAD FUNCTION
# =============================================================================

async def upload_image_to_s3(image_data: bytes, content_hash: str, image_index: int) -> Optional[str]:
    """
    Upload image to S3 bucket with proper error handling.
    
    Args:
        image_data: Raw image bytes
        content_hash: Unique content hash for the social media post
        image_index: Index of the image (0, 1, 2, etc.)
        
    Returns:
        S3 public URL if successful, None if failed
        
    Example:
        s3_url = await upload_image_to_s3(image_bytes, "abc123def456", 0)
    """
    try:
        # Determine file format and extension
        try:
            with Image.open(io.BytesIO(image_data)) as img:
                format_lower = img.format.lower()
                extension = "jpg" if format_lower == "jpeg" else format_lower
        except Exception:
            extension = "jpg"  # Default fallback
            
        # Generate S3 key
        s3_key = generate_s3_key(content_hash, image_index, extension)
        
        # Get S3 client
        s3_client = get_s3_client()
        
        # Upload to S3
        s3_client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=s3_key,
            Body=image_data,
            ContentType=f"image/{extension}",
            CacheControl="public, max-age=31536000",  # 1 year cache
            Metadata={
                'content_hash': content_hash,
                'image_index': str(image_index),
                'uploaded_at': datetime.now().isoformat()
            }
        )
        
        # Generate public URL
        s3_url = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{s3_key}"
        
        print(f"Successfully uploaded image to S3: {s3_url}")
        return s3_url
        
    except Exception as e:
        print(f"Error uploading image to S3: {e}")
        return None


# =============================================================================
# 5. IMAGE DELETION FUNCTION
# =============================================================================

async def delete_image_from_s3(s3_key: str) -> bool:
    """
    Delete image from S3 bucket.
    
    Args:
        s3_key: S3 object key to delete
        
    Returns:
        True if successful, False if failed
        
    Example:
        success = await delete_image_from_s3("social_media/20240115/abc123_image_0.jpg")
    """
    try:
        s3_client = get_s3_client()
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
        print(f"Successfully deleted image from S3: {s3_key}")
        return True
        
    except Exception as e:
        print(f"Error deleting image from S3: {e}")
        return False


# =============================================================================
# 6. BATCH IMAGE PROCESSING FUNCTION
# =============================================================================

async def process_social_media_images(image_urls: list, content_hash: str) -> list:
    """
    Process multiple images from social media post.
    
    Downloads images from URLs and uploads them to S3 in parallel.
    
    Args:
        image_urls: List of image URLs to process
        content_hash: Unique content hash for the post
        
    Returns:
        List of image data with S3 URLs and metadata
        
    Example:
        image_data = await process_social_media_images(
            ["https://example.com/img1.jpg", "https://example.com/img2.jpg"],
            "abc123def456"
        )
    """
    processed_images = []
    
    # Process images concurrently
    tasks = []
    for i, image_url in enumerate(image_urls):
        tasks.append(_process_single_image(image_url, content_hash, i))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Collect successful results
    for i, result in enumerate(results):
        if isinstance(result, dict):
            processed_images.append(result)
        else:
            print(f"Failed to process image {i}: {result}")
    
    return processed_images


async def _process_single_image(image_url: str, content_hash: str, image_index: int) -> Optional[dict]:
    """
    Process a single image: download and upload to S3.
    
    Args:
        image_url: Image URL to process
        content_hash: Content hash
        image_index: Image index
        
    Returns:
        Image data dict if successful, None if failed
    """
    try:
        # Download image
        image_data = await download_image_from_url(image_url)
        if not image_data:
            return None
            
        # Upload to S3
        s3_url = await upload_image_to_s3(image_data, content_hash, image_index)
        if not s3_url:
            return None
            
        # Generate S3 key for reference
        s3_key = generate_s3_key(content_hash, image_index)
        
        return {
            "original_url": image_url,
            "s3_url": s3_url,
            "s3_key": s3_key,
            "file_size": len(image_data),
            "uploaded_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        print(f"Error processing image {image_url}: {e}")
        return None