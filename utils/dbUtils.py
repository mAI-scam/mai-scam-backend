"""
Database Utilities for MAI Scam Detection System

This module provides centralized database operations for storing and retrieving
analysis results from MongoDB, including content hashing for reusability.

TABLE OF CONTENTS:
==================

EXPORTED FUNCTIONS:
------------------
1. create_content_hash(content_type, **kwargs) -> str
   - Creates unique, reusable hashes for content analysis
   - Supports email, website, and social media content types

2. save_analysis_to_db(document, content_type, **kwargs) -> str
   - Saves analysis document to MongoDB with error handling
   - Returns document ID (MongoDB ObjectId or temporary ID)

3. retrieve_analysis_from_db(document_id, content_type, **kwargs) -> dict
   - Retrieves analysis document from MongoDB by ID
   - Returns document if found, None otherwise

4. find_analysis_by_hash(content_hash, content_type, **kwargs) -> dict
   - Finds existing analysis by content hash for reusability
   - Returns existing document if found, None otherwise

5. update_analysis_in_db(document_id, target_language, analysis_data, content_type, **kwargs) -> bool
   - Updates existing analysis document with new language analysis
   - Returns True if update successful, False otherwise

6. get_db_connection_info(content_type, **kwargs) -> dict
   - Gets database connection information for a content type
   - Returns dictionary with db_name and collection_name

DOCUMENT PREPARATION FUNCTIONS:
-----------------------------
7. prepare_email_document(title, content, from_email, reply_to_email, base_language, analysis, signals) -> dict
   - Prepares email document for database storage

8. prepare_social_media_document(platform, content, author_username, post_url, author_followers_count, engagement_metrics, base_language, analysis, signals) -> dict
   - Prepares social media document for database storage

9. prepare_website_document(url, title, content, screenshot_data, metadata, base_language, analysis, signals) -> dict
   - Prepares website document for database storage

USAGE EXAMPLES:
--------------
# Create content hash
hash_value = create_content_hash("email", subject="Test", content="Hello", from_email="test@example.com")

# Save analysis
doc_id = await save_analysis_to_db(document, "email")

# Retrieve analysis
analysis = await retrieve_analysis_from_db(doc_id, "email")

# Find by hash
existing = await find_analysis_by_hash(hash_value, "email")
"""

import hashlib
import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional, Any
from models.clients import get_mongodb_client

# Constants
HASH_ALGORITHM = "sha256"
HASH_LENGTH = 16

# Database configuration
DEFAULT_DB_NAME = "maiscam-db"
COLLECTION_NAMES = {
    "email": "emails",
    "socialmedia": "social_media_posts",
    "website": "websites"
}


def normalize_text(text: str) -> str:
    """
    Normalize text for consistent hashing by removing extra whitespace and converting to lowercase.

    Args:
        text: Input text to normalize

    Returns:
        str: Normalized text
    """
    if not text:
        return ""
    # Remove extra whitespace and convert to lowercase
    normalized = re.sub(r'\s+', ' ', text.strip().lower())
    return normalized


def normalize_url(url: str) -> str:
    """
    Normalize URL for consistent hashing by removing query parameters and fragments.

    Args:
        url: Input URL to normalize

    Returns:
        str: Normalized URL
    """
    if not url:
        return ""

    try:
        parsed = urlparse(url)
        # Remove query parameters and fragments, keep only scheme, netloc, and path
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        # Remove trailing slash for consistency
        normalized = normalized.rstrip('/')
        return normalized.lower()
    except:
        # If URL parsing fails, return normalized original
        return normalize_text(url)


def create_content_hash(content_type: str, **kwargs) -> str:
    """
    Create a unique, reusable hash for content analysis.

    This function generates consistent hashes for the same content, enabling
    the system to reuse existing analysis results and avoid redundant LLM calls.

    Args:
        content_type: "email", "website", or "socialmedia"
        **kwargs: Content-specific parameters

    Returns:
        SHA-256 hash string (first 16 characters for readability)

    Raises:
        ValueError: If content_type is not supported

    Example:
        hash_value = create_content_hash(
            "email", 
            subject="Test Email", 
            content="Hello world", 
            from_email="sender@example.com"
        )
    """

    if content_type == "email":
        subject = normalize_text(kwargs.get('subject', ''))
        content = normalize_text(kwargs.get('content', ''))
        from_email = normalize_text(kwargs.get('from_email', ''))

        # Create hash from normalized content
        hash_input = f"email:{subject}|{content}|{from_email}"

    elif content_type == "website":
        url = normalize_url(kwargs.get('url', ''))
        title = normalize_text(kwargs.get('title', ''))
        content = normalize_text(kwargs.get('content', ''))

        # Create hash from normalized URL and content
        hash_input = f"website:{url}|{title}|{content}"

    elif content_type == "socialmedia":
        platform = kwargs.get('platform', '').lower()
        content = normalize_text(kwargs.get('content', ''))
        author_username = normalize_text(kwargs.get('author_username', ''))
        post_url = normalize_url(kwargs.get('post_url', ''))

        # Create hash from platform, content, author, and URL
        hash_input = f"socialmedia:{platform}|{content}|{author_username}|{post_url}"

    else:
        raise ValueError(f"Unsupported content_type: {content_type}")

    # Generate SHA-256 hash and return first 16 characters
    hash_object = hashlib.sha256(hash_input.encode('utf-8'))
    return hash_object.hexdigest()[:HASH_LENGTH]


async def save_analysis_to_db(document: Dict[str, Any], content_type: str, **kwargs) -> str:
    """
    Save analysis document to MongoDB with error handling.

    This function attempts to save the document to MongoDB and provides
    graceful error handling by generating a temporary ID if the save fails.

    Args:
        document: Document to save
        content_type: "email", "socialmedia", or "website"
        **kwargs: Additional options (db_name, collection_name)

    Returns:
        Document ID (MongoDB ObjectId as string or temporary ID)

    Example:
        doc_id = await save_analysis_to_db(
            document=analysis_doc, 
            content_type="email",
            db_name="custom_db"
        )
    """
    try:
        db_name = kwargs.get('db_name', DEFAULT_DB_NAME)
        collection_name = kwargs.get(
            'collection_name', COLLECTION_NAMES.get(content_type, content_type))

        client = get_mongodb_client()
        db = client[db_name]
        collection = db[collection_name]

        # Insert document and return the ID
        result = collection.insert_one(document)
        return str(result.inserted_id)

    except Exception as e:
        # If MongoDB save fails, generate a temporary ID and continue
        import uuid
        return f"temp_{uuid.uuid4().hex[:8]}"


async def retrieve_analysis_from_db(document_id: str, content_type: str, **kwargs) -> Optional[Dict[str, Any]]:
    """
    Retrieve analysis document from MongoDB by ID.

    This function handles both MongoDB ObjectIds and temporary IDs,
    returning None for temporary IDs or if the document is not found.

    Args:
        document_id: Document ID to retrieve
        content_type: "email", "socialmedia", or "website"
        **kwargs: Additional options (db_name, collection_name)

    Returns:
        Document if found, None otherwise

    Example:
        analysis = await retrieve_analysis_from_db(
            document_id="507f1f77bcf86cd799439011",
            content_type="email"
        )
    """
    try:
        from bson import ObjectId

        db_name = kwargs.get('db_name', DEFAULT_DB_NAME)
        collection_name = kwargs.get(
            'collection_name', COLLECTION_NAMES.get(content_type, content_type))

        client = get_mongodb_client()
        db = client[db_name]
        collection = db[collection_name]

        # Try to convert to ObjectId if it's not a temporary ID
        if not document_id.startswith('temp_'):
            try:
                obj_id = ObjectId(document_id)
                document = collection.find_one({"_id": obj_id})
            except:
                document = None
        else:
            document = None

        return document

    except Exception as e:
        return None


async def find_analysis_by_hash(content_hash: str, content_type: str, **kwargs) -> Optional[Dict[str, Any]]:
    """
    Find existing analysis by content hash for reusability.

    This function searches for existing analysis results using the content hash,
    enabling the system to reuse previous analysis and avoid redundant LLM calls.

    Args:
        content_hash: The content hash to search for
        content_type: "email", "socialmedia", or "website"
        **kwargs: Additional options (db_name, collection_name)

    Returns:
        Existing document if found, None otherwise

    Example:
        existing = await find_analysis_by_hash(
            content_hash="a1b2c3d4e5f6g7h8",
            content_type="email"
        )
    """
    try:
        db_name = kwargs.get('db_name', DEFAULT_DB_NAME)
        collection_name = kwargs.get(
            'collection_name', COLLECTION_NAMES.get(content_type, content_type))

        client = get_mongodb_client()
        db = client[db_name]
        collection = db[collection_name]

        # Find document with matching content hash
        existing_doc = collection.find_one({"content_hash": content_hash})
        return existing_doc

    except Exception as e:
        return None


async def update_analysis_in_db(document_id: str, target_language: str, analysis_data: Dict[str, Any],
                                content_type: str, **kwargs) -> bool:
    """
    Update existing analysis document with new language analysis.

    This function adds or updates analysis results for a specific language
    in an existing document, typically used for translation results.

    Args:
        document_id: Document ID to update
        target_language: Language code for the analysis
        analysis_data: Analysis data to add
        content_type: "email", "socialmedia", or "website"
        **kwargs: Additional options (db_name, collection_name)

    Returns:
        True if update successful, False otherwise

    Example:
        success = await update_analysis_in_db(
            document_id="507f1f77bcf86cd799439011",
            target_language="zh",
            analysis_data=chinese_analysis,
            content_type="email"
        )
    """
    try:
        from bson import ObjectId

        db_name = kwargs.get('db_name', DEFAULT_DB_NAME)
        collection_name = kwargs.get(
            'collection_name', COLLECTION_NAMES.get(content_type, content_type))

        client = get_mongodb_client()
        db = client[db_name]
        collection = db[collection_name]

        # Try to convert to ObjectId if it's not a temporary ID
        if not document_id.startswith('temp_'):
            try:
                obj_id = ObjectId(document_id)
                result = collection.update_one(
                    {"_id": obj_id},
                    {"$set": {f"analysis.{target_language}": analysis_data}}
                )
                return result.modified_count > 0
            except:
                return False
        else:
            return False

    except Exception as e:
        return False


async def get_db_connection_info(content_type: str, **kwargs) -> Dict[str, str]:
    """
    Get database connection information for a content type.

    This function returns the database and collection names for a given
    content type, useful for debugging or custom database operations.

    Args:
        content_type: "email", "socialmedia", or "website"
        **kwargs: Additional options (db_name, collection_name)

    Returns:
        Dictionary with db_name and collection_name

    Example:
        info = await get_db_connection_info("email")
        # Returns: {"db_name": "maiscam-db", "collection_name": "emails"}
    """
    db_name = kwargs.get('db_name', DEFAULT_DB_NAME)
    collection_name = kwargs.get(
        'collection_name', COLLECTION_NAMES.get(content_type, content_type))

    return {
        "db_name": db_name,
        "collection_name": collection_name
    }


def prepare_email_document(title: str, content: str, from_email: str, reply_to_email: str,
                           base_language: str, analysis: dict, signals: dict | None = None) -> dict:
    """
    Prepare email document for database storage.

    This function creates a standardized document structure for email analysis
    results, including metadata, content, analysis results, and extracted signals.

    Args:
        title: Email subject
        content: Email content
        from_email: Sender email
        reply_to_email: Reply-to email
        base_language: Detected language
        analysis: Analysis results
        signals: Extracted signals (optional)

    Returns:
        Document ready for database storage

    Example:
        doc = prepare_email_document(
            title="Test Email",
            content="Hello world",
            from_email="sender@example.com",
            reply_to_email="reply@example.com",
            base_language="en",
            analysis=analysis_results,
            signals=extracted_signals
        )
    """
    from uuid import uuid4
    from datetime import datetime as dt

    document = {
        "_id": uuid4().hex,
        "created_at": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "updated_at": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "title": title,
        "content": content,
        "from_email": from_email,
        "reply_to_email": reply_to_email,
        "base_language": base_language,
        "analysis": analysis,
    }

    if signals is not None:
        document["signals"] = signals

    return document


def prepare_social_media_document(platform: str, content: str, author_username: str, post_url: str,
                                  author_followers_count: int, engagement_metrics: dict,
                                  base_language: str, analysis: dict, signals: dict | None = None) -> dict:
    """
    Prepare social media document for database storage.

    This function creates a standardized document structure for social media
    analysis results, including platform-specific metadata and engagement data.

    Args:
        platform: Social media platform
        content: Post content
        author_username: Author username
        post_url: Post URL
        author_followers_count: Follower count
        engagement_metrics: Engagement data
        base_language: Detected language
        analysis: Analysis results
        signals: Extracted signals (optional)

    Returns:
        Document ready for database storage

    Example:
        doc = prepare_social_media_document(
            platform="facebook",
            content="Check out this amazing offer!",
            author_username="user123",
            post_url="https://facebook.com/post/123",
            author_followers_count=1000,
            engagement_metrics={"likes": 50, "comments": 10},
            base_language="en",
            analysis=analysis_results,
            signals=extracted_signals
        )
    """
    from uuid import uuid4
    from datetime import datetime as dt

    document = {
        "_id": uuid4().hex,
        "created_at": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "updated_at": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "platform": platform,
        "content": content,
        "author_username": author_username,
        "post_url": post_url,
        "author_followers_count": author_followers_count,
        "engagement_metrics": engagement_metrics,
        "base_language": base_language,
        "analysis": analysis,
    }

    if signals is not None:
        document["signals"] = signals

    return document


def prepare_website_document(url: str, title: str, content: str, screenshot_data: str,
                             metadata: dict, base_language: str, analysis: dict, signals: dict | None = None) -> dict:
    """
    Prepare website document for database storage.

    This function creates a standardized document structure for website
    analysis results, including URL, metadata, and screenshot data.

    Args:
        url: Website URL
        title: Page title
        content: Page content
        screenshot_data: Screenshot data
        metadata: Website metadata
        base_language: Detected language
        analysis: Analysis results
        signals: Extracted signals (optional)

    Returns:
        Document ready for database storage

    Example:
        doc = prepare_website_document(
            url="https://example.com",
            title="Example Website",
            content="Welcome to our website",
            screenshot_data="base64_encoded_screenshot",
            metadata={"ssl_valid": True, "domain_age_days": 365},
            base_language="en",
            analysis=analysis_results,
            signals=extracted_signals
        )
    """
    from uuid import uuid4
    from datetime import datetime as dt

    document = {
        "_id": uuid4().hex,
        "created_at": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "updated_at": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url": url,
        "title": title,
        "content": content,
        "screenshot_data": screenshot_data,
        "metadata": metadata,
        "base_language": base_language,
        "analysis": analysis,
    }

    if signals is not None:
        document["signals"] = signals

    return document
