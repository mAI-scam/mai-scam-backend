"""
LLM Utilities for MAI Scam Detection System

This module provides centralized functions for interacting with the Sea Lion LLM,
including prompt handling, response parsing, and JSON extraction.

TABLE OF CONTENTS:
==================

EXPORTED FUNCTIONS:
------------------
1. call_sea_lion_llm (v3.5)
2. call_sea_lion_v4_llm (v4)
3. call_sagemaker_sealion_llm (SageMaker)
4. call_sagemaker_sealion_multimodal_llm (SageMaker Multimodal)
5. parse_sealion_json
6. parse_sagemaker_json

USAGE EXAMPLES:
--------------
# Basic LLM call
completion = await call_sea_lion_llm(prompt="Analyze this content")

# Custom configuration
completion = await call_sea_lion_llm(
    prompt="Translate this text",
    model="different-model",
    thinking_mode="on",
    cache=True
)

# Parse response
json_response = parse_sealion_json(completion)
"""

import json
import re
import logging
from models.clients import get_sea_lion_client, get_sea_lion_v4_client, get_sagemaker_predictor
from fastapi import HTTPException


# =============================================================================
# 1. LLM INTERACTION FUNCTION
# =============================================================================

async def call_sea_lion_llm(
    prompt: str,
    model: str = "aisingapore/Llama-SEA-LION-v3.5-70B-R",
    thinking_mode: str = "off",
    cache: bool = False,
    max_retries: int = 2
):
    """
    Centralized function to call Sea Lion LLM with configurable parameters and error handling.

    This function provides a unified interface for all LLM calls across the system,
    with sensible defaults, retry logic, and comprehensive error handling for rate limits.

    Args:
        prompt: The prompt to send to the LLM (required)
        model: The model to use (default: "aisingapore/Llama-SEA-LION-v3.5-70B-R")
        thinking_mode: Thinking mode setting - "on" or "off" (default: "off")
        cache: Whether to enable caching (default: False)
        max_retries: Maximum number of retries for failed requests (default: 2)

    Returns:
        The LLM completion response object

    Raises:
        HTTPException: When Sea-Lion API is not responding or rate limited

    Example:
        completion = await call_sea_lion_llm(
            prompt="Analyze this email for scam indicators",
            thinking_mode="off",
            cache=False
        )
    """
    logger = logging.getLogger(__name__)
    
    for attempt in range(max_retries + 1):
        try:
            logger.info("🦁 Calling Sea-Lion API for comprehensive analysis")
            
            client = get_sea_lion_client()
            
            completion = client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                extra_body={
                    "chat_template_kwargs": {
                        "thinking_mode": thinking_mode
                    },
                    "cache": {
                        "no-cache": not cache
                    }
                },
            )
            
            logger.info("✅ Sea-Lion API comprehensive analysis successful")
            return completion
            
        except Exception as e:
            error_message = str(e).lower()
            
            # Check for rate limit errors
            if any(term in error_message for term in ['rate limit', '429', 'too many requests', 'quota']):
                logger.warning(f"⚠️ Sea-Lion API rate limit hit (attempt {attempt + 1}/{max_retries + 1})")
                if attempt < max_retries:
                    logger.info("🔄 Retrying Sea-Lion API call...")
                    continue
                else:
                    logger.error("❌ Sea-Lion API rate limit exceeded. Max retries reached.")
                    raise HTTPException(
                        status_code=429, 
                        detail="Sea-Lion API is currently rate limited (10 requests/minute). Please wait a moment and try again. This is a temporary limitation from the AI service provider."
                    )
            
            # Check for timeout errors
            elif any(term in error_message for term in ['timeout', 'connection', 'network']):
                logger.warning(f"⚠️ Sea-Lion API connection issue (attempt {attempt + 1}/{max_retries + 1}): {error_message}")
                if attempt < max_retries:
                    logger.info("🔄 Retrying Sea-Lion API call...")
                    continue
                else:
                    logger.error("❌ Sea-Lion API connection failed. Max retries reached.")
                    raise HTTPException(
                        status_code=503, 
                        detail="Sea-Lion AI service is currently not responding. This may be due to network issues or the service being temporarily unavailable. Please try again later."
                    )
            
            # Check for authentication errors
            elif any(term in error_message for term in ['unauthorized', 'authentication', 'api key', 'forbidden']):
                logger.error(f"❌ Sea-Lion API authentication error: {error_message}")
                raise HTTPException(
                    status_code=401, 
                    detail="Sea-Lion API authentication failed. The API key may be invalid or expired. Please check your Sea-Lion API configuration."
                )
            
            # Generic API error
            else:
                logger.warning(f"⚠️ Sea-Lion API error (attempt {attempt + 1}/{max_retries + 1}): {error_message}")
                if attempt < max_retries:
                    logger.info("🔄 Retrying Sea-Lion API call...")
                    continue
                else:
                    logger.error(f"❌ Sea-Lion API failed after {max_retries + 1} attempts: {error_message}")
                    raise HTTPException(
                        status_code=502, 
                        detail=f"Sea-Lion AI service encountered an error: {str(e)}. The analysis could not be completed. Please try again or contact support if the issue persists."
                    )
    
    # This should never be reached, but just in case
    raise HTTPException(
        status_code=500, 
        detail="Unexpected error occurred while calling Sea-Lion API. Please try again."
    )


# =============================================================================
# 1.2. SEA-LION V4 LLM INTERACTION FUNCTION
# =============================================================================

async def call_sea_lion_v4_llm(
    prompt: str,
    model: str = "aisingapore/Gemma-SEA-LION-v4-27B-IT",
    cache: bool = False,
    max_retries: int = 2
):
    """
    Centralized function to call Sea Lion v4 LLM with configurable parameters and error handling.

    This function provides a unified interface for all Sea Lion v4 LLM calls across the system,
    with sensible defaults, retry logic, and comprehensive error handling for rate limits.

    Args:
        prompt: The prompt to send to the LLM (required)
        model: The model to use (default: "aisingapore/Gemma-SEA-LION-v4-27B-IT")
        cache: Whether to enable caching (default: False)
        max_retries: Maximum number of retries for failed requests (default: 2)

    Returns:
        The LLM completion response object

    Raises:
        HTTPException: When Sea-Lion v4 API is not responding or rate limited

    Example:
        completion = await call_sea_lion_v4_llm(
            prompt="Analyze this email for scam indicators",
            cache=False
        )
    """
    logger = logging.getLogger(__name__)
    
    for attempt in range(max_retries + 1):
        try:
            logger.info("🦁 Calling Sea-Lion v4 API for comprehensive analysis")
            
            client = get_sea_lion_v4_client()
            
            completion = client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                extra_body={
                    "cache": {
                        "no-cache": not cache
                    }
                },
            )
            
            logger.info("✅ Sea-Lion v4 API comprehensive analysis successful")
            return completion
            
        except Exception as e:
            error_message = str(e).lower()
            
            # Check for rate limit errors
            if any(term in error_message for term in ['rate limit', '429', 'too many requests', 'quota']):
                logger.warning(f"⚠️ Sea-Lion v4 API rate limit hit (attempt {attempt + 1}/{max_retries + 1})")
                if attempt < max_retries:
                    logger.info("🔄 Retrying Sea-Lion v4 API call...")
                    continue
                else:
                    logger.error("❌ Sea-Lion v4 API rate limit exceeded. Max retries reached.")
                    raise HTTPException(
                        status_code=429, 
                        detail="Sea-Lion v4 API is currently rate limited (10 requests/minute). Please wait a moment and try again. This is a temporary limitation from the AI service provider."
                    )
            
            # Check for timeout errors
            elif any(term in error_message for term in ['timeout', 'connection', 'network']):
                logger.warning(f"⚠️ Sea-Lion v4 API connection issue (attempt {attempt + 1}/{max_retries + 1}): {error_message}")
                if attempt < max_retries:
                    logger.info("🔄 Retrying Sea-Lion v4 API call...")
                    continue
                else:
                    logger.error("❌ Sea-Lion v4 API connection failed. Max retries reached.")
                    raise HTTPException(
                        status_code=503, 
                        detail="Sea-Lion v4 AI service is currently not responding. This may be due to network issues or the service being temporarily unavailable. Please try again later."
                    )
            
            # Check for authentication errors
            elif any(term in error_message for term in ['unauthorized', 'authentication', 'api key', 'forbidden']):
                logger.error(f"❌ Sea-Lion v4 API authentication error: {error_message}")
                raise HTTPException(
                    status_code=401, 
                    detail="Sea-Lion v4 API authentication failed. The API key may be invalid or expired. Please check your Sea-Lion API configuration."
                )
            
            # Generic API error
            else:
                logger.warning(f"⚠️ Sea-Lion v4 API error (attempt {attempt + 1}/{max_retries + 1}): {error_message}")
                if attempt < max_retries:
                    logger.info("🔄 Retrying Sea-Lion v4 API call...")
                    continue
                else:
                    logger.error(f"❌ Sea-Lion v4 API failed after {max_retries + 1} attempts: {error_message}")
                    raise HTTPException(
                        status_code=502, 
                        detail=f"Sea-Lion v4 AI service encountered an error: {str(e)}. The analysis could not be completed. Please try again or contact support if the issue persists."
                    )
    
    # This should never be reached, but just in case
    raise HTTPException(
        status_code=500, 
        detail="Unexpected error occurred while calling Sea-Lion v4 API. Please try again."
    )


# =============================================================================
# 1.3. SAGEMAKER SEA-LION LLM INTERACTION FUNCTION
# =============================================================================

async def call_sagemaker_sealion_llm(
    prompt: str,
    max_tokens: int = 500,
    temperature: float = 0.1,
    top_p: float = 0.9,
    max_retries: int = 2
):
    """
    Centralized function to call SageMaker-hosted SeaLion v4 LLM with configurable parameters and error handling.

    This function provides a unified interface for all SageMaker SeaLion v4 LLM calls,
    with sensible defaults, retry logic, and comprehensive error handling.

    Args:
        prompt: The prompt to send to the LLM (required)
        max_tokens: Maximum tokens to generate (default: 500)
        temperature: Temperature for response generation (default: 0.1)  
        top_p: Top-p sampling parameter (default: 0.9)
        max_retries: Maximum number of retries for failed requests (default: 2)

    Returns:
        The SageMaker response object

    Raises:
        HTTPException: When SageMaker API is not responding or encounters errors

    Example:
        response = await call_sagemaker_sealion_llm(
            prompt="Analyze this email for scam indicators",
            max_tokens=500,
            temperature=0.1
        )
    """
    logger = logging.getLogger(__name__)
    
    for attempt in range(max_retries + 1):
        try:
            logger.info("🦁 Calling SageMaker SeaLion v4 endpoint for comprehensive analysis")
            
            predictor = get_sagemaker_predictor()
            
            # Prepare payload according to the test.py format
            payload = {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": prompt
                            }
                        ]
                    }
                ],
                "max_tokens": max_tokens,
                "temperature": temperature,
                "top_p": top_p,
            }
            
            response = predictor.predict(payload)
            
            logger.info("✅ SageMaker SeaLion v4 endpoint analysis successful")
            return response
            
        except Exception as e:
            error_message = str(e).lower()
            
            # Check for AWS/SageMaker specific errors
            if any(term in error_message for term in ['throttling', 'rate limit', 'throttled']):
                logger.warning(f"⚠️ SageMaker endpoint throttling (attempt {attempt + 1}/{max_retries + 1})")
                if attempt < max_retries:
                    logger.info("🔄 Retrying SageMaker endpoint call...")
                    continue
                else:
                    logger.error("❌ SageMaker endpoint throttling exceeded. Max retries reached.")
                    raise HTTPException(
                        status_code=429, 
                        detail="SageMaker SeaLion v4 endpoint is currently throttled. Please wait a moment and try again."
                    )
            
            # Check for timeout errors
            elif any(term in error_message for term in ['timeout', 'connection', 'network', 'endpoint']):
                logger.warning(f"⚠️ SageMaker endpoint connection issue (attempt {attempt + 1}/{max_retries + 1}): {error_message}")
                if attempt < max_retries:
                    logger.info("🔄 Retrying SageMaker endpoint call...")
                    continue
                else:
                    logger.error("❌ SageMaker endpoint connection failed. Max retries reached.")
                    raise HTTPException(
                        status_code=503, 
                        detail="SageMaker SeaLion v4 endpoint is currently not responding. This may be due to network issues or the endpoint being temporarily unavailable. Please try again later."
                    )
            
            # Check for authentication/permission errors
            elif any(term in error_message for term in ['access denied', 'unauthorized', 'credentials', 'forbidden']):
                logger.error(f"❌ SageMaker endpoint authentication error: {error_message}")
                raise HTTPException(
                    status_code=401, 
                    detail="SageMaker endpoint authentication failed. Please check your AWS credentials and SageMaker endpoint permissions."
                )
            
            # Generic SageMaker error
            else:
                logger.warning(f"⚠️ SageMaker endpoint error (attempt {attempt + 1}/{max_retries + 1}): {error_message}")
                if attempt < max_retries:
                    logger.info("🔄 Retrying SageMaker endpoint call...")
                    continue
                else:
                    logger.error(f"❌ SageMaker endpoint failed after {max_retries + 1} attempts: {error_message}")
                    raise HTTPException(
                        status_code=502, 
                        detail=f"SageMaker SeaLion v4 endpoint encountered an error: {str(e)}. The analysis could not be completed. Please try again or contact support if the issue persists."
                    )
    
    # This should never be reached, but just in case
    raise HTTPException(
        status_code=500, 
        detail="Unexpected error occurred while calling SageMaker SeaLion v4 endpoint. Please try again."
    )


# =============================================================================
# 1.4. SAGEMAKER MULTIMODAL SEA-LION LLM INTERACTION FUNCTION
# =============================================================================

async def call_sagemaker_sealion_multimodal_llm(
    prompt: str,
    base64_image: str,
    max_tokens: int = 1500,
    temperature: float = 0.6,
    top_p: float = 0.9,
    max_retries: int = 2
):
    """
    Centralized function to call SageMaker-hosted SeaLion v4 LLM with multimodal support (text + image).

    This function provides a unified interface for multimodal SageMaker SeaLion v4 LLM calls,
    with sensible defaults, retry logic, and comprehensive error handling.

    Args:
        prompt: The text prompt to send to the LLM (required)
        base64_image: Base64 encoded image string (required)
        max_tokens: Maximum tokens to generate (default: 1500)
        temperature: Temperature for response generation (default: 0.6)  
        top_p: Top-p sampling parameter (default: 0.9)
        max_retries: Maximum number of retries for failed requests (default: 2)

    Returns:
        The SageMaker response object

    Raises:
        HTTPException: When SageMaker API is not responding or encounters errors

    Example:
        response = await call_sagemaker_sealion_multimodal_llm(
            prompt="Analyze this social media post for scam indicators",
            base64_image="iVBORw0KGgoAAAANSUhEUgAA...",
            max_tokens=1500,
            temperature=0.6
        )
    """
    logger = logging.getLogger(__name__)
    
    for attempt in range(max_retries + 1):
        try:
            logger.info("🦁 Calling SageMaker SeaLion v4 endpoint for multimodal analysis")
            
            predictor = get_sagemaker_predictor()
            
            # Prepare multimodal payload according to the test-multimodal.py format
            payload = {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{base64_image}"
                                }
                            },
                            {
                                "type": "text",
                                "text": prompt
                            }
                        ]
                    }
                ],
                "max_tokens": max_tokens,
                "temperature": temperature,
                "top_p": top_p,
            }
            
            response = predictor.predict(payload)
            
            logger.info("✅ SageMaker SeaLion v4 multimodal endpoint analysis successful")
            return response
            
        except Exception as e:
            error_message = str(e).lower()
            
            # Check for AWS/SageMaker specific errors
            if any(term in error_message for term in ['throttling', 'rate limit', 'throttled']):
                logger.warning(f"⚠️ SageMaker multimodal endpoint throttling (attempt {attempt + 1}/{max_retries + 1})")
                if attempt < max_retries:
                    logger.info("🔄 Retrying SageMaker multimodal endpoint call...")
                    continue
                else:
                    logger.error("❌ SageMaker multimodal endpoint throttling exceeded. Max retries reached.")
                    raise HTTPException(
                        status_code=429, 
                        detail="SageMaker SeaLion v4 multimodal endpoint is currently throttled. Please wait a moment and try again."
                    )
            
            # Check for timeout errors
            elif any(term in error_message for term in ['timeout', 'connection', 'network', 'endpoint']):
                logger.warning(f"⚠️ SageMaker multimodal endpoint connection issue (attempt {attempt + 1}/{max_retries + 1}): {error_message}")
                if attempt < max_retries:
                    logger.info("🔄 Retrying SageMaker multimodal endpoint call...")
                    continue
                else:
                    logger.error("❌ SageMaker multimodal endpoint connection failed. Max retries reached.")
                    raise HTTPException(
                        status_code=503, 
                        detail="SageMaker SeaLion v4 multimodal endpoint is currently not responding. This may be due to network issues or the endpoint being temporarily unavailable. Please try again later."
                    )
            
            # Check for authentication/permission errors
            elif any(term in error_message for term in ['access denied', 'unauthorized', 'credentials', 'forbidden']):
                logger.error(f"❌ SageMaker multimodal endpoint authentication error: {error_message}")
                raise HTTPException(
                    status_code=401, 
                    detail="SageMaker multimodal endpoint authentication failed. Please check your AWS credentials and SageMaker endpoint permissions."
                )
            
            # Generic SageMaker error
            else:
                logger.warning(f"⚠️ SageMaker multimodal endpoint error (attempt {attempt + 1}/{max_retries + 1}): {error_message}")
                if attempt < max_retries:
                    logger.info("🔄 Retrying SageMaker multimodal endpoint call...")
                    continue
                else:
                    logger.error(f"❌ SageMaker multimodal endpoint failed after {max_retries + 1} attempts: {error_message}")
                    raise HTTPException(
                        status_code=502, 
                        detail=f"SageMaker SeaLion v4 multimodal endpoint encountered an error: {str(e)}. The analysis could not be completed. Please try again or contact support if the issue persists."
                    )
    
    # This should never be reached, but just in case
    raise HTTPException(
        status_code=500, 
        detail="Unexpected error occurred while calling SageMaker SeaLion v4 multimodal endpoint. Please try again."
    )


# =============================================================================
# 2. RESPONSE PARSING FUNCTION
# =============================================================================

def parse_sealion_json(resp):
    """
    Extract and parse JSON from Sea Lion LLM responses.

    This function handles multiple JSON formats that the LLM might return:
    1. Plain JSON: {"key": "value"}
    2. Fenced JSON blocks: ```json {"key": "value"} ```
    3. Balanced braces: Extracts first complete {...} object

    Args:
        resp: The Sea Lion LLM completion response object

    Returns:
        dict: Parsed JSON object

    Raises:
        ValueError: If no valid JSON object can be found in the response
    """
    # 1) get the text
    content = resp.choices[0].message.content

    # 2) try plain JSON first
    try:
        return json.loads(content)
    except Exception:
        pass

    # 3) try fenced ```json ... ``` block
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, flags=re.S)
    if m:
        return json.loads(m.group(1))

    # 4) fall back: extract first balanced {...}
    start = content.find("{")
    if start == -1:
        raise ValueError("No JSON object found in LLM output")

    depth = 0
    end = None
    for i, ch in enumerate(content[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end is None:
        raise ValueError("Unbalanced JSON braces in LLM output")

    return json.loads(content[start:end])


def parse_sagemaker_json(resp):
    """
    Extract and parse JSON from SageMaker SeaLion LLM responses.

    This function handles the SageMaker response format, which differs from the Sea Lion API.
    The SageMaker response structure contains choices[0]['message']['content'].

    Args:
        resp: The SageMaker LLM prediction response object

    Returns:
        dict: Parsed JSON object

    Raises:
        ValueError: If no valid JSON object can be found in the response
    """
    # 1) get the text from SageMaker response format
    content = resp['choices'][0]['message']['content']

    # 2) try plain JSON first
    try:
        return json.loads(content)
    except Exception:
        pass

    # 3) try fenced ```json ... ``` block
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, flags=re.S)
    if m:
        return json.loads(m.group(1))

    # 4) fall back: extract first balanced {...}
    start = content.find("{")
    if start == -1:
        raise ValueError("No JSON object found in SageMaker LLM output")

    depth = 0
    end = None
    for i, ch in enumerate(content[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end is None:
        raise ValueError("Unbalanced JSON braces in SageMaker LLM output")

    return json.loads(content[start:end])
