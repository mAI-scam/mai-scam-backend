"""
LLM Utilities for MAI Scam Detection System

This module provides centralized functions for interacting with the Sea Lion LLM,
including prompt handling, response parsing, and JSON extraction.

TABLE OF CONTENTS:
==================

EXPORTED FUNCTIONS:
------------------
1. call_sea_lion_llm
2. parse_sealion_json

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
from models.clients import get_sea_lion_client
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
            logger.info(f"🦁 Calling Sea-Lion API (attempt {attempt + 1}/{max_retries + 1})")
            
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
            
            logger.info("✅ Sea-Lion API call successful")
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
