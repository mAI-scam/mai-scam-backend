"""
External service clients configuration and initialization.
"""
import os
from setting import Setting
from typing import Optional
from openai import OpenAI

from fastapi import HTTPException

config = Setting()


class ClientError(Exception):
    """Custom exception for client initialization errors."""
    pass


class AIClients:
    """Singleton class to manage AI service clients."""

    _sea_lion_client: Optional[OpenAI] = None
    _sea_lion_v4_client: Optional[OpenAI] = None

    @classmethod
    def get_sea_lion_client(cls) -> OpenAI:
        """Get or create Sea-Lion AI client."""
        if cls._sea_lion_client is None:
            api_key = os.getenv("SEA_LION_API_KEY") or config.get(
                "SEA_LION_API_KEY", "")
            if not api_key:
                raise ClientError(
                    "SEA_LION_API_KEY environment variable not configured")

            cls._sea_lion_client = OpenAI(
                api_key=api_key,
                base_url="https://api.sea-lion.ai/v1"
            )

        return cls._sea_lion_client

    @classmethod
    def get_sea_lion_v4_client(cls) -> OpenAI:
        """Get or create Sea-Lion v4 AI client."""
        if cls._sea_lion_v4_client is None:
            api_key = os.getenv("SEA_LION_API_KEY") or config.get(
                "SEA_LION_API_KEY", "")
            if not api_key:
                raise ClientError(
                    "SEA_LION_API_KEY environment variable not configured")

            cls._sea_lion_v4_client = OpenAI(
                api_key=api_key,
                base_url="https://api.sea-lion.ai/v1"
            )

        return cls._sea_lion_v4_client


    @classmethod
    def reset_clients(cls):
        """Reset all clients (useful for testing)."""
        cls._sea_lion_client = None
        cls._sea_lion_v4_client = None




def get_sea_lion_client() -> OpenAI:
    """Get Sea-Lion AI client instance."""
    try:
        return AIClients.get_sea_lion_client()
    except ClientError as e:
        raise HTTPException(status_code=500, detail=str(e))


def get_sea_lion_v4_client() -> OpenAI:
    """Get Sea-Lion v4 AI client instance."""
    try:
        return AIClients.get_sea_lion_v4_client()
    except ClientError as e:
        raise HTTPException(status_code=500, detail=str(e))




