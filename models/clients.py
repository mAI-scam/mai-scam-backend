"""
External service clients configuration and initialization.
"""
import os
from typing import Optional
from openai import OpenAI
from mistralai import Mistral
from fastapi import HTTPException


class ClientError(Exception):
    """Custom exception for client initialization errors."""
    pass


class AIClients:
    """Singleton class to manage AI service clients."""
    
    _sea_lion_client: Optional[OpenAI] = None
    _mistral_client: Optional[Mistral] = None
    
    @classmethod
    def get_sea_lion_client(cls) -> OpenAI:
        """Get or create Sea-Lion AI client."""
        if cls._sea_lion_client is None:
            api_key = os.getenv("SEA_LION_API_KEY")
            if not api_key:
                raise ClientError("SEA_LION_API_KEY environment variable not configured")
            
            cls._sea_lion_client = OpenAI(
                api_key=api_key,
                base_url="https://api.sea-lion.ai/v1"
            )
        
        return cls._sea_lion_client
    
    @classmethod
    def get_mistral_client(cls) -> Mistral:
        """Get or create Mistral AI client."""
        if cls._mistral_client is None:
            api_key = os.getenv("MISTRAL_API_KEY")
            if not api_key:
                raise ClientError("MISTRAL_API_KEY environment variable not configured")
            
            cls._mistral_client = Mistral(api_key=api_key)
        
        return cls._mistral_client
    
    @classmethod
    def reset_clients(cls):
        """Reset all clients (useful for testing)."""
        cls._sea_lion_client = None
        cls._mistral_client = None


# Convenience functions for backward compatibility
def get_sea_lion_client() -> OpenAI:
    """Get Sea-Lion AI client instance."""
    try:
        return AIClients.get_sea_lion_client()
    except ClientError as e:
        raise HTTPException(status_code=500, detail=str(e))


def get_mistral_client() -> Mistral:
    """Get Mistral AI client instance."""
    try:
        return AIClients.get_mistral_client()
    except ClientError as e:
        raise HTTPException(status_code=500, detail=str(e)) 