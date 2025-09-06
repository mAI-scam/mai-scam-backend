"""
External service clients configuration and initialization.
"""
import os
from setting import Setting
from typing import Optional
from openai import OpenAI
from sagemaker.serializers import JSONSerializer
from sagemaker.deserializers import JSONDeserializer
from sagemaker.predictor import Predictor
from sagemaker.session import Session
import boto3

from fastapi import HTTPException

config = Setting()


class ClientError(Exception):
    """Custom exception for client initialization errors."""
    pass


class AIClients:
    """Singleton class to manage AI service clients."""

    _sea_lion_client: Optional[OpenAI] = None
    _sea_lion_v4_client: Optional[OpenAI] = None
    _sagemaker_predictor: Optional[Predictor] = None

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
    def get_sagemaker_predictor(cls) -> Predictor:
        """Get or create SageMaker predictor for SeaLion-v4."""
        if cls._sagemaker_predictor is None:
            # Get AWS credentials from environment variables
            aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
            aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
            aws_region = os.getenv("AWS_REGION")
            endpoint_name = os.getenv("SAGEMAKER_ENDPOINT_NAME") or "gemma-sea-lion-v4-27b-it-250905-0016"
            
            if not all([aws_access_key_id, aws_secret_access_key, aws_region]):
                raise ClientError(
                    "AWS credentials not configured. Please set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION environment variables")

            # Create boto3 session with loaded credentials
            boto_session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=aws_region
            )
            
            # Create SageMaker session with the boto3 session
            sagemaker_session = Session(boto_session=boto_session)
            
            cls._sagemaker_predictor = Predictor(
                endpoint_name=endpoint_name,
                sagemaker_session=sagemaker_session,
                serializer=JSONSerializer(),
                deserializer=JSONDeserializer()
            )
        
        return cls._sagemaker_predictor

    @classmethod
    def reset_clients(cls):
        """Reset all clients (useful for testing)."""
        cls._sea_lion_client = None
        cls._sea_lion_v4_client = None
        cls._sagemaker_predictor = None




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


def get_sagemaker_predictor() -> Predictor:
    """Get SageMaker predictor instance."""
    try:
        return AIClients.get_sagemaker_predictor()
    except ClientError as e:
        raise HTTPException(status_code=500, detail=str(e))




