from uuid import uuid4
from datetime import datetime as dt
from starlette.concurrency import run_in_threadpool

from models.clients import get_sea_lion_client, get_mongodb_client
from utils.constant import LANGUAGES
from utils.llmUtils import parse_sealion_json
from library.emailPrompts import prompts


async def detect_language(content: str) -> str:
    prompt = prompts["detectLanguage"].format(
        available_languages=str(", ".join(LANGUAGES)),
        content=content,
    )

    client = get_sea_lion_client()

    completion = client.chat.completions.create(
        model="aisingapore/Llama-SEA-LION-v3.5-70B-R",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        extra_body={
            "chat_template_kwargs": {
                "thinking_mode": "off"
            },
            "cache": {
                "no-cache": True
            }
        },
    )

    json_response = parse_sealion_json(completion)

    return json_response["base_language"]


async def analyze_email(title: str, content: str, base_language: str) -> dict:
    prompt = prompts["analyzeEmail"].format(
        language=base_language,
        title=title,
        content=content,
    )

    client = get_sea_lion_client()

    completion = client.chat.completions.create(
        model="aisingapore/Llama-SEA-LION-v3.5-70B-R",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        extra_body={
            "chat_template_kwargs": {
                "thinking_mode": "off"
            },
            "cache": {
                "no-cache": True
            }
        },
    )

    json_response = parse_sealion_json(completion)

    return json_response


async def translate_analysis(base_language_analysis, base_language, target_language) -> dict:
    prompt = prompts["translateAnalysis"].format(
        base_language=base_language,
        target_language=target_language,
        risk_level=base_language_analysis.get('risk_level'),
        analysis=base_language_analysis.get('analysis'),
        recommended_action=base_language_analysis.get('recommended_action'),
    )

    client = get_sea_lion_client()

    completion = client.chat.completions.create(
        model="aisingapore/Llama-SEA-LION-v3.5-70B-R",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        extra_body={
            "chat_template_kwargs": {
                "thinking_mode": "off"
            },
            "cache": {
                "no-cache": True
            }
        },
    )

    json_response = parse_sealion_json(completion)

    return json_response


def prepare_document(title: str, content: str, from_email: str, reply_to_email: str, base_language: str, analysis: dict) -> dict:
    document = {
        "_id": uuid4().hex,
        "created_at": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "title": title,
        "content": content,
        "from_email": from_email,
        "reply_to_email": reply_to_email,
        "base_language": base_language,
        "analysis": analysis
    }

    return document


async def save_to_mongodb(document: dict, db_name: str = "maiscam-db", collection_name: str = "emails"):
    client = get_mongodb_client()

    email_collection = client[db_name][collection_name]

    res = await run_in_threadpool(email_collection.insert_one, document)

    return res.inserted_id
