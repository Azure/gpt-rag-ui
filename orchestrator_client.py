import os
import logging
from typing import Optional

import httpx
from azure.identity import ManagedIdentityCredential, AzureCliCredential, ChainedTokenCredential

from dependencies import get_config

logger = logging.getLogger("gpt_rag_ui.orchestrator_client")
config = get_config()


def _get_config_value(key: str, *, default=None, allow_none: bool = False):
    try:
        return config.get_value(key, default=default, allow_none=allow_none)
    except Exception:
        if allow_none or default is not None:
            logger.debug("Configuration key '%s' not found; using default", key)
        else:
            logger.exception("Failed to read configuration value for key '%s'", key)
        return default


def _get_orchestrator_base_url() -> Optional[str]:
    value = _get_config_value("ORCHESTRATOR_BASE_URL", default=None, allow_none=True)
    if value:
        return value.rstrip("/")
    return None


# Obtain an Azure AD token via Managed Identity or Azure CLI credentials
def get_managed_identity_token():
    credential = ChainedTokenCredential(
        ManagedIdentityCredential(),
        AzureCliCredential()
    )
    return credential.get_token("https://management.azure.com/.default").token


async def call_orchestrator_stream(conversation_id: str, question: str, auth_info: dict, question_id: str | None = None):    
    # Get access token from auth info
    access_token = auth_info.get('access_token')
    
    # Read Dapr settings and target app ID
    orchestrator_app_id = "orchestrator"
    base_url = _get_orchestrator_base_url()
    if base_url:
        url = f"{base_url}/orchestrator"
    else:
        dapr_port = _get_config_value("DAPR_HTTP_PORT", default="3500")
        url = (
            f"http://127.0.0.1:{dapr_port}/v1.0/invoke/{orchestrator_app_id}/method/orchestrator"
        )

    # Read the Dapr sidecar API token, favoring environment variables to avoid config churn
    dapr_token = os.getenv("DAPR_API_TOKEN")
    if dapr_token is None:
        dapr_token = _get_config_value("DAPR_API_TOKEN", default=None, allow_none=True)
    if not dapr_token:
        logger.debug("DAPR_API_TOKEN is not set; proceeding without Dapr token header")

    # Prepare headers: content-type and optional Dapr token
    headers = {
        "Content-Type": "application/json",
    }
    if dapr_token:
        headers["dapr-api-token"] = dapr_token

    api_key = _get_config_value("ORCHESTRATOR_APP_APIKEY", default="")
    if api_key:
        headers["X-API-KEY"] = api_key
    
    # Add Authorization header with Bearer token
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    
    payload = {
        "conversation_id": conversation_id,
        "question": question, #for backward compatibility
        "ask": question,
    }

    if question_id:
        payload["question_id"] = question_id


    # Invoke through Dapr sidecar and stream response
    async with httpx.AsyncClient(timeout=None) as client:
        async with client.stream("POST", url, json=payload, headers=headers) as response:
            if response.status_code >= 400:
                body = await response.aread()
                raise Exception(
                    f"Error invoking orchestrator (HTTP {response.status_code}): "
                    f"{response.reason_phrase}. Details: {body.decode(errors='ignore')}"
                )
            async for chunk in response.aiter_text():
                if chunk:
                    yield chunk



async def call_orchestrator_for_feedback(
        conversation_id: str,
        question_id: str,
        ask: str,
        is_positive: bool,
        star_rating: Optional[int | str],
        feedback_text: Optional[str],
        auth_info: dict,
    ) -> bool:
    if not question_id:
        logger.warning("call_orchestrator_for_feedback called without question_id; feedback will have null question_id")
    # Read Dapr settings and target app ID
    orchestrator_app_id = "orchestrator"
    base_url = _get_orchestrator_base_url()
    if base_url:
        url = f"{base_url}/orchestrator"
    else:
        dapr_port = _get_config_value("DAPR_HTTP_PORT", default="3500")
        url = (
            f"http://127.0.0.1:{dapr_port}/v1.0/invoke/{orchestrator_app_id}/method/orchestrator"
        )

    # Read the Dapr sidecar API token
    dapr_token = os.getenv("DAPR_API_TOKEN")
    if not dapr_token:
        logger.debug("DAPR_API_TOKEN is not set; proceeding without Dapr token header")

    # Prepare headers: content-type and optional Dapr token
    headers = {
        "Content-Type": "application/json",
    }
    if dapr_token:
        headers["dapr-api-token"] = dapr_token

    api_key = _get_config_value("ORCHESTRATOR_APP_APIKEY", default="")
    if api_key:
        headers["X-API-KEY"] = api_key
    
    # Add Authorization header with Bearer token
    access_token = auth_info.get('access_token')
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    payload = {
        "type": "feedback",
        "conversation_id": conversation_id,
        "question_id": question_id,
        "is_positive": is_positive,
    }
    # Include optional fields only when provided
    if star_rating is not None:
        payload["stars_rating"] = star_rating
    if feedback_text:
        payload["feedback_text"] = feedback_text
    
    async with httpx.AsyncClient(timeout=None) as client:
        response = await client.post(url, json=payload, headers=headers)
        if response.status_code >= 400:
            raise Exception(f"Error calling orchestrator for feedback. HTTP status code: {response.status_code}, status: {response.reason_phrase}")
        return True