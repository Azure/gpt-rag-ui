import os
import logging
from typing import Optional

import httpx
from azure.identity import ManagedIdentityCredential, AzureCliCredential, ChainedTokenCredential

from dependencies import get_config

logger = logging.getLogger("gpt_rag_ui.orchestrator_client")
config = get_config()


def _bool_env(value: Optional[str]) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


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


def _build_orchestrator_url() -> tuple[str, dict]:
    """Return (url, context) where context is safe for logs."""
    orchestrator_app_id = "orchestrator"
    base_url = _get_orchestrator_base_url()
    if base_url:
        url = f"{base_url}/orchestrator"
        return url, {"mode": "direct", "base_url": base_url, "dapr_port": None, "app_id": orchestrator_app_id}

    dapr_port = _get_config_value("DAPR_HTTP_PORT", default="3500")
    url = f"http://127.0.0.1:{dapr_port}/v1.0/invoke/{orchestrator_app_id}/method/orchestrator"
    return url, {"mode": "dapr", "base_url": None, "dapr_port": str(dapr_port), "app_id": orchestrator_app_id}


def _headers_summary(headers: dict) -> dict:
    # Never log secrets. Only presence flags.
    return {
        "has_dapr_token": "dapr-api-token" in headers,
        "has_api_key": "X-API-KEY" in headers,
        "has_bearer_token": "Authorization" in headers,
    }


def _hint_for_connect_error(context: dict) -> str:
    if context.get("mode") == "dapr":
        return (
            "Connection failed to local Dapr sidecar. Ensure Dapr is running and listening on "
            f"127.0.0.1:{context.get('dapr_port')} and that the orchestrator app-id 'orchestrator' is registered. "
            "If you are not using Dapr locally, set ORCHESTRATOR_BASE_URL to the orchestrator HTTP endpoint."
        )
    return (
        "Connection failed to orchestrator base URL. Verify ORCHESTRATOR_BASE_URL, network access, and that the "
        "orchestrator service is healthy and reachable from this container."
    )


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
    
    url, target_context = _build_orchestrator_url()

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

    logger.info(
        "Invoking orchestrator: question_id=%s conversation_id=%s mode=%s url=%s headers=%s",
        question_id or "n/a",
        conversation_id or "new",
        target_context.get("mode"),
        url,
        _headers_summary(headers),
    )

    timeout = httpx.Timeout(connect=10.0, read=None, write=30.0, pool=10.0)
    # Invoke through Dapr sidecar and stream response
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            async with client.stream("POST", url, json=payload, headers=headers) as response:
                if response.status_code >= 400:
                    body = await response.aread()
                    body_text = body.decode(errors="ignore")
                    snippet = (body_text[:2000] + "...") if len(body_text) > 2000 else body_text
                    raise RuntimeError(
                        f"Orchestrator returned HTTP {response.status_code} {response.reason_phrase}. "
                        f"url={url} details={snippet}"
                    )
                async for chunk in response.aiter_text():
                    if chunk:
                        yield chunk
    except httpx.ConnectError as e:
        hint = _hint_for_connect_error(target_context)
        logger.error(
            "Orchestrator connection failed: question_id=%s url=%s mode=%s hint=%s",
            question_id or "n/a",
            url,
            target_context.get("mode"),
            hint,
        )
        raise RuntimeError(f"Orchestrator connection failed. {hint}") from e
    except httpx.TimeoutException as e:
        logger.error(
            "Orchestrator timeout: question_id=%s url=%s mode=%s",
            question_id or "n/a",
            url,
            target_context.get("mode"),
        )
        raise RuntimeError(f"Orchestrator request timed out. url={url}") from e
    except httpx.HTTPError as e:
        # Covers protocol errors, invalid URL, TLS issues, etc.
        logger.exception(
            "Orchestrator HTTP error: question_id=%s url=%s mode=%s",
            question_id or "n/a",
            url,
            target_context.get("mode"),
        )
        raise RuntimeError(f"Orchestrator HTTP error. url={url} error={e}") from e



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
    url, target_context = _build_orchestrator_url()

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
    
    logger.info(
        "Sending feedback to orchestrator: question_id=%s conversation_id=%s mode=%s url=%s headers=%s",
        question_id or "n/a",
        conversation_id or "new",
        target_context.get("mode"),
        url,
        _headers_summary(headers),
    )

    timeout = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=headers)
            if response.status_code >= 400:
                body_text = response.text
                snippet = (body_text[:2000] + "...") if len(body_text) > 2000 else body_text
                raise RuntimeError(
                    f"Orchestrator feedback call failed (HTTP {response.status_code} {response.reason_phrase}). "
                    f"url={url} details={snippet}"
                )
            return True
    except httpx.ConnectError as e:
        hint = _hint_for_connect_error(target_context)
        logger.error(
            "Orchestrator connection failed (feedback): question_id=%s url=%s mode=%s hint=%s",
            question_id or "n/a",
            url,
            target_context.get("mode"),
            hint,
        )
        raise RuntimeError(f"Orchestrator connection failed. {hint}") from e
    except httpx.TimeoutException as e:
        logger.error(
            "Orchestrator timeout (feedback): question_id=%s url=%s mode=%s",
            question_id or "n/a",
            url,
            target_context.get("mode"),
        )
        raise RuntimeError(f"Orchestrator request timed out. url={url}") from e
    except httpx.HTTPError as e:
        logger.exception(
            "Orchestrator HTTP error (feedback): question_id=%s url=%s mode=%s",
            question_id or "n/a",
            url,
            target_context.get("mode"),
        )
        raise RuntimeError(f"Orchestrator HTTP error. url={url} error={e}") from e