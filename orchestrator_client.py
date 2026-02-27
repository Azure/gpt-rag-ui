import os
import logging
import base64
import json
import re
from typing import Optional

import httpx
from azure.identity import ManagedIdentityCredential, AzureCliCredential, ChainedTokenCredential

from dependencies import get_config

logger = logging.getLogger("gpt_rag_ui.orchestrator_client")
config = get_config()


_SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "dapr-api-token",
    "x-api-key",
}

_SENSITIVE_JSON_KEY_RE = re.compile(r"(authorization|token|secret|password|api[_-]?key|cookie)", re.IGNORECASE)


def _mask_secret(value: object, *, keep_start: int = 6, keep_end: int = 4) -> str:
    if value is None:
        return "<empty>"
    text = str(value)
    stripped = text.strip()
    if not stripped:
        return "<empty>"
    if len(stripped) <= keep_start + keep_end + 3:
        return "<redacted>"
    return f"{stripped[:keep_start]}…{stripped[-keep_end:]}"


def _sanitize_for_log(obj: object, *, depth: int = 0, max_depth: int = 6) -> object:
    """Return a log-safe representation: redacts secrets and truncates very large values."""
    if depth > max_depth:
        return "<max-depth>"

    if obj is None or isinstance(obj, (bool, int, float)):
        return obj

    if isinstance(obj, str):
        s = obj
        if len(s) > 800:
            return s[:800] + "…"
        return s

    if isinstance(obj, (list, tuple)):
        items = list(obj)
        if len(items) > 50:
            return [_sanitize_for_log(x, depth=depth + 1, max_depth=max_depth) for x in items[:50]] + [
                f"<truncated: {len(items) - 50} more items>"
            ]
        return [_sanitize_for_log(x, depth=depth + 1, max_depth=max_depth) for x in items]

    if isinstance(obj, dict):
        sanitized: dict = {}
        for key, value in obj.items():
            key_str = str(key)
            if _SENSITIVE_JSON_KEY_RE.search(key_str):
                sanitized[key_str] = "<redacted>"
            else:
                sanitized[key_str] = _sanitize_for_log(value, depth=depth + 1, max_depth=max_depth)
        return sanitized

    # Fallback for unknown objects
    return str(obj)


def _format_outgoing_request_debug(*, method: str, url: str, headers: dict, json_body: object) -> str:
    safe_headers = {}
    for k, v in (headers or {}).items():
        key = str(k)
        if key.lower() in _SENSITIVE_HEADER_KEYS:
            # Keep a hint of token shape without leaking the full value.
            if key.lower() == "authorization" and isinstance(v, str) and v.lower().startswith("bearer "):
                token = v[7:].strip()
                safe_headers[key] = f"Bearer {_mask_secret(token)}"
            else:
                safe_headers[key] = _mask_secret(v)
        else:
            safe_headers[key] = str(v)

    payload = {
        "method": method,
        "url": url,
        "headers": safe_headers,
        "json": _sanitize_for_log(json_body),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)


def _decode_jwt_unverified(token: str) -> dict | None:
    """Decode JWT payload without verifying signature.

    Debug-only helper. Never use this to authorize.
    """

    try:
        parts = (token or "").split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
        data = json.loads(payload.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _access_token_debug_summary(access_token: str) -> dict:
    claims = _decode_jwt_unverified(access_token) or {}
    aud = claims.get("aud")
    if isinstance(aud, list):
        aud_value = ",".join(str(x) for x in aud)
    else:
        aud_value = str(aud) if aud is not None else None

    def _short(value: object) -> str:
        s = str(value or "")
        if len(s) <= 10:
            return s
        return f"{s[:4]}…{s[-4:]}"

    return {
        "aud": aud_value,
        "tid": _short(claims.get("tid")) if claims.get("tid") else None,
        "oid": _short(claims.get("oid")) if claims.get("oid") else None,
        "iss": claims.get("iss"),
        "scp": claims.get("scp"),
        "ver": claims.get("ver"),
    }


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


def _get_dapr_api_token() -> Optional[str]:
    # Prefer process environment (VS Code launch.json / container env), then App Configuration.
    value = os.getenv("DAPR_API_TOKEN")
    if value:
        return value
    value = _get_config_value("DAPR_API_TOKEN", default=None, allow_none=True)
    return value if value else None


def _get_orchestrator_base_url() -> Optional[str]:
    # Prefer the process environment (e.g., VS Code launch.json / container env)
    # so local debug doesn't depend on App Configuration for this one value.
    value = os.getenv("ORCHESTRATOR_BASE_URL")
    if value:
        return value.rstrip("/")

    value = _get_config_value("ORCHESTRATOR_BASE_URL", default=None, allow_none=True)
    if value:
        return str(value).rstrip("/")
    return None


def _build_orchestrator_url() -> tuple[str, dict]:
    """Return (url, context) where context is safe for logs."""
    orchestrator_app_id = "orchestrator"
    base_url = _get_orchestrator_base_url()
    if base_url:
        # Allow callers to pass either the service root ("https://host")
        # or the full endpoint ("https://host/orchestrator").
        url = base_url if base_url.endswith("/orchestrator") else f"{base_url}/orchestrator"
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

    # Prepare headers: content-type and optional Dapr token
    headers = {
        "Content-Type": "application/json",
    }

    # The orchestrator endpoint enforces the same shared secret used by the Dapr sidecar.
    # Include it whenever present (both 'dapr' and 'direct' modes).
    dapr_token = _get_dapr_api_token()
    if dapr_token:
        headers["dapr-api-token"] = dapr_token
    else:
        logger.debug(
            "DAPR_API_TOKEN not set; omitting 'dapr-api-token' header (expected in ACA; set only for local enforced sidecar)"
        )

    api_key = _get_config_value("ORCHESTRATOR_APP_APIKEY", default="")
    if api_key:
        headers["X-API-KEY"] = api_key
    
    # Add Authorization header with Bearer token
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    if access_token and logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "Orchestrator bearer token claims (unverified): question_id=%s conversation_id=%s %s",
            question_id or "n/a",
            conversation_id or "new",
            _access_token_debug_summary(access_token),
        )

    # INFO-level auth health log (never prints secrets)
    logger.info(
        "Orchestrator request auth health: question_id=%s conversation_id=%s mode=%s has_access_token=%s access_token_len=%s has_authorization_header=%s",
        question_id or "n/a",
        conversation_id or "new",
        target_context.get("mode"),
        bool(access_token),
        (len(str(access_token)) if access_token else 0),
        ("Authorization" in headers),
    )
    
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

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "Outgoing orchestrator request (sanitized):\n%s",
            _format_outgoing_request_debug(method="POST", url=url, headers=headers, json_body=payload),
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

    # Prepare headers: content-type and optional Dapr token
    headers = {
        "Content-Type": "application/json",
    }

    dapr_token = _get_dapr_api_token()
    if dapr_token:
        headers["dapr-api-token"] = dapr_token
    else:
        logger.debug(
            "DAPR_API_TOKEN not set; omitting 'dapr-api-token' header (expected in ACA; set only for local enforced sidecar)"
        )

    api_key = _get_config_value("ORCHESTRATOR_APP_APIKEY", default="")
    if api_key:
        headers["X-API-KEY"] = api_key
    
    # Add Authorization header with Bearer token
    access_token = auth_info.get('access_token')
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    if access_token and logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "Orchestrator bearer token claims (unverified): question_id=%s conversation_id=%s %s",
            question_id or "n/a",
            conversation_id or "new",
            _access_token_debug_summary(access_token),
        )

    logger.info(
        "Orchestrator feedback auth health: question_id=%s conversation_id=%s mode=%s has_access_token=%s access_token_len=%s has_authorization_header=%s",
        question_id or "n/a",
        conversation_id or "new",
        target_context.get("mode"),
        bool(access_token),
        (len(str(access_token)) if access_token else 0),
        ("Authorization" in headers),
    )

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

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "Outgoing orchestrator feedback request (sanitized):\n%s",
            _format_outgoing_request_debug(method="POST", url=url, headers=headers, json_body=payload),
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