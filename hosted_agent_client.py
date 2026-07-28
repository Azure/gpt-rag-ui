"""
Client for the Chainlit hosted-agent BFF path (CHAT_BACKEND=hosted_agent).

Implements server-side streaming over the GPT-RAG hosted orchestrator contract:
text deltas, citations, tool activity, errors, cancellation, and
conversation/thread-ID mapping.

All credentials are obtained server-side via managed identity; no tokens or
platform details are ever forwarded from the browser to the backend service.
Per ADR-0001, only the authenticated identity context (principal ID and name)
is propagated in the payload — never raw access tokens.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import AsyncGenerator, Optional

import httpx
from azure.identity import AzureCliCredential, ChainedTokenCredential, ManagedIdentityCredential

from dependencies import get_config
from orchestrator_client import (
    _format_outgoing_request_debug,
    _get_dapr_api_token,
    _headers_summary,
)

logger = logging.getLogger("gpt_rag_ui.hosted_agent_client")
config = get_config()


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class HostedAgentConfigError(Exception):
    """Raised when the hosted-agent configuration is missing or invalid."""


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def _get_hosted_agent_base_url() -> Optional[str]:
    value = os.getenv("HOSTED_AGENT_BASE_URL")
    if value:
        return value.rstrip("/")
    try:
        value = config.get("HOSTED_AGENT_BASE_URL", None, str)
    except Exception:
        logger.debug("HOSTED_AGENT_BASE_URL not found in App Configuration")
        return None
    if value:
        return str(value).rstrip("/")
    return None


def validate_hosted_agent_config() -> None:
    """Validate that the hosted-agent endpoint is configured.

    Raises :exc:`HostedAgentConfigError` with a clear, actionable message when
    the configuration is missing or invalid.  Call this at startup whenever
    ``CHAT_BACKEND=hosted_agent`` so the operator gets an explicit error rather
    than a silent runtime failure on the first request.
    """
    url = _get_hosted_agent_base_url()
    if not url:
        raise HostedAgentConfigError(
            "CHAT_BACKEND is set to 'hosted_agent' but HOSTED_AGENT_BASE_URL is not configured. "
            "Set HOSTED_AGENT_BASE_URL to the hosted orchestrator endpoint in App Configuration "
            "or via the HOSTED_AGENT_BASE_URL environment variable."
        )
    if not url.startswith(("http://", "https://")):
        raise HostedAgentConfigError(
            f"HOSTED_AGENT_BASE_URL must be an absolute HTTP(S) URL, got: {url!r}"
        )


# ---------------------------------------------------------------------------
# SSE parsing
# ---------------------------------------------------------------------------

@dataclass
class HostedAgentEvent:
    """Parsed Server-Sent Event from the hosted orchestrator stream."""

    event_type: str
    data: dict = field(default_factory=dict)


def _parse_sse_block(raw: str) -> Optional[HostedAgentEvent]:
    """Parse a single SSE block (the lines between blank-line separators)."""
    event_type = ""
    data_lines: list[str] = []
    for line in raw.splitlines():
        if line.startswith("event:"):
            event_type = line[len("event:"):].strip()
        elif line.startswith("data:"):
            data_lines.append(line[len("data:"):].strip())
    if not event_type and not data_lines:
        return None
    raw_data = "\n".join(data_lines)
    try:
        data = json.loads(raw_data) if raw_data else {}
    except json.JSONDecodeError:
        data = {"raw": raw_data}
    return HostedAgentEvent(event_type=event_type or "unknown", data=data)


async def _iter_sse_events(
    response: httpx.Response,
) -> AsyncGenerator[HostedAgentEvent, None]:
    """Yield :class:`HostedAgentEvent` objects from an SSE HTTP response."""
    buffer = ""
    async for chunk in response.aiter_text():
        buffer += chunk
        while "\n\n" in buffer:
            block, buffer = buffer.split("\n\n", 1)
            block = block.strip()
            if not block or block.startswith(":"):
                continue
            event = _parse_sse_block(block)
            if event is not None:
                yield event
    # Flush any trailing content that was not terminated with a blank line.
    remaining = buffer.strip()
    if remaining and not remaining.startswith(":"):
        event = _parse_sse_block(remaining)
        if event is not None:
            yield event


# ---------------------------------------------------------------------------
# Auth / headers — server-side only
# ---------------------------------------------------------------------------

def _get_hosted_agent_scope() -> str:
    """Return the Azure resource scope for managed-identity token acquisition."""
    value = os.getenv("HOSTED_AGENT_RESOURCE_SCOPE")
    if value:
        return value
    try:
        value = config.get("HOSTED_AGENT_RESOURCE_SCOPE", None, str)
    except Exception:
        pass
    return value or "https://management.azure.com/.default"


def _get_hosted_agent_api_key() -> str:
    value = os.getenv("HOSTED_AGENT_APP_APIKEY", "")
    if value:
        return value
    try:
        value = config.get("HOSTED_AGENT_APP_APIKEY", "", str) or ""
    except Exception:
        pass
    return value


def _build_hosted_agent_headers(auth_info: dict) -> dict:  # noqa: ARG001
    """Build request headers for the hosted-agent endpoint.

    Uses a server-side managed-identity token.  The user's delegated access
    token is intentionally NOT forwarded — see ADR-0001.  Identity context
    (principal ID and name) is passed in the request payload instead.
    """
    headers: dict = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }

    dapr_token = _get_dapr_api_token()
    if dapr_token:
        headers["dapr-api-token"] = dapr_token

    api_key = _get_hosted_agent_api_key()
    if api_key:
        headers["X-API-KEY"] = api_key

    # Managed-identity token — never a user-delegated or browser-forwarded token.
    try:
        scope = _get_hosted_agent_scope()
        credential = ChainedTokenCredential(
            ManagedIdentityCredential(),
            AzureCliCredential(),
        )
        mi_token = credential.get_token(scope).token
        headers["Authorization"] = f"******"
        logger.debug("Hosted-agent: managed identity token acquired (scope=%s)", scope)
    except Exception:
        logger.warning(
            "Hosted-agent: could not acquire managed identity token; "
            "request may be rejected by the backend",
            exc_info=True,
        )

    return headers


# ---------------------------------------------------------------------------
# Main streaming entry point
# ---------------------------------------------------------------------------

async def call_hosted_agent_stream(
    conversation_id: str,
    question: str,
    auth_info: dict,
    question_id: Optional[str] = None,
    hosted_thread_id: Optional[str] = None,
) -> AsyncGenerator[tuple[str, dict], None]:
    """Stream ``(text_chunk, metadata)`` pairs from the hosted orchestrator.

    Yields:
        ``(text_chunk, metadata)`` where *text_chunk* is a piece of text to
        stream to the user and *metadata* is a (possibly empty) ``dict`` that
        may carry:

        * ``"conversation_id"`` — new or confirmed conversation UUID.
        * ``"thread_id"`` — hosted-agent thread identifier for session continuity.

    Empty text chunks with non-empty metadata signal lifecycle transitions (e.g.
    thread creation, stream completion) without visible output.

    Raises:
        :exc:`HostedAgentConfigError`: endpoint not configured.
        :exc:`RuntimeError`: HTTP error or an explicit ``error`` event from the
            service.
        ``httpx.ConnectError`` / ``httpx.TimeoutException``: network failures
            (re-raised so the caller can surface a user-facing message).
    """
    base_url = _get_hosted_agent_base_url()
    if not base_url:
        raise HostedAgentConfigError(
            "HOSTED_AGENT_BASE_URL is not configured. "
            "Set CHAT_BACKEND=orchestrator or configure HOSTED_AGENT_BASE_URL."
        )

    url = f"{base_url}/chat"
    headers = _build_hosted_agent_headers(auth_info)

    payload: dict = {
        "conversation_id": conversation_id,
        "question": question,
        "ask": question,
    }
    if question_id:
        payload["question_id"] = question_id
    if hosted_thread_id:
        payload["thread_id"] = hosted_thread_id

    # Propagate only the authenticated identity fields permitted by ADR-0001.
    # Never forward raw access tokens.
    principal_id = auth_info.get("client_principal_id") or ""
    principal_name = auth_info.get("client_principal_name") or ""
    if principal_id and principal_id != "no-auth":
        payload["client_principal_id"] = principal_id
    if principal_name and principal_name != "anonymous":
        payload["client_principal_name"] = principal_name

    logger.info(
        "Invoking hosted agent: question_id=%s conversation_id=%s url=%s headers=%s",
        question_id or "n/a",
        conversation_id or "new",
        url,
        _headers_summary(headers),
    )

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "Outgoing hosted-agent request (sanitized):\n%s",
            _format_outgoing_request_debug(
                method="POST", url=url, headers=headers, json_body=payload
            ),
        )

    timeout = httpx.Timeout(connect=10.0, read=None, write=30.0, pool=10.0)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            async with client.stream("POST", url, json=payload, headers=headers) as response:
                if response.status_code >= 400:
                    body = await response.aread()
                    body_text = body.decode(errors="ignore")
                    snippet = (body_text[:2000] + "...") if len(body_text) > 2000 else body_text
                    raise RuntimeError(
                        f"Hosted agent returned HTTP {response.status_code} "
                        f"{response.reason_phrase}. url={url} details={snippet}"
                    )

                async for event in _iter_sse_events(response):
                    logger.debug(
                        "Hosted-agent SSE event: type=%s question_id=%s",
                        event.event_type,
                        question_id or "n/a",
                    )

                    if event.event_type == "thread.created":
                        meta: dict = {}
                        if event.data.get("conversation_id"):
                            meta["conversation_id"] = event.data["conversation_id"]
                        if event.data.get("thread_id"):
                            meta["thread_id"] = event.data["thread_id"]
                        yield ("", meta)

                    elif event.event_type == "text.delta":
                        value = event.data.get("value", "")
                        if value:
                            yield (value, {})

                    elif event.event_type == "annotation":
                        # Citations are embedded in text deltas by the BFF;
                        # stand-alone annotation events carry extra metadata only.
                        logger.debug(
                            "Hosted-agent annotation: title=%s url=%s question_id=%s",
                            event.data.get("title", ""),
                            event.data.get("url", ""),
                            question_id or "n/a",
                        )

                    elif event.event_type == "tool.call":
                        tool_name = event.data.get("type") or event.data.get("tool", "")
                        status = event.data.get("status", "")
                        logger.info(
                            "Hosted-agent tool activity: tool=%s status=%s "
                            "question_id=%s conversation_id=%s",
                            tool_name,
                            status,
                            question_id or "n/a",
                            conversation_id or "new",
                        )

                    elif event.event_type == "error":
                        code = event.data.get("code", "")
                        msg = event.data.get("message") or "hosted agent error"
                        logger.error(
                            "Hosted-agent error event: code=%s message=%s question_id=%s",
                            code,
                            msg,
                            question_id or "n/a",
                        )
                        raise RuntimeError(
                            f"Hosted agent returned an error: {msg} (code={code})"
                        )

                    elif event.event_type == "cancelled":
                        logger.warning(
                            "Hosted-agent stream cancelled: question_id=%s conversation_id=%s",
                            question_id or "n/a",
                            conversation_id or "new",
                        )
                        return

                    elif event.event_type == "done":
                        meta = {}
                        if event.data.get("conversation_id"):
                            meta["conversation_id"] = event.data["conversation_id"]
                        if event.data.get("thread_id"):
                            meta["thread_id"] = event.data["thread_id"]
                        yield ("", meta)
                        return

                    else:
                        logger.debug(
                            "Hosted-agent unrecognised event type '%s'; ignoring: question_id=%s",
                            event.event_type,
                            question_id or "n/a",
                        )

    except httpx.ConnectError:
        logger.error(
            "Hosted-agent connection failed: question_id=%s url=%s",
            question_id or "n/a",
            url,
        )
        raise
    except httpx.TimeoutException:
        logger.error(
            "Hosted-agent request timed out: question_id=%s url=%s",
            question_id or "n/a",
            url,
        )
        raise
    except httpx.HTTPError as e:
        logger.exception(
            "Hosted-agent HTTP error: question_id=%s url=%s",
            question_id or "n/a",
            url,
        )
        raise RuntimeError(f"Hosted agent HTTP error. url={url} error={e}") from e
