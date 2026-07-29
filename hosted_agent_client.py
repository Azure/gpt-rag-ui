"""
Client for the Chainlit hosted-agent BFF path (CHAT_BACKEND=hosted_agent).

Implements server-side streaming over the GPT-RAG hosted orchestrator
``/invocations`` Responses contract: conversation continuity, text deltas,
citations, tool activity, errors, and cancellation.

All credentials are obtained server-side via managed identity; no tokens or
platform details are ever forwarded from the browser to the backend service.
Per ADR-0001, end-user document authorisation is governed by the Toolbox /
native identity path — the UI does not assert any caller identity claim.
"""
from __future__ import annotations

import asyncio
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

# Module-level reusable credential — created once to benefit from the SDK's
# built-in token cache, avoiding redundant token fetches across requests.
_credential: Optional[ChainedTokenCredential] = None


def _get_credential() -> ChainedTokenCredential:
    global _credential  # noqa: PLW0603
    if _credential is None:
        _credential = ChainedTokenCredential(
            ManagedIdentityCredential(),
            AzureCliCredential(),
        )
    return _credential


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


def _get_hosted_agent_scope() -> str:
    """Return the Azure resource scope for managed-identity token acquisition.

    Unlike the orchestrator client, there is intentionally *no default*: the
    operator must supply the exact data-plane scope of the deployed
    hosted-agent service (e.g. ``api://<client-id>/.default``).  Defaulting
    to the ARM audience would silently issue the wrong token.
    """
    value = os.getenv("HOSTED_AGENT_RESOURCE_SCOPE")
    if value:
        return value
    try:
        value = config.get("HOSTED_AGENT_RESOURCE_SCOPE", None, str)
    except Exception:
        pass
    return value or ""


def _get_hosted_agent_api_key() -> str:
    value = os.getenv("HOSTED_AGENT_APP_APIKEY", "")
    if value:
        return value
    try:
        value = config.get("HOSTED_AGENT_APP_APIKEY", "", str) or ""
    except Exception:
        pass
    return value


def validate_hosted_agent_config() -> None:
    """Validate that the hosted-agent endpoint and scope are configured.

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
    scope = _get_hosted_agent_scope()
    if not scope:
        raise HostedAgentConfigError(
            "HOSTED_AGENT_RESOURCE_SCOPE is required when CHAT_BACKEND=hosted_agent. "
            "Set it to the data-plane scope of the hosted-agent service "
            "(e.g. 'api://<client-id>/.default').  The ARM audience is not an accepted default."
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


async def _build_hosted_agent_headers() -> dict:
    """Build request headers for the hosted-agent endpoint.

    Acquires a managed-identity token asynchronously (non-blocking via
    ``asyncio.to_thread``).

    Raises :exc:`HostedAgentConfigError` immediately if ``HOSTED_AGENT_RESOURCE_SCOPE``
    is absent or if token acquisition fails — requests are *never* sent
    unauthenticated or with the wrong audience.
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

    scope = _get_hosted_agent_scope()
    if not scope:
        raise HostedAgentConfigError(
            "HOSTED_AGENT_RESOURCE_SCOPE is required but not configured. "
            "Set it to the data-plane scope of the hosted-agent service "
            "(e.g. 'api://<client-id>/.default')."
        )

    try:
        credential = _get_credential()
        # Non-blocking: run the synchronous SDK call in a thread-pool worker.
        token_response = await asyncio.to_thread(credential.get_token, scope)
        headers["Authorization"] = "Bearer " + token_response.token
        logger.debug("Hosted-agent: managed identity token acquired (scope=%s)", scope)
    except HostedAgentConfigError:
        raise
    except Exception as exc:
        raise HostedAgentConfigError(
            f"Hosted-agent: could not acquire managed identity token (scope={scope!r}). "
            "Ensure the deployment has a managed identity with the required role assignment. "
            f"Original error: {exc}"
        ) from exc

    return headers


# ---------------------------------------------------------------------------
# Main streaming entry point
# ---------------------------------------------------------------------------


async def call_hosted_agent_stream(
    conversation_id: str,
    question: str,
    auth_info: dict,  # reserved for future policy enforcement; not forwarded
    question_id: Optional[str] = None,
) -> AsyncGenerator[tuple[str, dict], None]:
    """Stream ``(text_chunk, metadata)`` pairs from the hosted orchestrator.

    Calls ``POST /invocations`` with the ``InvocationRequest`` contract:
    ordered ``messages`` ending in the current user ask, optional managed
    ``conversation_id``, and ``metadata`` containing correlation identifiers.

    Yields:
        ``(text_chunk, metadata)`` where *text_chunk* is a piece of text to
        stream to the user and *metadata* is a (possibly empty) ``dict`` that
        may carry:

        * ``"conversation_id"`` — server-assigned conversation UUID received
          from ``response.created`` or ``response.completed``.

    Empty text chunks with non-empty metadata signal lifecycle transitions
    (conversation creation, stream completion) without visible output.

    Raises:
        :exc:`HostedAgentConfigError`: endpoint or scope not configured, or
            managed-identity token acquisition failed (fail-fast, no retries).
        :exc:`RuntimeError`: HTTP error or an explicit ``error`` SSE event.
        ``httpx.ConnectError`` / ``httpx.TimeoutException``: network failures
            (re-raised so the caller can surface a user-facing message).
    """
    base_url = _get_hosted_agent_base_url()
    if not base_url:
        raise HostedAgentConfigError(
            "HOSTED_AGENT_BASE_URL is not configured. "
            "Set CHAT_BACKEND=orchestrator or configure HOSTED_AGENT_BASE_URL."
        )

    url = f"{base_url}/invocations"

    # Fail fast on auth before sending any request.
    headers = await _build_hosted_agent_headers()

    payload: dict = {
        "messages": [{"role": "user", "content": question}],
        "metadata": {
            "question_id": question_id or "",
        },
    }
    if conversation_id:
        payload["conversation_id"] = conversation_id
        payload["metadata"]["conversation_id"] = conversation_id

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

    # Finite idle timeout — 120 s between SSE chunks is generous but bounded.
    # This propagates cancellation: if the caller task is cancelled while
    # awaiting a chunk, httpx raises CancelledError through the stream.
    timeout = httpx.Timeout(connect=10.0, read=120.0, write=30.0, pool=10.0)
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

                    if event.event_type == "response.created":
                        # Server-assigned managed conversation_id.
                        cid = event.data.get("conversation_id") or event.data.get("id")
                        if cid:
                            yield ("", {"conversation_id": cid})

                    elif event.event_type == "response.output_text.delta":
                        delta = event.data.get("delta", "")
                        if delta:
                            yield (delta, {})

                    elif event.event_type == "response.output_text.annotation.added":
                        # Citation metadata; inline refs are already embedded in deltas.
                        logger.debug(
                            "Hosted-agent citation: title=%s url=%s question_id=%s",
                            event.data.get("title", ""),
                            event.data.get("url", ""),
                            question_id or "n/a",
                        )

                    elif event.event_type == "response.function_call_arguments.delta":
                        logger.info(
                            "Hosted-agent tool call delta: name=%s question_id=%s "
                            "conversation_id=%s",
                            event.data.get("name") or event.data.get("tool", ""),
                            question_id or "n/a",
                            conversation_id or "new",
                        )

                    elif event.event_type == "response.function_call_arguments.done":
                        logger.info(
                            "Hosted-agent tool call done: name=%s question_id=%s "
                            "conversation_id=%s",
                            event.data.get("name") or event.data.get("tool", ""),
                            question_id or "n/a",
                            conversation_id or "new",
                        )

                    elif event.event_type == "response.completed":
                        meta: dict = {}
                        # conversation_id may be at top level or inside response object.
                        cid = event.data.get("conversation_id") or (
                            (event.data.get("response") or {}).get("id")
                        )
                        if cid:
                            meta["conversation_id"] = cid
                        yield ("", meta)
                        return

                    elif event.event_type == "response.cancelled":
                        logger.warning(
                            "Hosted-agent stream cancelled: question_id=%s conversation_id=%s",
                            question_id or "n/a",
                            conversation_id or "new",
                        )
                        return

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

                    else:
                        logger.debug(
                            "Hosted-agent unrecognised event type '%s'; ignoring: "
                            "question_id=%s",
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
