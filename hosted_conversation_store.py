"""Typed async client for the BFF-owned Foundry managed Conversations
system-of-record (SoR).

This module is the *only* place in this UI allowed to create, read, append
to, or delete a Foundry managed Conversation resource for hosted-agent
continuity. The hosted Responses runtime invoked via ``hosted_agent_client.py``
never receives a conversation reference and has zero Conversations RBAC;
conversely nothing outside this module (and ``hosted_continuity.py``, which
orchestrates it) calls the Conversations REST surface directly.

The wire contract mirrors the standard OpenAI-compatible Conversations API
(``POST/GET/DELETE /conversations``, ``POST/GET /conversations/{id}/items``)
that Azure AI Foundry model endpoints expose alongside the Responses API.
Validate the exact deployed path and API version against the target Foundry
resource before enabling ``HOSTED_CONTINUITY_ENABLED`` in a given environment
(see README.md and the residual risks noted in the pull request).

Owner binding (``HOSTED_CONVERSATION_OWNER_BINDING``, see
``hosted_continuity_config.py``) controls how every call here authenticates
and asserts ownership:

* ``delegated`` (preferred/default) — this BFF authenticates as itself (a
  trusted middle-tier service identity, see
  ``hosted_agent_client.acquire_service_identity_token``) and attaches an
  ``x-ms-user-identity`` header carrying only the caller's validated Entra
  ``oid``. Per live evidence (Azure/GPT-RAG#591, "OQ-OWN"), Azure AI Foundry
  enforces per-asserted-user ownership of this state when the middle-tier
  identity also holds the custom ``UserIdentityImpersonation`` data action:
  a foreign/stale conversation id raises ``ConversationStoreAccessDeniedError``
  rather than ever silently returning someone else's history. This header is
  never the on-behalf-of (OBO) token used elsewhere for Toolbox per-user
  document retrieval (ADR-0001) — the two trust models are intentionally
  kept separate.
* ``capability`` (disabled fallback) — every call instead uses the caller's
  own OBO-delegated token as the bearer, so Foundry authorizes the operation
  as the actual signed-in end user (no ``x-ms-user-identity`` header).
"""

from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

import httpx

from auth_common import normalize_guid
from hosted_agent_client import acquire_obo_token, acquire_service_identity_token

logger = logging.getLogger("gpt_rag_ui.hosted_conversation_store")

_MAX_IDEMPOTENCY_CACHE_ENTRIES = 2048

ConversationStoreOwnerBinding = Literal["capability", "delegated"]


class ConversationStoreError(RuntimeError):
    """Base error for the Conversations system-of-record."""


class ConversationStoreAuthenticationError(ConversationStoreError):
    """Raised when a delegated data-plane token cannot be acquired."""


class ConversationStoreHTTPError(ConversationStoreError):
    """Raised when the Conversations API returns a non-success status."""


class ConversationStoreAccessDeniedError(ConversationStoreHTTPError):
    """Raised when the platform denies access to a managed conversation for
    the currently asserted identity (HTTP 401/403/404 on a read).

    Under ``HOSTED_CONVERSATION_OWNER_BINDING=delegated`` this is the
    platform's own per-user ownership enforcement rejecting a foreign, stale,
    malformed, or otherwise inaccessible conversation id under the caller's
    own asserted oid. Per ADR-0003, callers resolving which conversation to
    use for a turn must treat this as a fail-closed rejection of the
    *presented* reference: raise a single opaque not-found error and never
    silently create a fresh conversation, invoke the hosted agent, or append
    anything for that turn — doing so would turn an attempted
    cross-user/forged/guessed-id probe (IDOR/BOLA) into a success-shaped
    response. Callers must treat this distinctly from a generic
    ``ConversationStoreHTTPError`` raised elsewhere in the same turn, which
    still must fail closed as an explicit dependency/persistence error (not
    a 404-equivalent, and not a fresh conversation either).
    """


@dataclass(frozen=True)
class ConversationItem:
    item_id: str
    role: Literal["user", "assistant"]
    content: str


@dataclass(frozen=True)
class ConversationStoreSettings:
    base_url: str
    resource_scope: str


def _conversations_url(base_url: str, *parts: str) -> str:
    url = base_url.rstrip("/") + "/conversations"
    for part in parts:
        url += f"/{part}"
    return url


def _extract_text(item: dict) -> str:
    content = item.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for chunk in content:
            if isinstance(chunk, dict):
                text = chunk.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "".join(parts)
    return ""


class ConversationLockRegistry:
    """Per-conversation one-in-flight async lock registry.

    Locks are created lazily and kept for the process lifetime; this bounds
    memory to the number of distinct conversations a single replica has
    handled. This is a BFF-local mutual-exclusion guard, not a cross-replica
    lock — a multi-replica deployment that needs cross-replica one-in-flight
    guarantees must add a shared lock (e.g. a distributed lease); this is a
    documented residual risk, not silently claimed as solved here.
    """

    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}
        self._registry_lock = asyncio.Lock()

    async def acquire(self, conversation_id: str) -> asyncio.Lock:
        async with self._registry_lock:
            lock = self._locks.get(conversation_id)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[conversation_id] = lock
        return lock


class ConversationIdempotencyCache:
    """Bounded per-process cache of already-applied client turn ids.

    Prevents a duplicate append when the same client turn is retried (for
    example a network blip after the hosted runtime completed but before the
    caller observed success). Intentionally process-local and bounded to
    ``max_entries``; multi-replica deployments that need cross-replica
    idempotency must add a shared store (out of scope here — see residual
    risks in the pull request).
    """

    def __init__(self, *, max_entries: int = _MAX_IDEMPOTENCY_CACHE_ENTRIES) -> None:
        self._max_entries = max_entries
        self._seen: OrderedDict[tuple[str, str], bool] = OrderedDict()
        self._lock = asyncio.Lock()

    async def already_applied(self, conversation_id: str, client_turn_id: str) -> bool:
        key = (conversation_id, client_turn_id)
        async with self._lock:
            return key in self._seen

    async def mark_applied(self, conversation_id: str, client_turn_id: str) -> None:
        key = (conversation_id, client_turn_id)
        async with self._lock:
            self._seen[key] = True
            self._seen.move_to_end(key)
            while len(self._seen) > self._max_entries:
                self._seen.popitem(last=False)


class ConversationStoreClient:
    """Async client owning create/read/append/delete for the Conversations
    system-of-record.

    The authentication/ownership-assertion strategy is fixed at construction
    time via ``owner_binding`` (see module docstring): ``delegated`` uses this
    service's own credential plus an ``x-ms-user-identity`` header derived
    only from the caller's validated oid; ``capability`` uses the caller's
    own OBO-delegated token as the bearer with no special header. Either way,
    Foundry ends up authorizing each Conversations operation against a
    concrete end-user identity, never an anonymous or ambiguous one.
    """

    def __init__(
        self,
        settings: ConversationStoreSettings,
        *,
        owner_binding: ConversationStoreOwnerBinding = "capability",
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings
        self.owner_binding: ConversationStoreOwnerBinding = owner_binding
        self._http_client = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0),
            follow_redirects=False,
        )
        self._owns_http_client = http_client is None

    async def aclose(self) -> None:
        if self._owns_http_client:
            await self._http_client.aclose()

    async def _headers(
        self,
        *,
        user_access_token: str | None = None,
        oid: str | None = None,
    ) -> dict[str, str]:
        if self.owner_binding == "delegated":
            try:
                canonical_oid = normalize_guid(oid or "", claim_name="oid")
            except ValueError as exc:
                raise ConversationStoreAuthenticationError(
                    "A validated Entra oid is required to derive the "
                    "x-ms-user-identity header for delegated owner binding."
                ) from exc
            service_token = await acquire_service_identity_token(
                self.settings.resource_scope
            )
            return {
                "Authorization": f"Bearer {service_token}",
                "Content-Type": "application/json",
                # Derived exclusively from the server-validated Entra oid
                # above — never from any client/browser-supplied value.
                "x-ms-user-identity": canonical_oid,
            }

        stripped = (user_access_token or "").strip()
        if not stripped:
            raise ConversationStoreAuthenticationError(
                "A signed-in user access token is required to manage the "
                "hosted-agent continuity Conversations store."
            )
        delegated_token = await acquire_obo_token(stripped, self.settings.resource_scope)
        return {
            "Authorization": f"Bearer {delegated_token}",
            "Content-Type": "application/json",
        }

    async def create_conversation(
        self,
        *,
        user_access_token: str | None = None,
        oid: str | None = None,
    ) -> str:
        """Create a brand-new managed conversation under the caller's own
        identity. Callers must only invoke this to start continuity for the
        *current* authenticated user's own request flow, never to materialize
        an arbitrary caller-supplied conversation id.
        """
        headers = await self._headers(user_access_token=user_access_token, oid=oid)
        url = _conversations_url(self.settings.base_url)
        response = await self._http_client.post(url, json={}, headers=headers)
        if not 200 <= response.status_code < 300:
            raise ConversationStoreHTTPError(
                f"Failed to create the managed conversation (HTTP {response.status_code})."
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise ConversationStoreHTTPError(
                "The Conversations store returned a non-JSON create response."
            ) from exc
        conversation_id = str((data or {}).get("id") or "")
        if not conversation_id:
            raise ConversationStoreHTTPError(
                "The Conversations store did not return a conversation id."
            )
        return conversation_id

    async def list_items_ascending(
        self,
        *,
        user_access_token: str | None = None,
        oid: str | None = None,
        conversation_id: str,
        limit: int,
    ) -> list[ConversationItem]:
        """Read ordered (oldest-first) items for one managed conversation.

        Raises ``ConversationStoreAccessDeniedError`` (a subclass of
        ``ConversationStoreHTTPError``) on HTTP 401/403/404 — under
        delegated owner binding this is the platform itself denying the
        currently asserted identity access to this conversation id (a
        foreign, stale, malformed, or otherwise inaccessible reference).
        Callers resolving which conversation to use for a turn must map this
        to a single opaque not-found failure and fail closed (never create a
        new conversation, invoke the hosted agent, or persist anything for
        that turn). Any other failure raises the plain
        ``ConversationStoreHTTPError`` base class and remains an explicit
        dependency/persistence error — never a 404-equivalent and never a
        fresh conversation.
        """
        headers = await self._headers(user_access_token=user_access_token, oid=oid)
        url = _conversations_url(self.settings.base_url, conversation_id, "items")
        response = await self._http_client.get(
            url,
            headers=headers,
            params={"order": "asc", "limit": max(1, min(limit, 100))},
        )
        if response.status_code in (401, 403, 404):
            raise ConversationStoreAccessDeniedError(
                "Access to the managed conversation was denied "
                f"(HTTP {response.status_code})."
            )
        if not 200 <= response.status_code < 300:
            raise ConversationStoreHTTPError(
                f"Failed to read the managed conversation (HTTP {response.status_code})."
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise ConversationStoreHTTPError(
                "The Conversations store returned a non-JSON items response."
            ) from exc
        raw_items = (data or {}).get("data")
        if not isinstance(raw_items, list):
            raise ConversationStoreHTTPError(
                "The Conversations store returned an unexpected items payload."
            )
        items: list[ConversationItem] = []
        for raw_item in raw_items:
            if not isinstance(raw_item, dict):
                continue
            role = raw_item.get("role")
            if role not in {"user", "assistant"}:
                continue
            items.append(
                ConversationItem(
                    item_id=str(raw_item.get("id") or ""),
                    role=role,
                    content=_extract_text(raw_item),
                )
            )
        return items

    async def append_items(
        self,
        *,
        user_access_token: str | None = None,
        oid: str | None = None,
        conversation_id: str,
        items: Sequence[dict],
    ) -> None:
        """Append items to the managed conversation. Raises
        ``ConversationStoreHTTPError`` on any failure; callers must treat this
        as fail-closed and must not present the turn as durably committed.
        """
        if not items:
            return
        headers = await self._headers(user_access_token=user_access_token, oid=oid)
        url = _conversations_url(self.settings.base_url, conversation_id, "items")
        response = await self._http_client.post(
            url,
            json={"items": list(items)},
            headers=headers,
        )
        if not 200 <= response.status_code < 300:
            raise ConversationStoreHTTPError(
                f"Failed to append to the managed conversation (HTTP {response.status_code})."
            )

    async def delete_conversation(
        self,
        *,
        user_access_token: str | None = None,
        oid: str | None = None,
        conversation_id: str,
    ) -> None:
        headers = await self._headers(user_access_token=user_access_token, oid=oid)
        url = _conversations_url(self.settings.base_url, conversation_id)
        response = await self._http_client.delete(url, headers=headers)
        if response.status_code == 404:
            return
        if not 200 <= response.status_code < 300:
            raise ConversationStoreHTTPError(
                f"Failed to delete the managed conversation (HTTP {response.status_code})."
            )


def build_bounded_history(
    items: Sequence[ConversationItem],
    *,
    max_items: int,
    max_tokens: int,
) -> list[ConversationItem]:
    """Apply the explicit bounded-history policy to an already ordered
    (oldest-first) item sequence: keep at most ``max_items`` most-recent
    items, then drop the oldest remaining items while the estimated token
    total exceeds ``max_tokens`` (never dropping the single most recent
    item, even if it alone exceeds the budget).
    """
    bounded = list(items[-max_items:]) if max_items > 0 else []

    def _estimate_tokens(text: str) -> int:
        return max(1, (len(text) + 3) // 4)

    total_tokens = sum(_estimate_tokens(item.content) for item in bounded)
    while len(bounded) > 1 and total_tokens > max_tokens:
        dropped = bounded.pop(0)
        total_tokens -= _estimate_tokens(dropped.content)
    return bounded
