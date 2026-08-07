"""Orchestration for the opt-in hosted-agent cross-version continuity path
(``HOSTED_CONTINUITY_ENABLED=true``).

While the feature flag is false (the default), none of this module's logic
runs and the existing per-turn hosted-agent behavior in ``app.py`` /
``hosted_agent_client.py`` is completely unchanged.

Per turn, in order:

1. Resolve the managed conversation id for this turn according to the active
   owner-binding mode (``hosted_continuity_config.HostedContinuitySettings``):
   * ``delegated`` (preferred/default) — the caller's previously issued
     conversation id (if any) is re-validated by asking the Conversations
     store to read from it under the *current* caller's own validated Entra
     ``oid``, asserted only via the platform-trusted ``x-ms-user-identity``
     header (never a raw client-supplied claim of ownership). If the
     platform denies access (``ConversationStoreAccessDeniedError`` — a
     foreign, stale, or otherwise inaccessible reference), a brand-new
     managed conversation is created under the current user's own flow
     instead of ever reusing or trusting the untrusted reference.
   * ``capability`` (disabled fallback) — the caller-held opaque signed
     capability is validated against the caller's validated Entra oid
     (``hosted_conversation_capability.py``). Any failure — missing, forged,
     expired, retired key, or wrong oid — is treated identically: a
     brand-new managed conversation is created and a fresh capability is
     minted around it.
   Neither mode ever mints/returns a handle around a caller-supplied
   conversation id that this BFF did not itself just create or re-validate.
2. Acquire a one-in-flight lock for the resolved managed conversation id.
3. Read ordered history from the Conversations system-of-record
   (``hosted_conversation_store.py``) and apply the explicit bounded-history
   policy (max items, then max tokens, dropping the oldest first).
4. Build a complete, ordered, canonical stateless Responses input and invoke
   the hosted runtime *without* a top-level conversation/previous_response_id
   (``hosted_agent_client.py``); the hosted runtime never receives a
   conversation reference and has zero Conversations RBAC.
5. Append the user turn and the completed assistant turn back to the
   Conversations system-of-record. This append is fail-closed: if it does not
   succeed, ``ContinuityPersistenceError`` is raised and the caller must
   render an explicit failure rather than treat the already-streamed
   assistant text as a successfully committed turn. An idempotent client
   turn id prevents a duplicate append on retry.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from typing import Any

from auth_common import normalize_guid
from hosted_agent_client import HostedAgentError, InvocationMessage, call_hosted_agent_stream
from hosted_continuity_config import HostedContinuitySettings
from hosted_conversation_capability import (
    ConversationCapabilityError,
    ConversationCapabilityManager,
)
from hosted_conversation_store import (
    ConversationIdempotencyCache,
    ConversationLockRegistry,
    ConversationStoreAccessDeniedError,
    ConversationStoreClient,
    ConversationStoreError,
    build_bounded_history,
)

logger = logging.getLogger("gpt_rag_ui.hosted_continuity")


class ContinuityPersistenceError(RuntimeError):
    """Raised when a turn could not be durably committed to the Conversations
    system-of-record (a history read failure, an append failure, or a
    detected duplicate client turn id).

    Callers MUST treat this as a hard failure: render an explicit error and
    never present the assistant text that already streamed as a successfully
    completed, durably saved turn.
    """


class HostedContinuityCoordinator:
    """Wires owner-binding resolution, the Conversations system-of-record,
    and the stateless hosted-agent invocation together for one turn."""

    def __init__(
        self,
        *,
        settings: HostedContinuitySettings,
        store: ConversationStoreClient,
        capability_manager: ConversationCapabilityManager | None = None,
        locks: ConversationLockRegistry | None = None,
        idempotency: ConversationIdempotencyCache | None = None,
    ) -> None:
        if not settings.enabled:
            raise ValueError(
                "HostedContinuityCoordinator requires HOSTED_CONTINUITY_ENABLED=true."
            )
        if settings.uses_capability_binding and capability_manager is None:
            raise ValueError(
                "capability_manager is required when "
                "HOSTED_CONVERSATION_OWNER_BINDING=capability."
            )
        self.settings = settings
        self._store = store
        self._capabilities = capability_manager
        self._locks = locks or ConversationLockRegistry()
        self._idempotency = idempotency or ConversationIdempotencyCache()

    async def _resolve_conversation_id(
        self,
        *,
        owner_ref: str,
        oid: str,
        user_access_token: str,
    ) -> tuple[str, str]:
        """Return ``(conversation_id, owner_ref)`` for this turn, dispatching
        to the active owner-binding mode's resolution strategy."""
        if self.settings.uses_delegated_binding:
            return await self._resolve_conversation_id_delegated(
                owner_ref=owner_ref, oid=oid, user_access_token=user_access_token
            )
        return await self._resolve_conversation_id_capability(
            capability=owner_ref, oid=oid, user_access_token=user_access_token
        )

    async def _resolve_conversation_id_capability(
        self,
        *,
        capability: str,
        oid: str,
        user_access_token: str,
    ) -> tuple[str, str]:
        """Capability-mode resolution (disabled fallback).

        Mints a fresh managed conversation (and capability) whenever the
        caller has no capability yet, or it fails validation for *any*
        reason. Never mints a capability around a caller-supplied
        conversation id — the only conversation id ever bound here is one
        this method itself just created.
        """
        assert self._capabilities is not None  # enforced in __init__
        if capability:
            try:
                validated = self._capabilities.validate(capability, oid=oid)
                return validated.conversation_id, capability
            except ConversationCapabilityError:
                logger.info(
                    "Hosted-continuity capability rejected; starting a new "
                    "managed conversation for this turn."
                )
        conversation_id = await self._store.create_conversation(
            user_access_token=user_access_token,
        )
        new_capability = self._capabilities.mint(oid=oid, conversation_id=conversation_id)
        return conversation_id, new_capability

    async def _resolve_conversation_id_delegated(
        self,
        *,
        owner_ref: str,
        oid: str,
        user_access_token: str,
    ) -> tuple[str, str]:
        """Delegated-mode resolution (preferred/default).

        The client-held ``owner_ref`` is simply the real managed conversation
        id — there is nothing to cryptographically validate locally, because
        ownership is enforced by the platform itself via the
        ``x-ms-user-identity`` header (derived only from ``oid``, never from
        the caller-supplied ``owner_ref``) on every Conversations call. A raw,
        unsigned, even guessed or stolen conversation id is therefore safe to
        hold client-side: replaying it under a *different* user's oid is
        rejected by the platform (``ConversationStoreAccessDeniedError``),
        never silently served. This is confirmed with a lightweight read
        probe before returning the reference as valid for this turn.
        """
        canonical_oid = normalize_guid(oid, claim_name="oid")
        candidate = owner_ref.strip()
        if candidate:
            try:
                await self._store.list_items_ascending(
                    oid=canonical_oid,
                    conversation_id=candidate,
                    limit=1,
                )
                return candidate, candidate
            except ConversationStoreAccessDeniedError:
                logger.info(
                    "Hosted-continuity delegated conversation reference was "
                    "rejected by the platform for the current identity; "
                    "starting a new managed conversation for this turn."
                )
        conversation_id = await self._store.create_conversation(
            user_access_token=user_access_token, oid=canonical_oid
        )
        return conversation_id, conversation_id

    async def run_turn(
        self,
        *,
        capability: str,
        oid: str,
        user_ask: str,
        client_turn_id: str,
        question_id: str | None,
        correlation_id: str | None,
        user_access_token: str,
    ) -> AsyncGenerator[tuple[str, dict[str, Any]], None]:
        """Run one bounded, stateless hosted-agent turn and durably persist it.

        Yields the same ``(text_chunk, meta)`` protocol as
        ``call_hosted_agent_stream``. The first yielded frame always carries
        ``meta["capability"]`` (the continuity handle the caller must persist
        for the next turn) and ``meta["conversation_id"]`` (the real,
        BFF-owned managed conversation id, safe to use only for the remainder
        of *this* request, e.g. for citation/download scoping — it must not
        be persisted across turns under its own name). Under
        ``HOSTED_CONVERSATION_OWNER_BINDING=capability`` the persisted handle
        is an opaque signed token; under the preferred ``delegated`` mode it
        is simply the real conversation id, which is safe to hold client-side
        because the platform (not a BFF-issued signature) enforces per-user
        ownership of it. Either way callers must treat the field as an opaque
        handle and never attempt to parse or trust its shape.

        Any ``conversation_id`` reported by the hosted runtime itself in
        later frames is intentionally stripped, since the hosted runtime's
        own ephemeral identifier is unrelated to the Conversations
        system-of-record this module owns.

        Raises ``ContinuityPersistenceError`` if the completed turn could not
        be durably appended (or a duplicate client turn id is detected);
        callers must treat this as a hard failure.
        """
        ask = user_ask.strip()
        if not ask:
            raise HostedAgentError("The current user message must not be empty.")
        if not client_turn_id:
            raise HostedAgentError("A client turn id is required for idempotent append.")

        canonical_oid = normalize_guid(oid, claim_name="oid")
        conversation_id, resolved_owner_ref = await self._resolve_conversation_id(
            owner_ref=capability,
            oid=canonical_oid,
            user_access_token=user_access_token,
        )
        yield "", {
            "capability": resolved_owner_ref,
            "conversation_id": conversation_id,
        }

        lock = await self._locks.acquire(conversation_id)
        async with lock:
            if await self._idempotency.already_applied(conversation_id, client_turn_id):
                raise ContinuityPersistenceError(
                    "This turn was already applied to the managed conversation; "
                    "refusing to process a duplicate client turn id."
                )

            try:
                history_items = await self._store.list_items_ascending(
                    user_access_token=user_access_token,
                    oid=canonical_oid,
                    conversation_id=conversation_id,
                    limit=self.settings.history_max_items,
                )
            except ConversationStoreError as exc:
                raise ContinuityPersistenceError(
                    "Failed to read the managed conversation history."
                ) from exc

            bounded_history = build_bounded_history(
                history_items,
                max_items=self.settings.history_max_items,
                max_tokens=self.settings.history_max_tokens,
            )
            messages = [
                InvocationMessage(role=item.role, content=item.content)
                for item in bounded_history
            ] + [InvocationMessage(role="user", content=ask)]

            assistant_text = ""
            generator = call_hosted_agent_stream(
                messages,
                conversation_id="",
                question_id=question_id,
                correlation_id=correlation_id,
                user_access_token=user_access_token,
            )
            try:
                async for text_chunk, meta in generator:
                    if text_chunk:
                        assistant_text += text_chunk
                    filtered_meta = dict(meta)
                    filtered_meta.pop("conversation_id", None)
                    yield text_chunk, filtered_meta
            finally:
                try:
                    await generator.aclose()
                except RuntimeError as exc:
                    if "async generator ignored GeneratorExit" not in str(exc):
                        raise

            try:
                await self._store.append_items(
                    user_access_token=user_access_token,
                    oid=canonical_oid,
                    conversation_id=conversation_id,
                    items=[
                        {"type": "message", "role": "user", "content": ask},
                        {
                            "type": "message",
                            "role": "assistant",
                            "content": assistant_text,
                        },
                    ],
                )
            except ConversationStoreError as exc:
                raise ContinuityPersistenceError(
                    "The completed response could not be durably saved to the "
                    "managed conversation."
                ) from exc

            await self._idempotency.mark_applied(conversation_id, client_turn_id)

