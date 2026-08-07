"""Typed store operations for the panel owner index and feedback metadata
(issue #611, ADR-0004).

This is the *only* place in this UI allowed to read or write the panel-only
Cosmos containers. Everything here is metadata: conversation identifiers,
titles, timestamps, principal ids, and feedback rating/category/comment --
never message content, citations, or document content.

Every function requires a caller-validated ``principal_id`` (the caller's
own Entra ``oid``, already authenticated by ``panel_auth.py`` before any of
these are invoked) and never accepts an owner/principal value from request
metadata. ``get_owner_index_row`` is the *only* accepted authorization
check before a per-conversation read, feedback operation, or delete ever
reaches the managed-Conversations store or performs a Cosmos write scoped
to that conversation id -- callers (``panel_routes.py``) must call it
first and fail closed (404) on a miss before doing anything else.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from auth_common import normalize_guid
from panel_cosmos import PanelCosmosClient, PanelStoreError

logger = logging.getLogger("gpt_rag_ui.panel_store")

_MAX_CONVERSATION_ID_LENGTH = 256
_MAX_TITLE_LENGTH = 256
_MAX_FEEDBACK_ID_LENGTH = 128
_MAX_MESSAGE_REF_LENGTH = 128
_MAX_CATEGORY_LENGTH = 64
_MAX_COMMENT_LENGTH = 2000

__all__ = [
    "PanelValidationError",
    "OwnerIndexRow",
    "FeedbackRecord",
    "upsert_owner_index_row",
    "get_owner_index_row",
    "list_owner_index_rows",
    "delete_owner_index_row",
    "create_feedback",
    "list_feedback_for_conversation",
    "delete_feedback_for_conversation",
]


class PanelValidationError(ValueError):
    """Raised for a caller-supplied identifier or field that fails schema
    or bounds validation. Route handlers must map this to HTTP 422."""


def _validate_conversation_id(value: str) -> str:
    conversation_id = str(value or "").strip()
    if (
        not conversation_id
        or len(conversation_id) > _MAX_CONVERSATION_ID_LENGTH
        or any(ord(char) < 32 for char in conversation_id)
    ):
        raise PanelValidationError("Invalid conversation id.")
    return conversation_id


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sanitize_text(value: str, *, max_length: int) -> str:
    # Strip control characters -- never persist raw control bytes as
    # metadata -- and bound the length.
    cleaned = "".join(char for char in value if ord(char) >= 32 or char in "\n\t")
    return cleaned.strip()[:max_length]


@dataclass(frozen=True)
class OwnerIndexRow:
    conversation_id: str
    principal_id: str
    title: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class FeedbackRecord:
    feedback_id: str
    conversation_id: str
    principal_id: str
    message_ref: str
    rating: Optional[int]
    category: Optional[str]
    comment: Optional[str]
    created_at: str


async def upsert_owner_index_row(
    *,
    client: PanelCosmosClient,
    principal_id: str,
    conversation_id: str,
    title: str = "",
) -> OwnerIndexRow:
    """Create or refresh an owner-index row for a BFF-created conversation.

    Callers (the injected callback in ``hosted_continuity.py``) must only
    invoke this for a conversation the BFF itself just created for the
    *current* authenticated user; never for a caller-supplied conversation
    id. Upserting keeps ``updated_at``/``title`` fresh across turns without
    requiring the caller to track "first write" separately, and is
    naturally idempotent under retry.
    """
    oid = normalize_guid(principal_id, claim_name="oid")
    cid = _validate_conversation_id(conversation_id)
    now = _now_iso()
    existing = await client.read_item(client.settings.owner_index_container, cid, oid)
    created_at = existing.get("created_at") if existing else now
    body = {
        "id": cid,
        "principal_id": oid,
        "title": _sanitize_text(title or "", max_length=_MAX_TITLE_LENGTH),
        "created_at": created_at,
        "updated_at": now,
    }
    saved = await client.upsert_item(client.settings.owner_index_container, body)
    return OwnerIndexRow(
        conversation_id=cid,
        principal_id=oid,
        title=saved.get("title", ""),
        created_at=saved.get("created_at", now),
        updated_at=saved.get("updated_at", now),
    )


async def get_owner_index_row(
    *,
    client: PanelCosmosClient,
    principal_id: str,
    conversation_id: str,
) -> Optional[OwnerIndexRow]:
    """Owner-gate lookup -- the *only* accepted authorization check before
    any per-conversation read, feedback operation, or delete. Returns
    ``None`` both for a missing row and for a row belonging to a different
    principal; callers must map both to an identical 404 and must never
    read the managed-Conversations store first."""
    oid = normalize_guid(principal_id, claim_name="oid")
    cid = _validate_conversation_id(conversation_id)
    row = await client.read_item(client.settings.owner_index_container, cid, oid)
    if not row or str(row.get("principal_id") or "") != oid:
        return None
    return OwnerIndexRow(
        conversation_id=cid,
        principal_id=oid,
        title=str(row.get("title") or ""),
        created_at=str(row.get("created_at") or ""),
        updated_at=str(row.get("updated_at") or ""),
    )


async def list_owner_index_rows(
    *,
    client: PanelCosmosClient,
    principal_id: str,
    skip: int,
    limit: int,
) -> tuple[list[OwnerIndexRow], bool]:
    """Return one page of the caller's own conversations (most-recently
    updated first) and whether a further page exists. The query is always
    partitioned and filtered by the validated oid -- another principal's
    rows are never returned, matched, or counted."""
    oid = normalize_guid(principal_id, claim_name="oid")
    query = (
        "SELECT c.id, c.title, c.created_at, c.updated_at FROM c "
        "WHERE c.principal_id = @principal_id "
        "ORDER BY c.updated_at DESC OFFSET @skip LIMIT @limit"
    )
    parameters = [
        {"name": "@principal_id", "value": oid},
        {"name": "@skip", "value": skip},
        {"name": "@limit", "value": limit + 1},
    ]
    rows = await client.query_items(
        client.settings.owner_index_container,
        query=query,
        parameters=parameters,
        partition_key=oid,
    )
    has_more = len(rows) > limit
    rows = rows[:limit]
    return (
        [
            OwnerIndexRow(
                conversation_id=str(row.get("id") or ""),
                principal_id=oid,
                title=str(row.get("title") or ""),
                created_at=str(row.get("created_at") or ""),
                updated_at=str(row.get("updated_at") or ""),
            )
            for row in rows
        ],
        has_more,
    )


async def delete_owner_index_row(
    *,
    client: PanelCosmosClient,
    principal_id: str,
    conversation_id: str,
) -> None:
    oid = normalize_guid(principal_id, claim_name="oid")
    cid = _validate_conversation_id(conversation_id)
    await client.delete_item(client.settings.owner_index_container, cid, oid)


async def create_feedback(
    *,
    client: PanelCosmosClient,
    principal_id: str,
    conversation_id: str,
    feedback_id: str,
    message_ref: str,
    rating: Optional[int],
    category: Optional[str],
    comment: Optional[str],
) -> FeedbackRecord:
    """Create (or idempotently re-apply) one feedback record.

    ``feedback_id`` is the Cosmos item id, so a client retrying the same
    create with the same ``feedback_id`` upserts the identical record
    instead of creating a duplicate. Metadata only: rating, a bounded
    reason-code-style category, and a bounded/sanitized user comment --
    never the underlying chat transcript or any citation/document content.
    """
    oid = normalize_guid(principal_id, claim_name="oid")
    cid = _validate_conversation_id(conversation_id)
    fid = str(feedback_id or "").strip()
    if (
        not fid
        or len(fid) > _MAX_FEEDBACK_ID_LENGTH
        or any(ord(char) < 32 for char in fid)
    ):
        raise PanelValidationError("Invalid feedback id.")
    ref = str(message_ref or "").strip()
    if (
        not ref
        or len(ref) > _MAX_MESSAGE_REF_LENGTH
        or any(ord(char) < 32 for char in ref)
    ):
        raise PanelValidationError("Invalid message reference.")
    if rating is not None and not (-5 <= int(rating) <= 5):
        raise PanelValidationError("rating must be between -5 and 5.")
    category_clean = (
        _sanitize_text(category, max_length=_MAX_CATEGORY_LENGTH)
        if category
        else None
    )
    comment_clean = (
        _sanitize_text(comment, max_length=_MAX_COMMENT_LENGTH) if comment else None
    )
    now = _now_iso()
    body = {
        "id": fid,
        "principal_id": oid,
        "conversation_id": cid,
        "message_ref": ref,
        "rating": rating,
        "category": category_clean,
        "comment": comment_clean,
        "created_at": now,
    }
    saved = await client.upsert_item(client.settings.feedback_container, body)
    return FeedbackRecord(
        feedback_id=fid,
        conversation_id=cid,
        principal_id=oid,
        message_ref=ref,
        rating=saved.get("rating"),
        category=saved.get("category"),
        comment=saved.get("comment"),
        created_at=saved.get("created_at", now),
    )


async def list_feedback_for_conversation(
    *,
    client: PanelCosmosClient,
    principal_id: str,
    conversation_id: str,
) -> list[FeedbackRecord]:
    oid = normalize_guid(principal_id, claim_name="oid")
    cid = _validate_conversation_id(conversation_id)
    query = (
        "SELECT * FROM c WHERE c.principal_id = @principal_id "
        "AND c.conversation_id = @conversation_id ORDER BY c.created_at ASC"
    )
    parameters = [
        {"name": "@principal_id", "value": oid},
        {"name": "@conversation_id", "value": cid},
    ]
    rows = await client.query_items(
        client.settings.feedback_container,
        query=query,
        parameters=parameters,
        partition_key=oid,
    )
    return [
        FeedbackRecord(
            feedback_id=str(row.get("id") or ""),
            conversation_id=cid,
            principal_id=oid,
            message_ref=str(row.get("message_ref") or ""),
            rating=row.get("rating"),
            category=row.get("category"),
            comment=row.get("comment"),
            created_at=str(row.get("created_at") or ""),
        )
        for row in rows
    ]


async def delete_feedback_for_conversation(
    *,
    client: PanelCosmosClient,
    principal_id: str,
    conversation_id: str,
) -> None:
    """Best-effort delete of every feedback row for one conversation.

    Attempts every row even if one fails, then raises ``PanelStoreError``
    if any delete failed, so a caller performing a conversation delete can
    report an explicit partial failure rather than silently leaving
    orphaned feedback metadata undetected.
    """
    records = await list_feedback_for_conversation(
        client=client, principal_id=principal_id, conversation_id=conversation_id
    )
    oid = normalize_guid(principal_id, claim_name="oid")
    failures = 0
    for record in records:
        try:
            await client.delete_item(
                client.settings.feedback_container, record.feedback_id, oid
            )
        except PanelStoreError:
            logger.exception(
                "[panel_store] failed to delete feedback record during "
                "conversation delete"
            )
            failures += 1
    if failures:
        raise PanelStoreError(
            f"Failed to delete {failures} of {len(records)} feedback records."
        )
