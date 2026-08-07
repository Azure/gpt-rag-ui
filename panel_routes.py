"""Panel user-facing conversation history/feedback/deletion routes
(issue #611, ADR-0004).

Mounted unconditionally on the host FastAPI app so a disabled deployment
still answers a genuine ``503`` (never a bare ``404``, which would look
like the route itself does not exist rather than being gated off). Every
request re-checks the gate state and re-derives identity from the bearer;
nothing is cached across requests or trusted from the client.

Call order enforced by every per-conversation endpoint (read, feedback,
delete): (1) gate check, (2) bearer validation, (3) the Cosmos-only
owner-index gate, and only *after* that succeeds (4) any call to the
managed-Conversations system-of-record. A caller-supplied ``{conversation_id}``
is therefore never used to drive a system-of-record read on its own -- it is
always conditioned on a passing owner check first, exactly as ADR-0004
requires.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import Optional

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from connectors.appconfig import AppConfigClient
from entra_token import EntraTokenValidator
from hosted_conversation_store import (
    ConversationStoreAccessDeniedError,
    ConversationStoreClient,
    ConversationStoreError,
)
from panel_auth import (
    PanelAuthError,
    PanelForbiddenError,
    PanelPrincipal,
    validate_panel_bearer,
)
from panel_config import PanelSettings
from panel_cosmos import PanelCosmosClient, PanelStoreError, get_panel_cosmos_client
from panel_cursor import PanelCursorError, PanelCursorManager
from panel_store import (
    OwnerIndexRow,
    PanelValidationError,
    create_feedback,
    delete_feedback_for_conversation,
    delete_owner_index_row,
    get_owner_index_row,
    list_feedback_for_conversation,
    list_owner_index_rows,
)

logger = logging.getLogger("gpt_rag_ui.panel_routes")

_NOT_FOUND_MESSAGE = "The referenced conversation could not be found."
_MAX_LIST_LIMIT = 50
_DEFAULT_LIST_LIMIT = 20
_MAX_MESSAGES_LIMIT = 200
_MAX_MESSAGE_CONTENT_CHARS = 20_000


class ConversationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    created_at: str
    updated_at: str


class ConversationsListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ConversationSummary]
    next_cursor: Optional[str] = None


class MessageOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str
    content: str


class MessagesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[MessageOut]


class FeedbackCreateRequest(BaseModel):
    """Strict, bounded feedback input. ``comment`` is genuine user-authored
    feedback content, bounded and sanitized; it must never carry the
    underlying chat transcript or citation/document content."""

    model_config = ConfigDict(extra="forbid")

    feedback_id: str = Field(min_length=1, max_length=128)
    message_ref: str = Field(min_length=1, max_length=128)
    rating: Optional[int] = Field(default=None, ge=-5, le=5)
    category: Optional[str] = Field(default=None, max_length=64)
    comment: Optional[str] = Field(default=None, max_length=2000)


class FeedbackOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feedback_id: str
    message_ref: str
    rating: Optional[int]
    category: Optional[str]
    comment: Optional[str]
    created_at: str


class FeedbackListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[FeedbackOut]


class DeleteConversationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    detail: str = ""


def _unavailable() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail=(
            "The administrative panel's conversation history surfaces are "
            "unavailable (DEPLOY_ADMINISTRATIVE_PANEL, PANEL_HISTORY_ENABLED, "
            "and hosted-agent continuity must all be enabled)."
        ),
    )


def _not_found() -> HTTPException:
    return HTTPException(status_code=404, detail=_NOT_FOUND_MESSAGE)


def register_panel_routes(
    app: FastAPI,
    *,
    config: AppConfigClient,
    settings: PanelSettings,
    continuity_active: Callable[[], bool],
    get_conversation_store: Callable[[], ConversationStoreClient],
) -> None:
    """Mount the panel's user-facing history/feedback/deletion endpoints.

    ``continuity_active``/``get_conversation_store`` are provided by the
    caller (``main.py``) so this module never constructs its own
    managed-Conversations client -- it reuses the exact same
    ``ConversationStoreClient`` instance the hosted-continuity turn path
    already owns (``hosted_continuity.py`` / ``app.py``), never a
    duplicate.
    """
    router = APIRouter()

    validator: EntraTokenValidator | None = None
    if settings.user_surfaces_active:
        validator = EntraTokenValidator(
            tenant_id=settings.tenant_id,
            audience=settings.token_audience,
        )

    def _require_active() -> None:
        if not (settings.user_surfaces_active and continuity_active()):
            raise _unavailable()

    async def _authenticate(request: Request) -> PanelPrincipal:
        assert validator is not None  # guaranteed once _require_active() passed
        try:
            return await validate_panel_bearer(request, validator)
        except PanelForbiddenError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except PanelAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def _cosmos_client() -> PanelCosmosClient:
        return get_panel_cosmos_client(settings, config)

    def _cursor_manager() -> PanelCursorManager:
        secret = os.environ.get("CHAINLIT_AUTH_SECRET", "")
        return PanelCursorManager(
            secret=secret, ttl_seconds=settings.cursor_ttl_seconds
        )

    async def _owner_gate(
        principal: PanelPrincipal, conversation_id: str
    ) -> OwnerIndexRow:
        """The only accepted authorization check before any per-conversation
        read, feedback operation, or delete. Cosmos-only; the
        managed-Conversations store is never touched before this passes."""
        try:
            row = await get_owner_index_row(
                client=_cosmos_client(),
                principal_id=principal.oid,
                conversation_id=conversation_id,
            )
        except PanelValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except PanelStoreError as exc:
            raise HTTPException(
                status_code=502, detail="Panel metadata store failed."
            ) from exc
        if row is None:
            raise _not_found()
        return row

    @router.get("/panel/conversations", response_model=ConversationsListResponse)
    async def list_conversations(
        request: Request,
        cursor: str = "",
        limit: int = Query(default=_DEFAULT_LIST_LIMIT, ge=1, le=_MAX_LIST_LIMIT),
    ) -> ConversationsListResponse:
        _require_active()
        principal = await _authenticate(request)

        cursor_manager = _cursor_manager()
        try:
            skip = cursor_manager.resolve(cursor or None, oid=principal.oid)
        except PanelCursorError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        try:
            rows, has_more = await list_owner_index_rows(
                client=_cosmos_client(),
                principal_id=principal.oid,
                skip=skip,
                limit=limit,
            )
        except PanelStoreError as exc:
            raise HTTPException(
                status_code=502, detail="Panel metadata store failed."
            ) from exc

        next_cursor = (
            cursor_manager.mint(oid=principal.oid, skip=skip + limit)
            if has_more
            else None
        )
        return ConversationsListResponse(
            items=[
                ConversationSummary(
                    id=row.conversation_id,
                    title=row.title,
                    created_at=row.created_at,
                    updated_at=row.updated_at,
                )
                for row in rows
            ],
            next_cursor=next_cursor,
        )

    @router.get(
        "/panel/conversations/{conversation_id}/messages",
        response_model=MessagesResponse,
    )
    async def get_messages(
        conversation_id: str,
        request: Request,
        limit: int = Query(default=_MAX_MESSAGES_LIMIT, ge=1, le=_MAX_MESSAGES_LIMIT),
    ) -> MessagesResponse:
        _require_active()
        principal = await _authenticate(request)
        await _owner_gate(principal, conversation_id)

        store = get_conversation_store()
        try:
            items = await store.list_items_ascending(
                oid=principal.oid,
                conversation_id=conversation_id,
                limit=limit,
                user_access_token=principal.access_token,
            )
        except ConversationStoreAccessDeniedError as exc:
            # The owner-index row passed, but the system of record itself
            # denies or cannot find it (e.g. a stale row): fail closed with
            # the same opaque not-found -- never disclose which check failed.
            raise _not_found() from exc
        except ConversationStoreError as exc:
            raise HTTPException(
                status_code=502, detail="The managed-Conversations store failed."
            ) from exc

        return MessagesResponse(
            items=[
                MessageOut(
                    role=item.role,
                    content=item.content[:_MAX_MESSAGE_CONTENT_CHARS],
                )
                for item in items
            ]
        )

    @router.post(
        "/panel/conversations/{conversation_id}/feedback",
        response_model=FeedbackOut,
    )
    async def post_feedback(
        conversation_id: str,
        body: FeedbackCreateRequest,
        request: Request,
    ) -> FeedbackOut:
        _require_active()
        principal = await _authenticate(request)
        await _owner_gate(principal, conversation_id)

        try:
            record = await create_feedback(
                client=_cosmos_client(),
                principal_id=principal.oid,
                conversation_id=conversation_id,
                feedback_id=body.feedback_id,
                message_ref=body.message_ref,
                rating=body.rating,
                category=body.category,
                comment=body.comment,
            )
        except PanelValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except PanelStoreError as exc:
            raise HTTPException(
                status_code=502, detail="Panel metadata store failed."
            ) from exc

        return FeedbackOut(
            feedback_id=record.feedback_id,
            message_ref=record.message_ref,
            rating=record.rating,
            category=record.category,
            comment=record.comment,
            created_at=record.created_at,
        )

    @router.get(
        "/panel/conversations/{conversation_id}/feedback",
        response_model=FeedbackListResponse,
    )
    async def get_feedback(
        conversation_id: str, request: Request
    ) -> FeedbackListResponse:
        _require_active()
        principal = await _authenticate(request)
        await _owner_gate(principal, conversation_id)

        try:
            records = await list_feedback_for_conversation(
                client=_cosmos_client(),
                principal_id=principal.oid,
                conversation_id=conversation_id,
            )
        except PanelStoreError as exc:
            raise HTTPException(
                status_code=502, detail="Panel metadata store failed."
            ) from exc

        return FeedbackListResponse(
            items=[
                FeedbackOut(
                    feedback_id=record.feedback_id,
                    message_ref=record.message_ref,
                    rating=record.rating,
                    category=record.category,
                    comment=record.comment,
                    created_at=record.created_at,
                )
                for record in records
            ]
        )

    @router.delete(
        "/panel/conversations/{conversation_id}",
        response_model=DeleteConversationResponse,
    )
    async def delete_conversation(
        conversation_id: str, request: Request
    ) -> DeleteConversationResponse:
        _require_active()
        principal = await _authenticate(request)
        await _owner_gate(principal, conversation_id)

        store = get_conversation_store()
        try:
            await store.delete_conversation(
                oid=principal.oid,
                conversation_id=conversation_id,
                user_access_token=principal.access_token,
            )
        except ConversationStoreError as exc:
            # The system-of-record delete itself failed. Nothing else is
            # touched, and no success of any kind is ever reported.
            raise HTTPException(
                status_code=502,
                detail="Failed to delete the managed conversation.",
            ) from exc

        # The system-of-record delete succeeded. From here on, a metadata
        # cleanup failure must never be reported as a plain success -- it is
        # surfaced as an explicit partial-failure status instead.
        cleanup_failed = False
        try:
            await delete_feedback_for_conversation(
                client=_cosmos_client(),
                principal_id=principal.oid,
                conversation_id=conversation_id,
            )
        except PanelStoreError:
            logger.exception(
                "[panel_routes] feedback cleanup failed after conversation "
                "delete (conversation=%s)",
                conversation_id,
            )
            cleanup_failed = True

        try:
            await delete_owner_index_row(
                client=_cosmos_client(),
                principal_id=principal.oid,
                conversation_id=conversation_id,
            )
        except PanelStoreError:
            logger.exception(
                "[panel_routes] owner-index cleanup failed after conversation "
                "delete (conversation=%s)",
                conversation_id,
            )
            cleanup_failed = True

        if cleanup_failed:
            return DeleteConversationResponse(
                status="partial",
                detail=(
                    "The conversation was deleted, but some panel metadata "
                    "could not be cleaned up. Retry the deletion to finish "
                    "cleanup."
                ),
            )
        return DeleteConversationResponse(status="deleted")

    app.include_router(router)
