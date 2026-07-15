"""
Stateless data layer for Chainlit that persists conversations via the orchestrator API.

No direct database access — all conversation data flows through the orchestrator service.
User identity is resolved from the Chainlit session context (populated by OAuth).
"""

import logging
import uuid
from contextvars import ContextVar
from datetime import datetime
from typing import Optional

import chainlit as cl
from chainlit.data.base import BaseDataLayer
from chainlit.step import StepDict
from chainlit.types import (
    PaginatedResponse,
    Pagination,
    ThreadDict,
    ThreadFilter,
    PageInfo,
)
from chainlit.user import PersistedUser, User

from orchestrator_client import (
    call_orchestrator_list_conversations,
    call_orchestrator_update_conversation,
    call_orchestrator_delete_conversation,
)
from conversation_security import (
    get_owned_conversation,
    principal_id_from_metadata,
)
from embed_auth import resolve_access_token

logger = logging.getLogger("gpt_rag_ui.datalayer")

# In-memory user store: identifier -> PersistedUser
# Populated on login, lost on restart (acceptable: users re-auth via OAuth each session).
_users: dict[str, PersistedUser] = {}
_request_user_metadata: ContextVar[Optional[dict]] = ContextVar(
    "request_user_metadata",
    default=None,
)


def _get_current_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")


def _get_session_metadata() -> Optional[dict]:
    """Safely retrieve user metadata from the current Chainlit session context."""
    # Primary: Chainlit internal context
    try:
        from chainlit.context import context
        if context and context.session and context.session.user:
            metadata = context.session.user.metadata
            if metadata:
                logger.debug("_get_session_metadata: found via context.session.user (keys=%s)", sorted(metadata.keys()))
                return metadata
            else:
                logger.debug("_get_session_metadata: context.session.user exists but metadata is empty")
    except Exception as e:
        logger.debug("_get_session_metadata: context.session.user not available: %s", e)

    # Secondary: cl.user_session (different API, may work in different contexts)
    try:
        user = cl.user_session.get("user")
        if user and hasattr(user, "metadata") and user.metadata:
            logger.debug("_get_session_metadata: found via cl.user_session (keys=%s)", sorted(user.metadata.keys()))
            return user.metadata
    except Exception as e:
        logger.debug("_get_session_metadata: cl.user_session not available: %s", e)

    if metadata := _request_user_metadata.get():
        logger.debug(
            "_get_session_metadata: found via authenticated request context (keys=%s)",
            sorted(metadata.keys()),
        )
        return metadata

    logger.warning("_get_session_metadata: no metadata found via any source")
    return None


@cl.data_layer
def get_data_layer():
    return OrchestratorDataLayer()


class OrchestratorDataLayer(BaseDataLayer):
    """Chainlit data layer backed by the orchestrator API for conversations
    and an in-memory store for user management."""

    # ── User management (in-memory) ──────────────────────────────────────

    async def get_user(self, identifier: str) -> Optional[PersistedUser]:
        user = _users.get(identifier)
        if user and user.metadata:
            _request_user_metadata.set(user.metadata)
        return user

    async def create_user(self, user: User) -> Optional[PersistedUser]:
        principal_id = principal_id_from_metadata(user.metadata)
        if not principal_id or user.identifier.lower() != principal_id:
            logger.warning(
                "Refusing user with missing or inconsistent canonical identity"
            )
            return None

        persisted = PersistedUser(
            id=principal_id,
            identifier=principal_id,
            createdAt=_get_current_timestamp(),
            metadata=user.metadata or {},
        )
        _users[user.identifier] = persisted
        _request_user_metadata.set(persisted.metadata)
        return persisted

    # ── Thread / conversation operations (via orchestrator API) ──────────

    async def create_thread(self, thread_dict: ThreadDict) -> str:
        return thread_dict["id"]

    async def list_threads(
        self,
        pagination: Pagination,
        filters: ThreadFilter,
    ) -> PaginatedResponse[ThreadDict]:
        empty = PaginatedResponse(
            data=[],
            pageInfo=PageInfo(hasNextPage=False, startCursor=None, endCursor=None),
        )

        logger.info("list_threads called: pagination=%s filters=%s", pagination, filters)

        metadata = _get_session_metadata()
        if not metadata:
            logger.warning("list_threads: no session metadata; returning empty")
            return empty

        principal_id = principal_id_from_metadata(metadata)
        if not principal_id:
            logger.warning(
                "list_threads: canonical tid:oid identity is missing; returning empty"
            )
            return empty

        access_token = await resolve_access_token(metadata)
        logger.info(
            "list_threads: metadata found (has_access_token=%s, user_name=%s, principal_id=%s)",
            bool(access_token),
            metadata.get("user_name"),
            metadata.get("principal_id") or metadata.get("client_principal_id"),
        )
        if not access_token:
            logger.warning("list_threads: no access_token in session metadata; returning empty (user may not be authenticated)")
            return empty

        skip = 0
        limit = 10
        if hasattr(pagination, "first") and pagination.first:
            limit = int(pagination.first)
        if hasattr(pagination, "cursor") and pagination.cursor:
            try:
                skip = int(pagination.cursor)
            except (ValueError, TypeError):
                pass

        result = await call_orchestrator_list_conversations(
            access_token=access_token,
            skip=skip,
            limit=limit,
        )

        conversations = result.get("conversations", [])
        has_more = result.get("has_more", False)
        logger.info("list_threads: orchestrator returned %d conversations (skip=%d, limit=%d)", len(conversations), skip, limit)

        threads = []
        for conv in conversations:
            conversation_id = str(conv.get("id") or "").strip()
            if not conversation_id:
                logger.warning("list_threads: omitted conversation without an id")
                continue
            # The orchestrator list endpoint validates the same bearer token and
            # queries only that oid partition. Its compact response intentionally
            # omits principal_id, so the UI binds each returned thread to the
            # canonical tid:oid identity rather than inventing an owner fallback.
            threads.append(
                ThreadDict(
                    id=conversation_id,
                    name=conv.get("name", ""),
                    createdAt=conv.get("lastUpdated"),
                    userId=principal_id,
                    userIdentifier=principal_id,
                    tags=[],
                    metadata={},
                    steps=[],
                )
            )

        return PaginatedResponse(
            data=threads,
            pageInfo=PageInfo(
                hasNextPage=has_more,
                startCursor=str(skip),
                endCursor=str(skip + len(threads)) if has_more else None,
            ),
        )

    async def get_thread(self, thread_id: str) -> Optional[ThreadDict]:
        metadata = _get_session_metadata()
        if not metadata:
            logger.warning(
                "get_thread: no session metadata; returning None for thread=%s",
                thread_id,
            )
            return None

        conv = await get_owned_conversation(thread_id, metadata)
        if not conv:
            logger.warning(
                "get_thread: conversation missing or ownership denied for thread=%s",
                thread_id,
            )
            return None

        messages = conv.get("messages", [])
        principal_id = principal_id_from_metadata(metadata)
        steps = self._messages_to_steps(messages, thread_id, principal_id)

        ts_value = conv.get("_ts")
        created_at = None
        if ts_value:
            try:
                if isinstance(ts_value, str):
                    created_at = ts_value if ts_value.endswith("Z") else ts_value + "Z"
                else:
                    created_at = datetime.fromtimestamp(ts_value).isoformat() + "Z"
            except (ValueError, TypeError):
                pass

        return ThreadDict(
            id=conv["id"],
            name=conv.get("name", ""),
            createdAt=created_at,
            userId=principal_id,
            userIdentifier=principal_id,
            tags=[],
            metadata={},
            steps=steps,
        )

    async def get_thread_author(self, thread_id: str) -> Optional[str]:
        thread = await self.get_thread(thread_id)
        if thread:
            return thread.get("userIdentifier")
        return None

    async def update_thread(self, thread_id: str, **kwargs) -> None:
        metadata = _get_session_metadata()
        if not metadata:
            logger.warning(
                "update_thread: no session metadata; cannot rename thread=%s",
                thread_id,
            )
            return

        if not await get_owned_conversation(thread_id, metadata):
            logger.warning("update_thread: ownership denied for thread=%s", thread_id)
            return

        try:
            cl.user_session.set("conversation_id", thread_id)
        except Exception as exc:
            logger.debug(
                "update_thread: could not set conversation_id in session: %s",
                exc,
            )

        name_value = kwargs.get("name") or kwargs.get("title") or ""
        name = str(name_value).strip()
        if not name:
            return
        access_token = await resolve_access_token(metadata)
        if not access_token:
            logger.warning("update_thread: auth session unavailable for thread=%s", thread_id)
            return

        updated = await call_orchestrator_update_conversation(
            access_token=access_token,
            conversation_id=thread_id,
            name=name,
        )
        if not updated:
            logger.warning("update_thread: orchestrator rename failed for thread=%s", thread_id)

    async def delete_thread(self, thread_id: str) -> bool:
        metadata = _get_session_metadata()
        if not metadata:
            logger.warning(
                "delete_thread: no session metadata; cannot delete thread=%s",
                thread_id,
            )
            return False

        if not await get_owned_conversation(thread_id, metadata):
            logger.warning("delete_thread: ownership denied for thread=%s", thread_id)
            return False
        access_token = await resolve_access_token(metadata)
        if not access_token:
            logger.warning("delete_thread: no access_token; cannot delete thread=%s", thread_id)
            return False

        return await call_orchestrator_delete_conversation(
            access_token=access_token,
            conversation_id=thread_id,
        )

    # ── Stub methods (not backed by external storage) ────────────────────

    async def upsert_feedback(self, feedback) -> str:
        return ""

    async def delete_feedback(self, feedback_id: str) -> bool:
        return True

    async def create_element(self, element_dict) -> None:
        pass

    async def get_element(self, thread_id: str, element_id: str):
        return None

    async def delete_element(self, element_id: str) -> bool:
        return True

    async def create_step(self, step_dict) -> StepDict:
        return step_dict

    async def update_step(self, step_dict) -> StepDict:
        return step_dict

    async def delete_step(self, step_id: str) -> bool:
        return True

    async def delete_user_session(self, id: str) -> bool:
        return True

    async def build_debug_url(self) -> str:
        return ""

    async def close(self) -> None:
        pass

    # ── Helpers ──────────────────────────────────────────────────────────

    def _messages_to_steps(
        self,
        messages: list,
        thread_id: str,
        principal_id: str,
    ) -> list:
        """Convert orchestrator conversation messages to Chainlit StepDict format."""
        # Lazy import to avoid circular dependency (app.py imports datalayer).
        from app import replace_source_reference_links

        steps = []
        for msg in messages:
            role = msg.get("role", "")
            text = msg.get("text", "")
            step_type = "user_message" if role == "user" else "assistant_message"

            # Resolve source reference links so markdown renders on resume.
            if step_type == "assistant_message" and text:
                text = replace_source_reference_links(
                    text,
                    conversation_id=thread_id,
                    principal_id=principal_id,
                )

            steps.append({
                "id": str(uuid.uuid4()),
                "threadId": thread_id,
                "type": step_type,
                "output": text,
                "createdAt": _get_current_timestamp(),
                "isError": False,
                "metadata": {},
            })
        return steps
