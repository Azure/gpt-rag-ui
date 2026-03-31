"""
Stateless data layer for Chainlit that persists conversations via the orchestrator API.

No direct database access — all conversation data flows through the orchestrator service.
User identity is resolved from the Chainlit session context (populated by OAuth).
"""

import logging
import uuid
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
    call_orchestrator_get_conversation,
    call_orchestrator_delete_conversation,
)

logger = logging.getLogger("gpt_rag_ui.datalayer")

# In-memory user store: identifier -> PersistedUser
# Populated on login, lost on restart (acceptable: users re-auth via OAuth each session).
_users: dict[str, PersistedUser] = {}


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
        return _users.get(identifier)

    async def create_user(self, user: User) -> Optional[PersistedUser]:
        principal_id = None
        if user.metadata:
            principal_id = user.metadata.get("principal_id") or user.metadata.get("client_principal_id")

        if not principal_id:
            logger.warning("No principal_id in user metadata for %s", user.identifier)
            return None

        persisted = PersistedUser(
            id=user.identifier,
            identifier=user.identifier,
            createdAt=_get_current_timestamp(),
            metadata=user.metadata or {},
        )
        _users[user.identifier] = persisted
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
            # Fallback: try in-memory user store
            user_id = filters.userId if hasattr(filters, "userId") else None
            if user_id and user_id in _users:
                metadata = _users[user_id].metadata
            else:
                logger.warning("list_threads: no session metadata and no in-memory user found; returning empty")
                return empty

        access_token = metadata.get("access_token")
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
            threads.append(
                ThreadDict(
                    id=conv.get("id"),
                    name=conv.get("name", ""),
                    createdAt=conv.get("lastUpdated"),
                    userId=metadata.get("principal_id", ""),
                    userIdentifier=metadata.get("user_name", ""),
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
            # Fallback: try in-memory user store (session context may not be
            # available when Chainlit calls get_thread during resume).
            for user in _users.values():
                if user.metadata and user.metadata.get("access_token"):
                    metadata = user.metadata
                    logger.debug("get_thread: using in-memory user '%s' as fallback for thread=%s", user.identifier, thread_id)
                    break
            if not metadata:
                logger.warning("get_thread: no session metadata and no in-memory user found; returning None for thread=%s", thread_id)
                return None

        access_token = metadata.get("access_token")
        if not access_token:
            logger.warning("get_thread: no access_token in session metadata; returning None for thread=%s", thread_id)
            return None

        conv = await call_orchestrator_get_conversation(
            access_token=access_token,
            conversation_id=thread_id,
        )
        if not conv:
            logger.warning("get_thread: orchestrator returned no data for thread=%s", thread_id)
            return None

        messages = conv.get("messages", [])
        steps = self._messages_to_steps(messages, thread_id)

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

        principal_id = conv.get("principal_id", "")
        user_context = conv.get("user_context", {})
        # Prefer the Chainlit session/in-memory user_name so userIdentifier
        # matches user.identifier used by Chainlit's authorization check.
        user_identifier = (
            metadata.get("user_name")
            or user_context.get("user_name")
            or principal_id
        )
        logger.debug(
            "get_thread: thread=%s userIdentifier='%s' (meta=%s, ctx=%s, pid=%s)",
            thread_id, user_identifier,
            metadata.get("user_name"), user_context.get("user_name"), principal_id,
        )

        return ThreadDict(
            id=conv["id"],
            name=conv.get("name", ""),
            createdAt=created_at,
            userId=principal_id,
            userIdentifier=user_identifier,
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
        try:
            cl.user_session.set("conversation_id", thread_id)
        except Exception:
            pass

    async def delete_thread(self, thread_id: str) -> bool:
        metadata = _get_session_metadata()
        if not metadata:
            for user in _users.values():
                if user.metadata and user.metadata.get("access_token"):
                    metadata = user.metadata
                    break
            if not metadata:
                logger.warning("delete_thread: no session metadata; cannot delete thread=%s", thread_id)
                return False

        access_token = metadata.get("access_token")
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

    def _messages_to_steps(self, messages: list, thread_id: str) -> list:
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
                text = replace_source_reference_links(text)

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
