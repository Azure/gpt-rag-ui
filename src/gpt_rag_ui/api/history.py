"""Chainlit history callbacks, session bridge, factory and registration."""

import logging
from contextvars import ContextVar
from typing import Any

import chainlit as cl
from chainlit.context import ChainlitContextException
from chainlit.data.base import BaseDataLayer
from chainlit.step import StepDict
from chainlit.types import PaginatedResponse, Pagination, ThreadDict, ThreadFilter
from chainlit.user import PersistedUser, User

from gpt_rag_ui.auth.embed_auth import get_request_copilot_session
from gpt_rag_ui.services.history import HistoryOperationContext, HistoryService

logger = logging.getLogger("gpt_rag_ui.datalayer")
_request_user_metadata: ContextVar[dict | None] = ContextVar(
    "request_user_metadata", default=None,
)
_registered = False


def _get_session_metadata() -> dict | None:
    """Resolve live session metadata before consuming the authenticated request."""
    try:
        from chainlit.context import context

        if context and context.session and context.session.user:
            metadata = context.session.user.metadata
            if metadata:
                logger.debug("_get_session_metadata: found via context.session.user")
                return metadata
    except ChainlitContextException:
        logger.debug("_get_session_metadata: context.session.user not available")

    try:
        user = cl.user_session.get("user")
        if user and hasattr(user, "metadata") and user.metadata:
            logger.debug("_get_session_metadata: found via cl.user_session")
            return user.metadata
    except ChainlitContextException:
        logger.debug("_get_session_metadata: cl.user_session not available")

    if request_metadata := _request_user_metadata.get():
        _request_user_metadata.set(None)
        logger.debug("_get_session_metadata: consumed authenticated request context")
        return request_metadata
    logger.warning("_get_session_metadata: no metadata found via any source")
    return None


class OrchestratorDataLayer(BaseDataLayer):
    """Adapt Chainlit callbacks to history operations without owning user state."""

    def __init__(self) -> None:
        self._history = HistoryService()

    async def get_user(self, identifier: str) -> PersistedUser | None:
        user = await self._history.get_user(
            HistoryOperationContext(request_session=get_request_copilot_session()), identifier,
        )
        if user and user.metadata:
            _request_user_metadata.set(user.metadata)
        return user

    async def create_user(self, user: User) -> PersistedUser | None:
        persisted = await self._history.create_user(user)
        if persisted:
            _request_user_metadata.set(persisted.metadata)
        return persisted

    async def create_thread(self, thread_dict: ThreadDict) -> str:
        return thread_dict["id"]

    async def list_threads(
        self, pagination: Pagination, filters: ThreadFilter
    ) -> PaginatedResponse[ThreadDict]:
        return await self._history.list_threads(
            HistoryOperationContext(metadata=_get_session_metadata()), pagination, filters,
        )

    async def get_thread(self, thread_id: str) -> ThreadDict | None:
        return await self._history.get_thread(
            HistoryOperationContext(metadata=_get_session_metadata()), thread_id,
        )

    async def get_thread_author(self, thread_id: str) -> Any:
        # Chainlit annotates this as str, but the existing denial result is None.
        return await self._history.get_thread_author(
            HistoryOperationContext(metadata=_get_session_metadata()), thread_id,
        )

    async def update_thread(
        self,
        thread_id: str,
        name: str | None = None,
        user_id: str | None = None,
        metadata: dict | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        await self._history.update_thread(
            HistoryOperationContext(metadata=_get_session_metadata()),
            thread_id,
            on_authorized=self._select_thread,
            name=name,
            **kwargs,
        )

    def _select_thread(self, thread_id: str) -> None:
        try:
            cl.user_session.set("conversation_id", thread_id)
        except ChainlitContextException:
            logger.debug("update_thread: could not set conversation_id without a Chainlit session")

    async def delete_thread(self, thread_id: str) -> bool:
        return await self._history.delete_thread(
            HistoryOperationContext(metadata=_get_session_metadata()), thread_id,
        )

    async def upsert_feedback(self, feedback: Any) -> str:
        return ""

    async def delete_feedback(self, feedback_id: str) -> bool:
        return True

    async def create_element(self, element_dict: Any) -> None:
        pass

    async def get_element(self, thread_id: str, element_id: str) -> None:
        return None

    async def delete_element(self, element_id: str) -> bool:
        return True

    async def create_step(self, step_dict: StepDict) -> StepDict:
        return step_dict

    async def update_step(self, step_dict: StepDict) -> StepDict:
        return step_dict

    async def delete_step(self, step_id: str) -> bool:
        return True

    async def delete_user_session(self, id: str) -> bool:
        return True

    async def build_debug_url(self) -> str:
        return ""

    async def close(self) -> None:
        pass


def get_data_layer() -> OrchestratorDataLayer:
    return OrchestratorDataLayer()


def register_data_layer() -> None:
    global _registered
    if not _registered:
        cl.data_layer(get_data_layer)
        _registered = True
