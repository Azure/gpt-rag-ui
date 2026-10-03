"""Compatibility exports; implementation lives in gpt_rag_ui.config.chat_backend."""

from gpt_rag_ui.config.chat_backend import (
    ChatBackend as ChatBackend,
    ChatBackendConfig as ChatBackendConfig,
    DEFAULT_CHAT_BACKEND as DEFAULT_CHAT_BACKEND,
    load_chat_backend as load_chat_backend,
    resolve_chat_backend as resolve_chat_backend,
    select_upload_conversation_id as select_upload_conversation_id,
)
