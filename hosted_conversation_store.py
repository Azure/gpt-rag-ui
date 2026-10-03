"""Compatibility exports; implementation lives in gpt_rag_ui.clients.hosted_conversation_store."""

from gpt_rag_ui.clients.hosted_conversation_store import (
    ConversationIdempotencyCache as ConversationIdempotencyCache,
    ConversationItem as ConversationItem,
    ConversationLockRegistry as ConversationLockRegistry,
    ConversationStoreAccessDeniedError as ConversationStoreAccessDeniedError,
    ConversationStoreAuthenticationError as ConversationStoreAuthenticationError,
    ConversationStoreClient as ConversationStoreClient,
    ConversationStoreError as ConversationStoreError,
    ConversationStoreHTTPError as ConversationStoreHTTPError,
    ConversationStoreOwnerBinding as ConversationStoreOwnerBinding,
    ConversationStoreSettings as ConversationStoreSettings,
    build_bounded_history as build_bounded_history,
)
