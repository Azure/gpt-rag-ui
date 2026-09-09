"""Compatibility exports; implementation lives in gpt_rag_ui.services.conversation_security."""

from gpt_rag_ui.services.conversation_security import (
    canonical_conversation_id as canonical_conversation_id,
    conversation_belongs_to as conversation_belongs_to,
    get_owned_conversation as get_owned_conversation,
    principal_id_from_metadata as principal_id_from_metadata,
    thread_owner_id_from_metadata as thread_owner_id_from_metadata,
)
