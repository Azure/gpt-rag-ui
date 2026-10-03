"""Compatibility exports; implementation lives in gpt_rag_ui.auth.auth_common."""

from gpt_rag_ui.auth.auth_common import (
    canonical_principal_id as canonical_principal_id,
    is_user_authorized as is_user_authorized,
    normalize_guid as normalize_guid,
)
