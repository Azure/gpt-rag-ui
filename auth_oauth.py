"""Compatibility exports; implementation lives in gpt_rag_ui.auth.oauth."""

from gpt_rag_ui.auth.oauth import (
    ensure_fresh_user_access_token as ensure_fresh_user_access_token,
    get_env_var as get_env_var,
    oauth_callback as oauth_callback,
    read_scopes_list as read_scopes_list,
    refresh_access_token as refresh_access_token,
)
from gpt_rag_ui.api.oauth import register_oauth_callback

register_oauth_callback()
