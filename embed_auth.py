"""Compatibility exports; implementation lives in gpt_rag_ui.auth.embed_auth."""

from gpt_rag_ui.auth.embed_auth import (
    ANONYMOUS_TENANT_ID as ANONYMOUS_TENANT_ID,
    BootstrapRateLimiter as BootstrapRateLimiter,
    COPILOT_SESSION_COOKIE as COPILOT_SESSION_COOKIE,
    CopilotSession as CopilotSession,
    CopilotSessionStore as CopilotSessionStore,
    SessionInvalidationCallback as SessionInvalidationCallback,
    TokenValidator as TokenValidator,
    bind_request_copilot_session as bind_request_copilot_session,
    bootstrap_rate_limit_key as bootstrap_rate_limit_key,
    clear_copilot_session_cookie as clear_copilot_session_cookie,
    configure_session_store as configure_session_store,
    create_embed_session_jwt as create_embed_session_jwt,
    get_request_copilot_session as get_request_copilot_session,
    get_session_store as get_session_store,
    is_copilot_session_active as is_copilot_session_active,
    is_valid_session_id as is_valid_session_id,
    reset_request_copilot_session as reset_request_copilot_session,
    resolve_access_token as resolve_access_token,
    session_id_from_request as session_id_from_request,
    set_copilot_session_cookie as set_copilot_session_cookie,
)
from gpt_rag_ui.api.embed_routes import register_copilot_auth_routes as register_copilot_auth_routes
