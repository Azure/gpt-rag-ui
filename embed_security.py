"""Compatibility exports; implementation lives in gpt_rag_ui.auth.embed_security."""

from gpt_rag_ui.auth.embed_security import (
    CopilotRequestMiddleware as CopilotRequestMiddleware,
    CopilotSocketRegistry as CopilotSocketRegistry,
    DEFAULT_MAX_CONNECTIONS_PER_SESSION as DEFAULT_MAX_CONNECTIONS_PER_SESSION,
    SocketDisconnect as SocketDisconnect,
    canonical_origin as canonical_origin,
    configure_copilot_bridge_guards as configure_copilot_bridge_guards,
    disconnect_copilot_session as disconnect_copilot_session,
)
