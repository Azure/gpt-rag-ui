"""Compatibility exports; implementation lives in gpt_rag_ui.auth.panel_auth."""

from gpt_rag_ui.auth.panel_auth import (
    PanelAuthError as PanelAuthError,
    PanelForbiddenError as PanelForbiddenError,
    PanelPrincipal as PanelPrincipal,
    validate_panel_bearer as validate_panel_bearer,
)
