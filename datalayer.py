"""Compatibility exports; implementation lives in gpt_rag_ui.services.history."""

from gpt_rag_ui.services.history import (
    OrchestratorDataLayer as OrchestratorDataLayer,
    get_data_layer as get_data_layer,
)
from gpt_rag_ui.api.history import register_data_layer

register_data_layer()
