"""Chainlit data-layer registration over the history service."""

import chainlit as cl

from gpt_rag_ui.services.history import OrchestratorDataLayer, get_data_layer

_registered = False


def register_data_layer() -> None:
    global _registered
    if not _registered:
        cl.data_layer(get_data_layer)
        _registered = True
