"""Compatibility exports; implementation lives in gpt_rag_ui.services.feedback."""

from gpt_rag_ui.services.feedback import (
    ENABLE_FEEDBACK as ENABLE_FEEDBACK,
    FEEDBACK_RATING as FEEDBACK_RATING,
    create_feedback_actions as create_feedback_actions,
)
from gpt_rag_ui.api.feedback import register_feedback_handlers as register_feedback_handlers
