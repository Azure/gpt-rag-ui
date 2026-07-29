"""Chat backend selection shared by runtime wiring and focused tests."""

from typing import Literal

ChatBackend = Literal["orchestrator", "hosted_agent"]


def resolve_chat_backend(value: str | None) -> ChatBackend:
    backend = (value or "orchestrator").strip().lower()
    if backend not in {"orchestrator", "hosted_agent"}:
        raise RuntimeError(
            f"Unknown CHAT_BACKEND value: {backend!r}. "
            "Valid values are 'orchestrator' (default) and 'hosted_agent'."
        )
    return backend


def select_upload_conversation_id(
    backend: ChatBackend,
    *,
    classic_conversation_id: str,
    hosted_conversation_id: str,
) -> str:
    """Select only the conversation namespace owned by the active backend."""
    if backend == "hosted_agent":
        return hosted_conversation_id.strip()
    return classic_conversation_id.strip()
