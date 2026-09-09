"""Explicit, idempotent Chainlit OAuth callback registration."""

import chainlit as cl

from gpt_rag_ui.auth.oauth import oauth_callback

_registered = False


async def chainlit_oauth_callback(
    provider_id: str,
    code: str,
    raw_user_data: dict[str, str],
    default_user: cl.User,
    id_token: str | None = None,
) -> cl.User | None:
    return await oauth_callback(provider_id, code, raw_user_data, default_user)


def register_oauth_callback() -> None:
    global _registered
    if not _registered:
        cl.oauth_callback(chainlit_oauth_callback)
        _registered = True
