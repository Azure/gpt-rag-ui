import logging
import os
from typing import Optional

import chainlit as cl
import httpx
from starlette.datastructures import Headers

from auth_common import is_user_authorized
from dependencies import get_config
from entra_token import EntraTokenError, EntraTokenValidator


logger = logging.getLogger("gpt_rag_ui.auth_header")
config = get_config()
validator = EntraTokenValidator(
    tenant_id=os.environ["CHAINLIT_COPILOT_ENTRA_TENANT_ID"],
    audience=os.environ["CHAINLIT_COPILOT_ENTRA_AUDIENCE"],
    required_scope=os.environ["CHAINLIT_COPILOT_ENTRA_REQUIRED_SCOPE"],
)


def _get_bearer_token(headers: Headers) -> str | None:
    authorization = headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if separator and scheme.lower() == "bearer" and token.strip():
        return token.strip()
    return None


@cl.header_auth_callback
async def header_auth_callback(headers: Headers) -> Optional[cl.User]:
    token = _get_bearer_token(headers)
    if not token:
        logger.warning("Embedded authentication rejected: bearer token missing")
        return None

    try:
        claims = await validator.validate(token)
    except (EntraTokenError, httpx.HTTPError):
        logger.warning(
            "Embedded authentication rejected: Entra token validation failed",
            exc_info=True,
        )
        return None

    principal_id = str(claims.get("oid") or claims["sub"])
    principal_name = str(
        claims.get("preferred_username")
        or claims.get("email")
        or claims.get("upn")
        or ""
    )
    display_name = str(claims.get("name") or principal_name or principal_id)
    groups = claims.get("groups")
    group_ids = [str(group) for group in groups] if isinstance(groups, list) else []
    authorized = is_user_authorized(config, principal_name, principal_id)

    logger.info(
        "Embedded user authorization evaluated: principal=%s authorized=%s",
        principal_name or principal_id,
        authorized,
    )
    if not authorized:
        return None

    return cl.User(
        identifier=principal_id,
        display_name=display_name,
        metadata={
            "access_token": token,
            "access_token_expires_at": int(claims["exp"]),
            "authorized": authorized,
            "auth_source": "entra_header",
            "user_name": principal_id,
            "client_principal_id": principal_id,
            "client_principal_name": principal_name,
            "client_group_names": group_ids,
            "principal_id": principal_id,
        },
    )
