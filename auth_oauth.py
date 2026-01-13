import logging
from typing import Dict, List

import chainlit as cl
import httpx
import msal

from dependencies import get_config

logger = logging.getLogger("gpt_rag_ui.auth_oauth")

config = get_config()


def read_env_list(var_name: str) -> List[str]:
    value = config.get(var_name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def get_env_var(name: str, fallback: str | None = None) -> str | None:
    value = config.get(name, fallback)
    if value is None:
        logger.warning("Environment variable '%s' is not set", name)
    return value


async def get_user_groups(access_token: str) -> List[str]:
    graph_url = "https://graph.microsoft.com/v1.0/me/memberOf"
    headers = {"Authorization": f"Bearer {access_token}"}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(graph_url, headers=headers)
            response.raise_for_status()
            group_data = response.json()
        return [g.get("displayName", "unknown-group") for g in group_data.get("value", [])]
    except Exception as exc:
        logger.warning("Failed to retrieve groups from Graph API: %s", exc)
        return []


def is_user_authorized(name: str, principal_id: str, groups: List[str]) -> bool:
    allowed_names = read_env_list("ALLOWED_USER_NAMES")
    allowed_ids = read_env_list("ALLOWED_USER_PRINCIPALS")
    allowed_groups = read_env_list("ALLOWED_GROUP_NAMES")

    if not (allowed_names or allowed_ids or allowed_groups):
        return True

    if name in allowed_names or principal_id in allowed_ids:
        return True

    if any(group in allowed_groups for group in groups):
        return True

    logger.warning(
        "Access denied for principal '%s' (%s). No matching allow list entry.",
        name,
        principal_id,
    )
    return False


@cl.oauth_callback
async def oauth_callback(
    provider_id: str, code: str, raw_user_data: Dict[str, str], default_user: cl.User
) -> cl.User:
    """Optional OAuth callback flow (non-EasyAuth deployments).

    Uses MSAL to exchange Chainlit refresh_token for an AAD access token.
    """

    logger.info("OAuth callback received for provider '%s'", provider_id)

    client_id = get_env_var("OAUTH_AZURE_AD_CLIENT_ID", get_env_var("CLIENT_ID"))
    client_secret = get_env_var("OAUTH_AZURE_AD_CLIENT_SECRET")
    tenant_id = get_env_var("OAUTH_AZURE_AD_TENANT_ID")

    if not client_id or not client_secret or not tenant_id:
        raise RuntimeError("OAuth is not configured (missing OAUTH_AZURE_AD_* settings)")

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    scopes = read_env_list("OAUTH_AZURE_AD_SCOPES") or ["User.Read"]

    msal_app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret,
    )

    result = msal_app.acquire_token_by_refresh_token(
        refresh_token=default_user.metadata.get("refresh_token"),
        scopes=scopes,
    )

    if "error" in result:
        error_desc = result.get("error_description", "Unknown error")
        logger.error("Token acquisition failed: %s", error_desc)
        raise RuntimeError(f"Token acquisition failed: {error_desc}")

    access_token = result.get("access_token")
    refresh_token = result.get("refresh_token")
    id_token = result.get("id_token_claims", {})

    user_id = id_token.get("oid", "00000000-0000-0000-0000-000000000000")
    user_name = id_token.get("name", "anonymous")
    principal_name = id_token.get("preferred_username", "")

    groups = await get_user_groups(access_token) if access_token else []
    authorized = is_user_authorized(principal_name, user_id, groups)

    logger.info(
        "User authenticated: name='%s' principal='%s' authorized=%s groups=%d",
        user_name,
        principal_name or user_id,
        authorized,
        len(groups),
    )

    return cl.User(
        identifier=user_name,
        metadata={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "authorized": authorized,
            "auth_source": "oauth",
            "user_name": user_name,
            "client_principal_id": user_id,
            "client_principal_name": principal_name,
            "client_group_names": groups,
        },
    )
