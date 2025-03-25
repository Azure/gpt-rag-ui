import logging
import os
from typing import Dict, List

import httpx
import msal
import chainlit as cl


def read_env_list(var_name: str) -> List[str]:
    """Reads a comma-separated list from the environment variable."""
    value = os.getenv(var_name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def get_env_var(name: str, fallback: str = None) -> str:
    """Helper to fetch and log missing environment variables."""
    value = os.getenv(name, fallback)
    if value is None:
        logging.warning(f"[auth] Environment variable '{name}' is not set.")
    return value


async def get_user_groups(access_token: str) -> List[str]:
    """Fetch user group names from Microsoft Graph API."""
    graph_url = "https://graph.microsoft.com/v1.0/me/memberOf"
    headers = {"Authorization": f"Bearer {access_token}"}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(graph_url, headers=headers)
            response.raise_for_status()
            group_data = response.json()
        groups = [g.get("displayName", "unknown-group") for g in group_data.get("value", [])]
        logging.info(f"[auth] User groups: {groups}")
        return groups
    except Exception as e:
        logging.warning(f"[auth] Failed to retrieve groups: {e}")
        return []


def is_user_authorized(name: str, principal_id: str, groups: List[str]) -> bool:
    """Check if user is authorized based on group or user criteria."""
    allowed_names = read_env_list("ALLOWED_USER_NAMES")
    allowed_ids = read_env_list("ALLOWED_USER_PRINCIPALS")
    allowed_groups = read_env_list("ALLOWED_GROUP_NAMES")

    if not (allowed_names or allowed_ids or allowed_groups):
        return True

    if name in allowed_names or principal_id in allowed_ids:
        return True

    if any(group in allowed_groups for group in groups):
        return True

    logging.info(f"[auth] Access denied for user {name}. Not in allowed users or groups.")
    return False


@cl.oauth_callback
async def oauth_callback(
    provider_id: str, code: str, raw_user_data: Dict[str, str], default_user: cl.User
) -> cl.User:
    """Handles the OAuth callback and returns a validated Chainlit User."""
    client_id = get_env_var("OAUTH_AZURE_AD_CLIENT_ID", get_env_var("CLIENT_ID"))
    client_secret = get_env_var("OAUTH_AZURE_AD_CLIENT_SECRET")
    tenant_id = get_env_var("OAUTH_AZURE_AD_TENANT_ID")
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    scopes = read_env_list("OAUTH_AZURE_AD_SCOPES") or ["User.Read"]

    # Build MSAL confidential client
    msal_app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret
    )

    result = msal_app.acquire_token_by_refresh_token(
        refresh_token=default_user.metadata.get("refresh_token"),
        scopes=scopes
    )

    if "error" in result:
        error_desc = result.get("error_description", "Unknown error")
        raise Exception(f"Token acquisition failed: {error_desc}")

    access_token = result.get("access_token")
    refresh_token = result.get("refresh_token")
    id_token = result.get("id_token_claims", {})

    user_id = id_token.get("oid", "00000000-0000-0000-0000-000000000000")
    user_name = id_token.get("name", "anonymous")
    principal_name = id_token.get("preferred_username", "")

    # Fetch user groups
    groups = await get_user_groups(access_token) if access_token else []
    authorized = is_user_authorized(principal_name, user_id, groups)

    return cl.User(
        identifier=user_name,
        metadata={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "authorized": authorized,
            "user_name": user_name,
            "client_principal_id": user_id,
            "client_principal_name": principal_name,
            "client_group_names": groups
        }
    )
