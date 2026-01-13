import base64
import json
import logging
import os
from typing import Any, Dict, List, Optional

import httpx
import chainlit as cl

from dependencies import get_config

logger = logging.getLogger("gpt_rag_ui.auth")

config = get_config()


def _is_running_in_azure_host() -> bool:
    # Heuristic: these env vars are present in Azure-managed hosting environments.
    # - App Service/EasyAuth commonly sets WEBSITE_SITE_NAME.
    # - Container Apps sets CONTAINER_APP_NAME / CONTAINER_APP_REVISION.
    return bool(
        os.environ.get("WEBSITE_SITE_NAME")
        or os.environ.get("CONTAINER_APP_NAME")
        or os.environ.get("CONTAINER_APP_REVISION")
    )


def _allow_anonymous() -> bool:
    # App setting override always wins.
    # Default behavior:
    # - Local/dev (not Azure host): allow anonymous.
    # - Azure host (ACA/App Service): require authentication unless explicitly allowed.
    default = not _is_running_in_azure_host()
    return config.get("ALLOW_ANONYMOUS", default, bool)

def read_env_list(var_name: str) -> List[str]:
    """Reads a comma-separated list from the environment variable."""
    value = config.get(var_name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


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
        logger.debug("Resolved %d group memberships", len(groups))
        return groups
    except Exception as e:
        logger.warning("Failed to retrieve groups from Graph API: %s", e)
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

    logger.warning(
        "Access denied for principal '%s' (%s). No matching allow list entry.",
        name,
        principal_id,
    )
    return False


def _normalize_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    if not headers:
        return {}
    return {str(key).lower(): value for key, value in headers.items() if key}


def _decode_client_principal(value: str) -> Dict[str, Any]:
    try:
        if not value:
            return {}
        padded = value + ("=" * (-len(value) % 4))
        raw = base64.b64decode(padded).decode("utf-8")
        decoded = json.loads(raw)
        return decoded if isinstance(decoded, dict) else {}
    except Exception as exc:
        logger.debug("Failed to decode X-MS-CLIENT-PRINCIPAL: %s", exc)
        return {}


def _claims_to_map(claims: Any) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    if not isinstance(claims, list):
        return result
    for item in claims:
        if not isinstance(item, dict):
            continue
        claim_type = item.get("typ")
        claim_value = item.get("val")
        if not claim_type or claim_value is None:
            continue
        result.setdefault(str(claim_type), []).append(str(claim_value))
    return result


def _first_claim(claim_map: Dict[str, List[str]], *keys: str) -> Optional[str]:
    for key in keys:
        values = claim_map.get(key) or []
        for value in values:
            normalized = (value or "").strip()
            if normalized:
                return normalized
    return None


if hasattr(cl, "header_auth_callback"):

    @cl.header_auth_callback
    async def header_auth_callback(headers: Dict[str, str]) -> Optional[cl.User]:
        """Authenticate using EasyAuth headers (Azure Container Apps / App Service).

        Expected headers include:
        - X-MS-CLIENT-PRINCIPAL, X-MS-CLIENT-PRINCIPAL-ID, X-MS-CLIENT-PRINCIPAL-NAME
        - X-MS-TOKEN-AAD-ACCESS-TOKEN (preferred), X-MS-TOKEN-AAD-ID-TOKEN (fallback)
        """

        h = _normalize_headers(headers)

        access_token = (h.get("x-ms-token-aad-access-token") or "").strip()
        id_token = (h.get("x-ms-token-aad-id-token") or "").strip()
        forwarded_token = access_token or id_token or None

        principal_name = (h.get("x-ms-client-principal-name") or "").strip()
        principal_id = (h.get("x-ms-client-principal-id") or "").strip()
        principal_b64 = (h.get("x-ms-client-principal") or "").strip()

        principal = _decode_client_principal(principal_b64) if principal_b64 else {}
        claim_map = _claims_to_map(principal.get("claims"))

        principal_id = (
            principal_id
            or (principal.get("userId") or principal.get("user_id") or "").strip()
            or _first_claim(
                claim_map,
                "oid",
                "http://schemas.microsoft.com/identity/claims/objectidentifier",
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
            )
            or ""
        )

        principal_name = (
            principal_name
            or (principal.get("userDetails") or principal.get("user_details") or "").strip()
            or _first_claim(
                claim_map,
                "preferred_username",
                "upn",
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                "name",
            )
            or ""
        )

        if not principal_id and not principal_name:
            if _allow_anonymous():
                return cl.User(
                    identifier="anonymous",
                    metadata={
                        "authorized": True,
                        "auth_source": "anonymous",
                        "client_principal_id": "no-auth",
                        "client_principal_name": "anonymous",
                        "client_group_names": [],
                        "access_token": None,
                    },
                )
            return None

        groups: List[str] = []
        if access_token:
            groups = await get_user_groups(access_token)

        authorized = is_user_authorized(principal_name, principal_id, groups)

        return cl.User(
            identifier=principal_name or principal_id,
            metadata={
                "authorized": authorized,
                "auth_source": "easyauth",
                "client_principal_id": principal_id,
                "client_principal_name": principal_name or principal_id,
                "client_group_names": groups,
                "access_token": forwarded_token,
                "id_token": id_token or None,
            },
        )

else:
    logger.warning("Chainlit has no header_auth_callback; EasyAuth headers won't be processed.")


def _oauth_is_configured() -> bool:
    # NOTE: AppConfig-backed `config.get()` raises if a key is missing unless a default is provided.
    # For EasyAuth deployments we don't want missing OAuth keys to crash startup.
    client_id = config.get("OAUTH_AZURE_AD_CLIENT_ID", "", str) or config.get("CLIENT_ID", "", str)
    client_secret = config.get("OAUTH_AZURE_AD_CLIENT_SECRET", "", str)
    tenant_id = config.get("OAUTH_AZURE_AD_TENANT_ID", "", str)
    return bool(client_id and client_secret and tenant_id)


if _oauth_is_configured():
    # Optional: enables Chainlit's OAuth callback flow (non-EasyAuth deployments).
    # Import registers @cl.oauth_callback via side effects.
    import auth_oauth  # noqa: F401
else:
    logger.info("OAuth callback not registered (missing OAUTH_AZURE_AD_* settings).")
