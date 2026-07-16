import base64
import json
import logging
import os
import re
import asyncio
import time
from typing import Dict, List, Optional

import chainlit as cl
import msal

from auth_common import (
    canonical_principal_id,
    is_user_authorized,
    safe_profile_metadata,
)
from auth_session import (
    OAUTH_SESSION_ID_KEY,
    OAUTH_SESSION_SOURCE,
    current_oauth_credential,
    current_user_metadata,
    delete_current_oauth_credential,
    get_oauth_credential_store,
    oauth_session_id_from_metadata,
)
from dependencies import get_config

logger = logging.getLogger("gpt_rag_ui.auth_oauth")

config = get_config()

_SCOPE_SPLIT_RE = re.compile(r"[\s,]+")


def _decode_jwt_unverified(token: str) -> Optional[dict]:
    """Decode JWT payload without verifying signature.

    For debug diagnostics only. Never use this to authorize.
    """

    try:
        parts = (token or "").split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
        data = json.loads(payload.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _access_token_debug_summary(access_token: str) -> dict:
    claims = _decode_jwt_unverified(access_token) or {}
    aud = claims.get("aud")
    if isinstance(aud, list):
        aud_value = ",".join(str(x) for x in aud)
    else:
        aud_value = str(aud) if aud is not None else None

    oid = claims.get("oid")
    tid = claims.get("tid")
    iss = claims.get("iss")
    scp = claims.get("scp")
    ver = claims.get("ver")
    azp = claims.get("azp")

    def _short(value: object) -> str:
        s = str(value or "")
        if len(s) <= 10:
            return s
        return f"{s[:4]}…{s[-4:]}"

    return {
        "aud": aud_value,
        "tid": _short(tid) if tid else None,
        "oid": _short(oid) if oid else None,
        "iss": iss,
        "scp": scp,
        "ver": ver,
        "azp": _short(azp) if azp else None,
    }


def _jwt_exp_unverified(access_token: str) -> int | None:
    claims = _decode_jwt_unverified(access_token) or {}
    exp = claims.get("exp")
    try:
        return int(exp) if exp is not None else None
    except Exception:
        return None


def _access_token_ttl_seconds(access_token: str) -> int | None:
    exp = _jwt_exp_unverified(access_token)
    if not exp:
        return None
    now = int(time.time())
    return int(exp) - now


def _is_access_token_expiring(access_token: str, *, min_ttl_seconds: int = 120) -> bool:
    ttl = _access_token_ttl_seconds(access_token)
    if ttl is None:
        # If we can't read exp, be safe and refresh.
        return True
    return ttl <= int(min_ttl_seconds)


def _resolve_oauth_runtime_config() -> tuple[str, str, str]:
    """Return (client_id, client_secret, tenant_id) for MSAL operations."""

    # Prefer process env (bootstrapped by main.py), then App Configuration.
    client_id = (os.getenv("OAUTH_AZURE_AD_CLIENT_ID") or "").strip() or (get_env_var("OAUTH_AZURE_AD_CLIENT_ID") or "").strip()
    client_secret = (os.getenv("OAUTH_AZURE_AD_CLIENT_SECRET") or "").strip() or (
        get_env_var("OAUTH_AZURE_AD_CLIENT_SECRET") or ""
    ).strip()
    tenant_id = (os.getenv("OAUTH_AZURE_AD_TENANT_ID") or "").strip() or (get_env_var("OAUTH_AZURE_AD_TENANT_ID") or "").strip()

    if not client_id or not client_secret or not tenant_id:
        raise RuntimeError("OAuth is not configured (missing OAUTH_AZURE_AD_* settings)")

    return client_id, client_secret, tenant_id


def _resolve_msal_scopes_for_refresh(*, client_id: str) -> List[str]:
    raw_scopes, scopes = read_scopes_list("OAUTH_AZURE_AD_SCOPES")
    if not scopes:
        scopes = [
            f"api://{client_id}/user_impersonation",
            "openid",
            "profile",
            "offline_access",
        ]

    if any(_looks_like_graph_scope(s) for s in scopes):
        raise RuntimeError(
            "Invalid OAUTH_AZURE_AD_SCOPES for 'single token' mode: Graph scopes detected. "
            "Remove Graph scopes (e.g. User.Read) and configure the API scope instead."
        )

    msal_scopes = [s for s in scopes if not _is_reserved_oidc_scope(s)]
    expected_api_scope = f"api://{client_id}/user_impersonation"
    if expected_api_scope not in msal_scopes:
        raise RuntimeError(
            "OAuth scope misconfiguration: expected API scope is missing for orchestrator token exchange. "
            f"expected={expected_api_scope} got={msal_scopes}"
        )

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "Resolved OAuth scopes for refresh: raw=%r parsed=%s msal_scopes=%s",
            raw_scopes,
            scopes,
            msal_scopes,
        )

    return msal_scopes


async def refresh_access_token(refresh_token: str) -> dict:
    """Exchange refresh_token -> new access_token using MSAL.

    This runs MSAL's blocking network call in a thread to avoid blocking the event loop.
    """

    client_id, client_secret, tenant_id = _resolve_oauth_runtime_config()
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    msal_scopes = _resolve_msal_scopes_for_refresh(client_id=client_id)

    msal_app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret,
    )

    def _run_refresh() -> dict:
        return msal_app.acquire_token_by_refresh_token(refresh_token=refresh_token, scopes=msal_scopes)

    return await asyncio.to_thread(_run_refresh)


async def ensure_fresh_user_access_token(user: cl.User, *, min_ttl_seconds: int = 120) -> bool:
    """Ensure the user's access token is valid and refresh it when close to expiry.

    Returns True if a refresh was performed.
    """

    metadata = user.metadata or {}
    session_id = oauth_session_id_from_metadata(metadata)
    credential = await current_oauth_credential(metadata)
    if not session_id or not credential:
        return False

    store = get_oauth_credential_store()
    async with store.refresh_lock(session_id):
        credential = await current_oauth_credential(metadata)
        if not credential:
            return False
        if not _is_access_token_expiring(
            credential.access_token,
            min_ttl_seconds=min_ttl_seconds,
        ):
            return False

        ttl = _access_token_ttl_seconds(credential.access_token)
        logger.info(
            "Refreshing user access token (near expiry): ttl_seconds=%s user=%s",
            ttl if ttl is not None else "unknown",
            (
                metadata.get("client_principal_name")
                or metadata.get("client_principal_id")
                or user.identifier
                or "<unknown>"
            ),
        )

        result = await refresh_access_token(credential.refresh_token)
        if "error" in result:
            error_desc = result.get("error_description", "Unknown error")
            logger.warning("User token refresh failed: %s", error_desc)
            raise RuntimeError(f"token refresh failed: {error_desc}")

        new_access_token = result.get("access_token")
        new_refresh_token = (
            result.get("refresh_token") or credential.refresh_token
        )
        if not new_access_token:
            raise RuntimeError("token refresh failed: missing access_token")

        updated = await store.update(
            session_id,
            principal_id=credential.principal_id,
            access_token=new_access_token,
            refresh_token=new_refresh_token,
        )
        if not updated:
            raise RuntimeError("OAuth session expired during token refresh")

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "Refreshed access token claims (unverified): %s",
                _access_token_debug_summary(new_access_token),
            )

    return True


@cl.on_logout
async def clear_oauth_credentials_on_logout(request, response):
    await delete_current_oauth_credential()
    return {"success": True}


def _looks_like_graph_scope(scope: str) -> bool:
    s = (scope or "").strip()
    if not s:
        return False

    s_lower = s.lower()

    # Common Graph scope names (delegated)
    if s_lower in {
        "user.read",
        "groupmember.read.all",
        "directory.read.all",
        "directory.accessasuser.all",
    }:
        return True

    # Graph resource identifiers / default scopes
    if "graph.microsoft.com" in s_lower:
        return True
    if "00000003-0000-0000-c000-000000000000" in s_lower:
        return True

    return False


def _is_reserved_oidc_scope(scope: str) -> bool:
    # MSAL Python rejects these in acquire_token_by_refresh_token.
    return (scope or "").strip().lower() in {"openid", "profile", "offline_access"}


def read_scopes_list(var_name: str = "OAUTH_AZURE_AD_SCOPES") -> tuple[str, List[str]]:
    """Read scopes from config and split by comma OR whitespace.

    Azure App Configuration values sometimes come space-separated (e.g. "openid profile").
    MSAL supports passing scopes as a list; internally they'll be joined with spaces.
    """

    # Prefer process env (bootstrapped by main.py) to avoid stale App Config cache.
    raw = (os.getenv(var_name) or "").strip()
    if not raw:
        raw = str(config.get(var_name, "") or "").strip()
    if not raw:
        return "", []
    parts = [p.strip() for p in _SCOPE_SPLIT_RE.split(raw) if p and p.strip()]
    return raw, parts


def get_env_var(name: str, fallback: str | None = None, *, warn_on_missing: bool = True) -> str | None:
    # Despite the name, we read from Azure App Configuration (and env as fallback when App Config isn't configured).
    # Use allow_none=True so missing keys don't crash.
    try:
        value = config.get_value(name, default=fallback, allow_none=True, type=str)
    except Exception:
        value = fallback
    if value is None:
        if warn_on_missing:
            logger.warning("Configuration key '%s' is not set", name)
    return value


@cl.oauth_callback
async def oauth_callback(
    provider_id: str, code: str, raw_user_data: Dict[str, str], default_user: cl.User
) -> Optional[cl.User]:
    """Chainlit OAuth callback.

    Uses MSAL to exchange the Chainlit refresh token for an Entra ID access token.
    """

    logger.info("OAuth callback received for provider '%s'", provider_id)

    try:
        metadata_keys = sorted(list((default_user.metadata or {}).keys()))
    except Exception:
        metadata_keys = []
    logger.info(
        "OAuth callback context: provider=%s metadata_keys=%s",
        provider_id,
        metadata_keys,
    )

    # Prefer the explicit OAuth keys; legacy fallbacks are optional and should not spam warnings.
    client_id = get_env_var("OAUTH_AZURE_AD_CLIENT_ID") or get_env_var("CLIENT_ID", warn_on_missing=False)
    client_secret = get_env_var("OAUTH_AZURE_AD_CLIENT_SECRET") or get_env_var("authClientSecret", warn_on_missing=False)
    tenant_id = get_env_var("OAUTH_AZURE_AD_TENANT_ID")

    if not client_id or not client_secret or not tenant_id:
        raise RuntimeError("OAuth is not configured (missing OAUTH_AZURE_AD_* settings)")

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    raw_scopes, scopes = read_scopes_list("OAUTH_AZURE_AD_SCOPES")
    if not scopes:
        # "Single token" mode: request a token for the orchestrator API (not Microsoft Graph).
        # This assumes the App Registration has "Expose an API" with scope 'user_impersonation'.
        scopes = [
            f"api://{client_id}/user_impersonation",
            "openid",
            "profile",
            "offline_access",
        ]

    # Guard rail: Graph scopes mint a token for Graph (aud=00000003-...), breaking the orchestrator audience check.
    if any(_looks_like_graph_scope(s) for s in scopes):
        raise RuntimeError(
            "Invalid OAUTH_AZURE_AD_SCOPES for 'single token' mode: Graph scopes detected. "
            "Remove Graph scopes (e.g. User.Read) and configure the API scope instead, e.g. "
            f"api://{client_id}/user_impersonation,openid,profile,offline_access"
        )

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "Resolved OAuth scopes: raw=%r parsed=%s",
            raw_scopes,
            scopes,
        )

    logger.info(
        "OAuth token exchange configuration: authority_tenant=%s scopes=%s",
        (tenant_id[-6:] if len(tenant_id) >= 6 else "<redacted>"),
        scopes,
    )

    # MSAL does not allow OIDC reserved scopes when exchanging refresh_token -> access_token.
    # Keep them for the interactive login/consent (so Chainlit can obtain a refresh token),
    # but omit them from this refresh token exchange.
    msal_scopes = [s for s in scopes if not _is_reserved_oidc_scope(s)]
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("MSAL refresh-token exchange scopes (reserved omitted): %s", msal_scopes)

    expected_api_scope = f"api://{client_id}/user_impersonation"
    if expected_api_scope not in msal_scopes:
        raise RuntimeError(
            "OAuth scope misconfiguration: expected API scope is missing for orchestrator token exchange. "
            f"expected={expected_api_scope} got={msal_scopes}"
        )

    refresh_token = (default_user.metadata or {}).get("refresh_token")
    if not refresh_token:
        raise RuntimeError(
            "OAuth callback did not receive a refresh token from Chainlit. "
            "Ensure your scopes include 'offline_access' (for example: api://<CLIENT_ID>/user_impersonation,openid,profile,offline_access)."
        )

    msal_app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret,
    )

    result = msal_app.acquire_token_by_refresh_token(refresh_token=refresh_token, scopes=msal_scopes)

    if "error" in result:
        error_desc = result.get("error_description", "Unknown error")
        if "AADSTS65001" in error_desc:
            logger.error("Token acquisition failed (consent required): %s", error_desc)
            raise RuntimeError(
                "Token acquisition failed: AADSTS65001 (consent required). "
                "Grant consent for this app in Entra ID (App Registration -> API permissions -> Grant admin consent) "
                "or allow user consent, then sign in again."
            )

        logger.error("Token acquisition failed: %s", error_desc)
        raise RuntimeError(f"Token acquisition failed: {error_desc}")

    access_token = result.get("access_token")
    refresh_token = result.get("refresh_token") or refresh_token
    id_token = result.get("id_token_claims", {})
    if not access_token:
        raise RuntimeError("Token acquisition failed: missing access token.")

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "Access token claims (unverified): %s",
            _access_token_debug_summary(access_token),
        )

    tenant_id_claim = str(id_token.get("tid") or "").strip()
    object_id = str(id_token.get("oid") or "").strip()
    if not tenant_id_claim or not object_id:
        raise RuntimeError(
            "OAuth identity is missing the required tid or oid claim."
        )
    principal_id = canonical_principal_id(tenant_id_claim, object_id)
    user_name = str(id_token.get("name") or "").strip() or principal_id
    principal_name = str(id_token.get("preferred_username") or "").strip()

    # "Single token" mode: do not call Microsoft Graph from the client.
    # If you need group-based auth, it will require a second token (Graph audience).
    groups: List[str] = []

    authorized = is_user_authorized(config, principal_name, principal_id)

    logger.info(
        "User authenticated: name='%s' principal='%s' authorized=%s",
        user_name,
        principal_name or principal_id,
        authorized,
    )
    if not authorized:
        return None

    from chainlit.config import config as chainlit_config

    previous_session_id = oauth_session_id_from_metadata(
        current_user_metadata()
    )
    credential = await get_oauth_credential_store().replace(
        previous_session_id=previous_session_id,
        principal_id=principal_id,
        access_token=access_token,
        refresh_token=refresh_token,
        ttl_seconds=chainlit_config.project.user_session_timeout,
    )
    profile = safe_profile_metadata(
        {
            "authorized": authorized,
            "tenant_id": tenant_id_claim,
            "object_id": object_id,
            "principal_id": principal_id,
            "client_principal_name": principal_name,
        }
    )
    profile.update(
        {
            "auth_source": OAUTH_SESSION_SOURCE,
            OAUTH_SESSION_ID_KEY: credential.session_id,
        }
    )

    return cl.User(
        identifier=principal_id,
        display_name=user_name,
        metadata=profile,
    )
