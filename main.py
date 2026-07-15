import asyncio
import logging
import mimetypes
import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse

from connectors import AppConfigClient, BlobClient
from dependencies import get_config
from embed_config import (
    configure_chainlit_allowed_origins,
    EmbedConfigError,
    EmbedSettings,
    load_embed_settings,
)


def _configure_logging() -> None:
    # Configure logging before importing any chatty libraries.
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    )

    # Reduce noise from chatty Azure SDK loggers so troubleshooting signals stand out.
    logging.getLogger("azure").setLevel(logging.WARNING)
    logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)


_configure_logging()
logger = logging.getLogger("gpt_rag_ui.main")


def _mask(value: str, *, keep_end: int = 6) -> str:
    v = (value or "").strip()
    if not v:
        return "<empty>"
    if len(v) <= keep_end:
        return "<redacted>"
    return f"…{v[-keep_end:]}"


def _is_truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _is_falsey(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"0", "false", "no", "n", "off"}


@dataclass(frozen=True)
class AuthState:
    oauth_configured: bool
    allow_anonymous: bool
    allow_anonymous_source: str
    allow_anonymous_raw: str
    default_allow_anonymous: bool
    running_in_azure_host: bool
    client_id_value: str
    tenant_id_value: str
    has_client_secret: bool
    client_secret_value: str


def _get_str_config(config: AppConfigClient, key: str, *fallback_keys: str) -> str:
    """Read a string config value, trying fallbacks, and normalize whitespace."""
    for k in (key, *fallback_keys):
        v = (config.get(k, "", str) or "").strip()
        if v:
            return v
    return ""


def _is_running_in_azure_host() -> bool:
    return bool(
        os.environ.get("WEBSITE_SITE_NAME")
        or os.environ.get("CONTAINER_APP_NAME")
        or os.environ.get("CONTAINER_APP_REVISION")
    )


def _clear_oauth_env_vars() -> bool:
    keys = (
        "OAUTH_AZURE_AD_CLIENT_ID",
        "OAUTH_AZURE_AD_TENANT_ID",
        "OAUTH_AZURE_AD_CLIENT_SECRET",
        "OAUTH_AZURE_AD_SCOPES",
        "OAUTH_AZURE_AD_ENABLE_SINGLE_TENANT",
    )
    cleared = False
    for k in keys:
        if k in os.environ:
            os.environ.pop(k, None)
            cleared = True
    return cleared


def _startup_banner() -> None:
    name = "GPT-RAG UI"
    version = _read_local_ui_version()

    banner_lines = [
        "",
        "╔══════════════════════════════════════════════╗",
        f"║  {name}{(' v' + version) if version else ''}".ljust(47) + "║",
        "║  FastAPI + Chainlit                          ║",
        "╚══════════════════════════════════════════════╝",
        "",
    ]
    for line in banner_lines:
        logger.info(line)


def _local_version_file_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")


def _read_local_ui_version() -> str | None:
    try:
        version_path = _local_version_file_path()
        if os.path.exists(version_path):
            with open(version_path, "r", encoding="utf-8") as f:
                value = (f.read() or "").strip()
                return value or None
    except Exception:
        logger.exception("Failed to read local VERSION file")
    return None


def _normalize_version_prefix(value: str | None) -> str | None:
    normalized = (value or "").strip()
    if not normalized:
        return None
    if normalized.lower().startswith("v"):
        return normalized
    return f"v{normalized}"


def _format_release_value(value: str | None, missing_message: str) -> str:
    normalized = _normalize_version_prefix(value)
    if normalized:
        return normalized
    return missing_message


def _want_chainlit_spontaneous_file_upload(auth_state: AuthState) -> bool:
    """True whenever the effective allow_anonymous is false.

    Per-conversation uploads require an authenticated caller (each file is bound to the
    user's conversation), so we enable the Chainlit paperclip whenever auth is in force,
    regardless of whether ALLOW_ANONYMOUS came from env, App Config, or the default.
    """

    return not auth_state.allow_anonymous


def _sync_chainlit_spontaneous_file_upload(auth_state: AuthState) -> None:
    """Write [features.spontaneous_file_upload].enabled before `import chainlit` (Chainlit reads TOML on import)."""

    want_enabled = _want_chainlit_spontaneous_file_upload(auth_state)
    path = Path(__file__).resolve().parent / ".chainlit" / "config.toml"
    if not path.is_file():
        logger.warning("Chainlit config not found at %s; skipping spontaneous file upload sync", path)
        return

    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        logger.exception("Failed to read Chainlit config %s", path)
        return

    lines = text.splitlines(keepends=True)
    section = "[features.spontaneous_file_upload]"
    in_section = False
    enabled_idx: int | None = None
    current: bool | None = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_section = stripped.lower() == section.lower()
            continue
        if not in_section:
            continue
        s = stripped.lower()
        if s.startswith("enabled") and "=" in s:
            val = stripped.split("=", 1)[1].strip().lower()
            if val == "true":
                current = True
            elif val == "false":
                current = False
            enabled_idx = i
            break

    if enabled_idx is None or current is None:
        logger.warning(
            "Could not find 'enabled' under %s in %s; spontaneous file upload not synced",
            section,
            path,
        )
        return

    if current is want_enabled:
        logger.info(
            "Chainlit spontaneous file upload already %s (ALLOW_ANONYMOUS source=%s allow_anonymous=%s)",
            "enabled" if want_enabled else "disabled",
            auth_state.allow_anonymous_source,
            auth_state.allow_anonymous,
        )
        return

    orig = lines[enabled_idx]
    prefix = orig[: len(orig) - len(orig.lstrip(" \t"))]
    if orig.endswith("\r\n"):
        eol = "\r\n"
    elif orig.endswith("\n"):
        eol = "\n"
    else:
        eol = "\n"
    lines[enabled_idx] = f"{prefix}enabled = {str(want_enabled).lower()}{eol}"

    try:
        path.write_text("".join(lines), encoding="utf-8")
    except OSError:
        logger.warning(
            "Could not write Chainlit config %s (read-only filesystem?); "
            "spontaneous file upload remains %s",
            path,
            "enabled" if current else "disabled",
            exc_info=True,
        )
        return

    logger.info(
        "Set Chainlit spontaneous file upload to %s (ALLOW_ANONYMOUS source=%s allow_anonymous=%s)",
        "enabled" if want_enabled else "disabled",
        auth_state.allow_anonymous_source,
        auth_state.allow_anonymous,
    )


def _configure_chainlit_prereqs(config: AppConfigClient) -> None:
    """Configure values needed by Chainlit regardless of auth mode."""

    # Chainlit requires env var CHAINLIT_AUTH_SECRET to sign its session JWT.
    # Prefer storing it in App Configuration (key `CHAINLIT_AUTH_SECRET`) backed by Key Vault.
    # If missing, generate a temporary secret (sessions will be invalidated on restart).
    if not os.environ.get("CHAINLIT_AUTH_SECRET"):
        chainlit_secret = _get_str_config(config, "CHAINLIT_AUTH_SECRET")
        if chainlit_secret:
            os.environ["CHAINLIT_AUTH_SECRET"] = chainlit_secret
            logger.info("Configured CHAINLIT_AUTH_SECRET from App Configuration key 'CHAINLIT_AUTH_SECRET'")
        else:
            os.environ["CHAINLIT_AUTH_SECRET"] = secrets.token_urlsafe(48)
            logger.warning(
                "App Configuration key 'CHAINLIT_AUTH_SECRET' is not set; using a temporary secret. "
                "Set 'CHAINLIT_AUTH_SECRET' (ideally Key Vault-backed) to avoid session resets on restart."
            )

    # Chainlit OAuth providers (including Azure AD) require configuration via environment variables.
    # To keep everything in App Configuration (+ Key Vault references), mirror relevant keys into
    # process environment before importing Chainlit.
    if not os.environ.get("CHAINLIT_URL"):
        chainlit_url = _get_str_config(config, "CHAINLIT_URL", "chainlitUrl")
        if chainlit_url:
            os.environ["CHAINLIT_URL"] = chainlit_url.rstrip("/")
            logger.info("Configured CHAINLIT_URL from App Configuration")


def _evaluate_auth_state(
    config: AppConfigClient,
    embed_settings: EmbedSettings | None = None,
) -> AuthState:
    """Compute auth state without importing Chainlit.

    Important: this is used to decide whether to start Chainlit or a "configuration required" app.
    """

    running_in_azure_host = _is_running_in_azure_host()

    client_id_value = (
        (os.environ.get("OAUTH_AZURE_AD_CLIENT_ID") or "").strip()
        or _get_str_config(config, "OAUTH_AZURE_AD_CLIENT_ID", "CLIENT_ID")
    )
    tenant_id_value = (
        (os.environ.get("OAUTH_AZURE_AD_TENANT_ID") or "").strip()
        or _get_str_config(config, "OAUTH_AZURE_AD_TENANT_ID")
    )
    client_secret_value = (
        (os.environ.get("OAUTH_AZURE_AD_CLIENT_SECRET") or "").strip()
        or _get_str_config(config, "OAUTH_AZURE_AD_CLIENT_SECRET", "authClientSecret")
    )

    embed_settings = embed_settings or EmbedSettings()
    oauth_configured = bool(client_id_value and tenant_id_value and client_secret_value)
    default_allow_anonymous = not running_in_azure_host

    allow_anonymous_source = "default"
    allow_anonymous_raw = ""
    allow_anonymous_env = os.environ.get("ALLOW_ANONYMOUS")
    if allow_anonymous_env is not None and str(allow_anonymous_env).strip() != "":
        allow_anonymous_raw = str(allow_anonymous_env).strip()
        allow_anonymous_source = "env"
        if _is_truthy(allow_anonymous_raw):
            allow_anonymous = True
        elif _is_falsey(allow_anonymous_raw):
            allow_anonymous = False
        else:
            allow_anonymous = default_allow_anonymous
            allow_anonymous_source = "env-unrecognized"
            logger.warning(
                "ALLOW_ANONYMOUS env var value '%s' is not recognized; using default_allow_anonymous=%s",
                allow_anonymous_raw,
                default_allow_anonymous,
            )
    else:
        allow_anonymous_raw = _get_str_config(config, "ALLOW_ANONYMOUS")
        if allow_anonymous_raw:
            allow_anonymous_source = "appconfig"
            if _is_truthy(allow_anonymous_raw):
                allow_anonymous = True
            elif _is_falsey(allow_anonymous_raw):
                allow_anonymous = False
            else:
                allow_anonymous = default_allow_anonymous
                allow_anonymous_source = "appconfig-unrecognized"
                logger.warning(
                    "App Configuration key 'ALLOW_ANONYMOUS' value '%s' is not recognized; using default_allow_anonymous=%s",
                    allow_anonymous_raw,
                    default_allow_anonymous,
                )
        else:
            allow_anonymous = default_allow_anonymous

    os.environ["ALLOW_ANONYMOUS_EFFECTIVE"] = "true" if allow_anonymous else "false"
    os.environ["ALLOW_ANONYMOUS_SOURCE"] = allow_anonymous_source
    os.environ["ALLOW_ANONYMOUS_RAW"] = allow_anonymous_raw or "<unset>"

    logger.info(
        "Auth decision: running_in_azure_host=%s oauth_min_config_present=%s default_allow_anonymous=%s allow_anonymous=%s allow_anonymous_source=%s",
        running_in_azure_host,
        oauth_configured,
        default_allow_anonymous,
        allow_anonymous,
        allow_anonymous_source,
    )

    if allow_anonymous_source == "default" and running_in_azure_host:
        logger.warning(
            "ALLOW_ANONYMOUS was not provided via env var or App Configuration; using default_allow_anonymous=%s. "
            "Note: this repo loads App Configuration labels 'gpt-rag-ui', 'gpt-rag', and <no label>.",
            default_allow_anonymous,
        )

    return AuthState(
        oauth_configured=oauth_configured,
        allow_anonymous=allow_anonymous,
        allow_anonymous_source=allow_anonymous_source,
        allow_anonymous_raw=(allow_anonymous_raw or "<unset>"),
        default_allow_anonymous=default_allow_anonymous,
        running_in_azure_host=running_in_azure_host,
        client_id_value=client_id_value,
        tenant_id_value=tenant_id_value,
        has_client_secret=bool(client_secret_value),
        client_secret_value=client_secret_value,
    )


def _configure_auth_environment(config: AppConfigClient, auth_state: AuthState | None = None) -> None:
    """Populate env vars for Chainlit auth/OAuth.

    Must run before importing Chainlit.
    """

    _configure_chainlit_prereqs(config)

    # Azure AD OAuth provider (Chainlit built-in provider id: azure-ad)
    # Docs callback path: {CHAINLIT_URL}/auth/oauth/azure-ad/callback
    #
    # Conditional auth behavior:
    # - If minimum OAuth config (client_id + tenant_id + client_secret) is present => enable OAuth.
    # - If minimum OAuth config is missing AND ALLOW_ANONYMOUS is true => run fully anonymous and ensure
    #   no partial OAuth env vars remain (so Chainlit doesn't attempt OAuth).
    # - If minimum OAuth config is missing AND ALLOW_ANONYMOUS is false => fail fast with a clear error.

    auth_state = auth_state or _evaluate_auth_state(config)
    client_id_value = auth_state.client_id_value
    tenant_id_value = auth_state.tenant_id_value
    client_secret_value = auth_state.client_secret_value
    oauth_configured = auth_state.oauth_configured
    allow_anonymous = auth_state.allow_anonymous

    if oauth_configured:
        if not os.environ.get("OAUTH_AZURE_AD_CLIENT_ID") and client_id_value:
            os.environ["OAUTH_AZURE_AD_CLIENT_ID"] = client_id_value
            logger.info("Configured OAUTH_AZURE_AD_CLIENT_ID")

        if not os.environ.get("OAUTH_AZURE_AD_TENANT_ID") and tenant_id_value:
            os.environ["OAUTH_AZURE_AD_TENANT_ID"] = tenant_id_value
            logger.info("Configured OAUTH_AZURE_AD_TENANT_ID")

        if not os.environ.get("OAUTH_AZURE_AD_CLIENT_SECRET") and client_secret_value:
            os.environ["OAUTH_AZURE_AD_CLIENT_SECRET"] = client_secret_value
            logger.info("Configured OAUTH_AZURE_AD_CLIENT_SECRET")

        # Scopes for Chainlit Azure AD provider.
        # Important: if this is not set, Chainlit/MSAL may fall back to Microsoft Graph defaults (e.g. User.Read),
        # which produces access_tokens with aud=00000003-... and the orchestrator correctly rejects them.
        #
        # Default to the orchestrator API scope to keep the system in "single token" mode.
        if not os.environ.get("OAUTH_AZURE_AD_SCOPES"):
            scopes_value = _get_str_config(config, "OAUTH_AZURE_AD_SCOPES")
            if str(scopes_value or "").strip():
                os.environ["OAUTH_AZURE_AD_SCOPES"] = str(scopes_value)
                logger.info("Configured OAUTH_AZURE_AD_SCOPES")
            else:
                os.environ["OAUTH_AZURE_AD_SCOPES"] = (
                    f"api://{client_id_value}/user_impersonation,openid,profile,offline_access"
                )
                logger.info("Defaulted OAUTH_AZURE_AD_SCOPES to orchestrator API scope")

        # Single-tenant toggle.
        # Default to true (most deployments use a tenant-specific app registration).
        # Allow explicitly forcing false for multi-tenant scenarios.
        if not os.environ.get("OAUTH_AZURE_AD_ENABLE_SINGLE_TENANT"):
            enable_single_tenant = _get_str_config(config, "OAUTH_AZURE_AD_ENABLE_SINGLE_TENANT")
            normalized = str(enable_single_tenant or "").strip().lower()
            if normalized in {"0", "false", "no", "n", "off"}:
                os.environ["OAUTH_AZURE_AD_ENABLE_SINGLE_TENANT"] = "false"
                logger.info("Configured OAUTH_AZURE_AD_ENABLE_SINGLE_TENANT=false")
            elif normalized in {"1", "true", "yes", "y", "on"}:
                os.environ["OAUTH_AZURE_AD_ENABLE_SINGLE_TENANT"] = "true"
                logger.info("Configured OAUTH_AZURE_AD_ENABLE_SINGLE_TENANT=true")
            else:
                os.environ["OAUTH_AZURE_AD_ENABLE_SINGLE_TENANT"] = "true"
                logger.info("Defaulted OAUTH_AZURE_AD_ENABLE_SINGLE_TENANT=true (not provided)")
    else:
        cleared = _clear_oauth_env_vars()

        if allow_anonymous:
            logger.warning(
                "OAuth is not configured (missing client_id/tenant_id/client_secret). "
                "Running in anonymous mode (ALLOW_ANONYMOUS=true). Cleared OAuth env vars=%s",
                cleared,
            )
        else:
            logger.error(
                "OAuth is not configured (missing client_id/tenant_id/client_secret) and ALLOW_ANONYMOUS=false. "
                "Starting without Chainlit (auth-required mode)."
            )
            return

    # Safe auth config health log (no secrets).
    try:
        client_id_env = (os.environ.get("OAUTH_AZURE_AD_CLIENT_ID") or "").strip()
        tenant_id_env = (os.environ.get("OAUTH_AZURE_AD_TENANT_ID") or "").strip()
        secret_env = (os.environ.get("OAUTH_AZURE_AD_CLIENT_SECRET") or "").strip()
        chainlit_url_env = (os.environ.get("CHAINLIT_URL") or "").strip()
        logger.info(
            "OAuth config health: enabled=%s allow_anonymous=%s chainlit_url=%s client_id=%s tenant_id=%s has_client_secret=%s single_tenant=%s",
            bool(client_id_env and tenant_id_env and secret_env),
            allow_anonymous,
            (chainlit_url_env or "<unset>"),
            (_mask(client_id_env) if client_id_env else "<unset>"),
            (_mask(tenant_id_env) if tenant_id_env else "<unset>"),
            bool(secret_env),
            _is_truthy(os.environ.get("OAUTH_AZURE_AD_ENABLE_SINGLE_TENANT")),
        )
    except Exception:
        logger.exception("Failed to compute OAuth config health")


def _create_not_ready_app() -> FastAPI:
    """Return an app that clearly signals configuration is missing/unavailable."""

    @asynccontextmanager
    async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
        logger.error(
            "APPLICATION STARTED IN NOT-READY MODE: Azure App Configuration is unavailable. "
            "This instance will return HTTP 503 until configuration is fixed."
        )
        yield

    app = FastAPI(title="GPT-RAG UI (configuration required)", lifespan=_lifespan)

    @app.get("/")
    async def _config_required_root():
        message = (
            "GPT-RAG UI is not ready. Azure App Configuration is required but could not be reached.\n\n"
            "How to fix:\n"
            "- Ensure Azure CLI is installed and run: az login\n"
            "- Or set APP_CONFIG_ENDPOINT / AZURE_APPCONFIG_CONNECTION_STRING\n"
        )
        return Response(
            message,
            status_code=503,
            media_type="text/plain",
            headers={"Retry-After": "30"},
        )

    @app.get("/healthz")
    async def _healthz_config_required():
        return Response(
            "not-ready",
            status_code=503,
            media_type="text/plain",
            headers={"Retry-After": "30"},
        )

    return app


def _create_auth_required_app(auth_state: AuthState) -> FastAPI:
    """Return an app that stays up but signals OAuth configuration is required."""

    @asynccontextmanager
    async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
        logger.error(
            "APPLICATION STARTED IN AUTH-REQUIRED MODE: OAuth is required but not configured. "
            "This instance will return HTTP 503 until OAuth configuration is provided. "
            "allow_anonymous=%s source=%s",
            auth_state.allow_anonymous,
            auth_state.allow_anonymous_source,
        )
        yield

    app = FastAPI(title="GPT-RAG UI (authentication required)", lifespan=_lifespan)

    @app.get("/")
    async def _auth_required_root():
        message = (
            "GPT-RAG UI is not ready. Authentication is required, but OAuth is not configured.\n\n"
            "Required settings:\n"
            "- OAUTH_AZURE_AD_CLIENT_ID\n"
            "- OAUTH_AZURE_AD_TENANT_ID\n"
            "- OAUTH_AZURE_AD_CLIENT_SECRET\n\n"
            "Recommended setup:\n"
            "Create the keys in Azure App Configuration using label: gpt-rag\n"
            "Optional: use label gpt-rag-ui only for UI-specific overrides.\n\n"
            "Alternative setup:\n"
            "Set the same values as container environment variables.\n"
        )
        return Response(
            message,
            status_code=503,
            media_type="text/plain",
            headers={"Retry-After": "30"},
        )

    @app.get("/healthz")
    async def _healthz_auth_required():
        return Response(
            "auth-required",
            status_code=200,
            media_type="text/plain",
            headers={"X-App-Mode": "auth-required"},
        )

    return app


def _configure_embed_environment(settings: EmbedSettings) -> None:
    os.environ["CHAINLIT_COPILOT_ENABLED_EFFECTIVE"] = (
        "true" if settings.enabled else "false"
    )
    if not settings.enabled:
        return

    os.environ["CHAINLIT_COOKIE_SAMESITE"] = settings.cookie_samesite
    os.environ["CHAINLIT_PUBLIC_URL"] = settings.ui_origin


def _create_chainlit_app(
    config: AppConfigClient,
    auth_state: AuthState | None = None,
    embed_settings: EmbedSettings | None = None,
) -> FastAPI:
    """Create the main Chainlit ASGI app.

    Important: this must configure env vars before importing Chainlit.
    """

    embed_settings = embed_settings or EmbedSettings()
    _configure_embed_environment(embed_settings)
    _configure_auth_environment(config, auth_state)
    effective_auth = auth_state or _evaluate_auth_state(config, embed_settings)
    _sync_chainlit_spontaneous_file_upload(effective_auth)

    from download_security import configure_download_tokens

    public_url = (
        embed_settings.ui_origin
        or (os.environ.get("CHAINLIT_URL") or "").strip().rstrip("/")
    )
    if public_url:
        configure_download_tokens(
            secret=os.environ["CHAINLIT_AUTH_SECRET"],
            public_url=public_url,
        )

    copilot_sessions = None
    if embed_settings.enabled:
        from embed_auth import configure_session_store

        copilot_sessions = configure_session_store(
            max_sessions=embed_settings.max_sessions,
            ttl_seconds=embed_settings.session_ttl_seconds,
        )

    # Importing chainlit.config does not create the server app, so enabled
    # origins can be applied in memory without modifying the deployment files.
    from chainlit.config import config as chainlit_config

    configure_chainlit_allowed_origins(embed_settings, chainlit_config)
    from chainlit.server import app as chainlit_app, sio
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from starlette.middleware.cors import CORSMiddleware

    account_name = _get_str_config(config, "STORAGE_ACCOUNT_NAME")
    documents_container = _get_str_config(config, "DOCUMENTS_STORAGE_CONTAINER")
    images_container = _get_str_config(config, "DOCUMENTS_IMAGES_STORAGE_CONTAINER")
    conversation_documents_container = _get_str_config(
        config,
        "CONVERSATION_DOCUMENTS_STORAGE_CONTAINER",
    )
    shared_download_containers = {
        container.strip().strip("/")
        for container in _get_str_config(
            config,
            "CITATION_SHARED_DOWNLOAD_CONTAINERS",
        ).split(",")
        if container.strip().strip("/")
    }

    def download_from_blob(file_name: str) -> bytes:
        logger.info("Preparing blob download for '%s'", file_name)
        blob_url = f"https://{account_name}.blob.core.windows.net/{file_name}"
        logger.debug("Constructed blob URL %s", blob_url)

        try:
            blob_client = BlobClient(blob_url=blob_url)
            blob_data = blob_client.download_blob()
            logger.debug("Successfully downloaded blob data for '%s'", file_name)
            return blob_data
        except Exception:
            logger.exception("Error downloading blob '%s'", file_name)
            raise

    # One-time runtime auth-mode log (useful when operators attach to logs after startup).
    _auth_mode_logged = False

    @chainlit_app.middleware("http")
    async def _log_auth_mode_once(request, call_next):
        nonlocal _auth_mode_logged
        if not _auth_mode_logged:
            _auth_mode_logged = True
            oauth_enabled = bool(
                (os.environ.get("OAUTH_AZURE_AD_CLIENT_ID") or "").strip()
                and (os.environ.get("OAUTH_AZURE_AD_TENANT_ID") or "").strip()
                and (os.environ.get("OAUTH_AZURE_AD_CLIENT_SECRET") or "").strip()
            )
            logger.info(
                "Auth effective: oauth_enabled=%s allow_anonymous=%s source=%s",
                oauth_enabled,
                (os.environ.get("ALLOW_ANONYMOUS_EFFECTIVE") or "<unset>"),
                (os.environ.get("ALLOW_ANONYMOUS_SOURCE") or "<unset>"),
            )
        return await call_next(request)

    # Import Chainlit event handlers.
    import app as chainlit_handlers  # noqa: F401
    logger.info("Chainlit handlers imported")

    # Provide friendly app metadata used by OpenAPI.
    chainlit_app.title = getattr(chainlit_app, "title", "GPT-RAG UI")
    try:
        version = _read_local_ui_version()
        if version:
            chainlit_app.version = version
    except Exception:
        chainlit_app.version = getattr(chainlit_app, "version", "dev")

    from fastapi.openapi.utils import get_openapi

    def _safe_openapi():
        if getattr(chainlit_app, "openapi_schema", None):
            return chainlit_app.openapi_schema
        try:
            chainlit_app.openapi_schema = get_openapi(
                title=chainlit_app.title,
                version=chainlit_app.version,
                routes=chainlit_app.routes,
            )
        except Exception:
            logger.exception("OpenAPI generation failed; returning fallback schema")
            chainlit_app.openapi_schema = {
                "openapi": "3.0.0",
                "info": {"title": chainlit_app.title, "version": chainlit_app.version},
                "paths": {},
            }
        return chainlit_app.openapi_schema

    chainlit_app.openapi = _safe_openapi

    host_app = FastAPI(title="GPT-RAG UI host")
    if embed_settings.enabled:
        from embed_security import (
            configure_copilot_bridge_guards,
            CopilotRequestMiddleware,
        )

        host_app.add_middleware(
            CORSMiddleware,
            allow_origins=list(embed_settings.allowed_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
        )
        host_app.add_middleware(
            CopilotRequestMiddleware,
            settings=embed_settings,
            sessions=copilot_sessions,
        )
        configure_copilot_bridge_guards(sio)
        logger.info(
            "Chainlit Copilot enabled: origins=%s cookie_samesite=%s max_sessions=%s session_ttl_seconds=%s",
            list(embed_settings.allowed_origins),
            embed_settings.cookie_samesite,
            embed_settings.max_sessions,
            embed_settings.session_ttl_seconds,
        )

    if embed_settings.enabled:
        import httpx

        from auth_common import canonical_principal_id, is_user_authorized
        from embed_auth import (
            clear_copilot_session_cookie,
            session_id_from_request,
            set_copilot_session_cookie,
        )
        from entra_token import EntraTokenError, EntraTokenValidator

        validator = EntraTokenValidator(
            tenant_id=embed_settings.entra_tenant_id,
            audience=embed_settings.entra_audience,
            required_scope=embed_settings.entra_required_scope,
        )

        def _copilot_auth_error(status_code: int, detail: str) -> JSONResponse:
            response = JSONResponse(
                {"detail": detail},
                status_code=status_code,
                headers={"Cache-Control": "no-store"},
            )
            clear_copilot_session_cookie(
                response,
                same_site=embed_settings.cookie_samesite,
            )
            return response

        @host_app.post("/copilot/auth/bootstrap")
        async def bootstrap_copilot(request: Request):
            previous_session_id = session_id_from_request(request)
            await copilot_sessions.delete(previous_session_id)
            authorization = request.headers.get("Authorization", "")
            scheme, separator, access_token = authorization.partition(" ")
            if not separator or scheme.lower() != "bearer" or not access_token.strip():
                return _copilot_auth_error(
                    status.HTTP_401_UNAUTHORIZED,
                    "Authentication required",
                )
            try:
                claims = await validator.validate(access_token.strip())
            except EntraTokenError:
                logger.warning("Copilot bootstrap rejected an invalid Entra token")
                return _copilot_auth_error(
                    status.HTTP_401_UNAUTHORIZED,
                    "Authentication failed",
                )
            except httpx.HTTPError:
                logger.exception("Copilot bootstrap could not reach Entra JWKS")
                return _copilot_auth_error(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "Authentication service unavailable",
                )

            tenant_id = str(claims["tid"])
            object_id = str(claims["oid"])
            principal_id = canonical_principal_id(tenant_id, object_id)
            principal_name = str(
                claims.get("preferred_username")
                or claims.get("email")
                or claims.get("upn")
                or ""
            )
            if not is_user_authorized(config, principal_name, principal_id):
                logger.warning("Copilot bootstrap denied principal=%s", principal_id)
                return _copilot_auth_error(
                    status.HTTP_403_FORBIDDEN,
                    "Access denied",
                )

            try:
                session = await copilot_sessions.replace(
                    previous_session_id=None,
                    access_token=access_token.strip(),
                    claims=claims,
                    display_name=str(
                        claims.get("name") or principal_name or principal_id
                    ),
                    principal_name=principal_name,
                )
            except (KeyError, TypeError, ValueError):
                logger.warning("Copilot bootstrap rejected invalid token claims")
                return _copilot_auth_error(
                    status.HTTP_401_UNAUTHORIZED,
                    "Authentication failed",
                )
            response = JSONResponse(
                {"success": True, "expiresAt": session.expires_at},
                headers={"Cache-Control": "no-store"},
            )
            set_copilot_session_cookie(
                response,
                session,
                same_site=embed_settings.cookie_samesite,
            )
            return response

        @host_app.post("/copilot/auth/logout")
        async def logout_copilot(request: Request):
            await copilot_sessions.delete(session_id_from_request(request))
            response = JSONResponse(
                {"success": True},
                headers={"Cache-Control": "no-store"},
            )
            clear_copilot_session_cookie(
                response,
                same_site=embed_settings.cookie_samesite,
            )
            return response

    from chainlit.auth import get_current_user
    from chainlit.user import User
    from conversation_security import get_owned_conversation
    from download_security import get_download_tokens, is_download_target_allowed

    @host_app.get("/api/download/{grant_token}")
    async def download_blob_file(
        grant_token: str,
        current_user: User | None = Depends(get_current_user),
    ):
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        grant = get_download_tokens().verify(grant_token)
        metadata = current_user.metadata or {}
        if not grant or grant.principal_id != current_user.identifier:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        if not await get_owned_conversation(grant.conversation_id, metadata):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

        allowed_containers = {
            container
            for container in (
                documents_container,
                images_container,
                conversation_documents_container,
            )
            if container
        }
        if grant.container not in allowed_containers:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        if not is_download_target_allowed(
            conversation_id=grant.conversation_id,
            container=grant.container,
            blob_name=grant.blob_name,
            conversation_container=conversation_documents_container,
            shared_containers=shared_download_containers,
        ):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

        try:
            file_bytes = await asyncio.to_thread(
                download_from_blob,
                f"{grant.container}/{grant.blob_name}",
            )
        except Exception as exc:
            logger.warning(
                "Authorized download failed: conversation=%s container=%s",
                grant.conversation_id,
                grant.container,
                exc_info=True,
            )
            if "BlobNotFound" in str(exc):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Not found",
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Download failed",
            ) from exc
        if not file_bytes:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

        file_name = os.path.basename(grant.blob_name)
        content_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"
        return StreamingResponse(
            BytesIO(file_bytes),
            media_type=content_type,
            headers={
                "Content-Disposition": (
                    "attachment; filename*=UTF-8''"
                    f"{quote(file_name, safe='')}"
                ),
                "Cache-Control": "private, no-store",
            },
        )

    @host_app.get("/version-footer")
    async def get_version_footer_data():
        show_release_footer = config.get("SHOW_RELEASE_FOOTER", True, bool)
        gpt_rag_release = (config.get("RELEASE", "", str) or os.environ.get("RELEASE", "")).strip()
        gpt_rag_ui_release = _read_local_ui_version()

        payload = {
            "show_release_footer": show_release_footer,
            "gpt_rag_release": _format_release_value(
                gpt_rag_release,
                "gpt-rag release information is missing",
            ),
            "gpt_rag_ui_release": _format_release_value(
                gpt_rag_ui_release,
                "gpt-rag-ui release information is missing",
            ),
        }
        return JSONResponse(payload)

    host_app.mount("/", chainlit_app)

    logger.info("Mounted Chainlit app at / on host app")

    FastAPIInstrumentor.instrument_app(host_app)
    HTTPXClientInstrumentor().instrument()
    return host_app


def build_app() -> FastAPI:
    config: AppConfigClient = get_config()
    _startup_banner()

    connected = bool(getattr(config, "connected", False))
    if connected:
        logger.info("Configuration loaded from Azure App Configuration")

        # Configure Chainlit prerequisites (session secret, URL) even when OAuth is missing.
        _configure_chainlit_prereqs(config)
        try:
            embed_settings = load_embed_settings(config)
        except EmbedConfigError:
            logger.exception("Invalid Chainlit Copilot configuration")
            raise
        auth_state = _evaluate_auth_state(config, embed_settings)
        if embed_settings.enabled and (
            not auth_state.oauth_configured or auth_state.allow_anonymous
        ):
            raise EmbedConfigError(
                "Chainlit Copilot requires standalone OAuth and "
                "ALLOW_ANONYMOUS=false; embedding never bypasses or downgrades "
                "the standalone authentication policy."
            )

        if (
            auth_state.oauth_configured
            or auth_state.allow_anonymous
        ):
            return _create_chainlit_app(config, auth_state, embed_settings)

        logger.error(
            "OAuth is required but not configured and anonymous mode is disabled; starting in auth-required mode (HTTP 503)."
        )
        return _create_auth_required_app(auth_state)

    logger.warning(
        "Running without Azure App Configuration (not logged in or unavailable). "
        "Set env vars locally or run 'az login' to enable App Configuration."
    )
    return _create_not_ready_app()


# ASGI entry point (used by: `uvicorn main:app`)
app = build_app()