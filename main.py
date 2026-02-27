import logging
import os
import secrets
from dataclasses import dataclass
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from io import BytesIO

from fastapi import FastAPI, Response
from fastapi.responses import StreamingResponse

from connectors import AppConfigClient, BlobClient
from dependencies import get_config


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
    version = None
    try:
        if os.path.exists("VERSION"):
            with open("VERSION", "r", encoding="utf-8") as f:
                version = f.read().strip()
    except Exception:
        version = None

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


def _evaluate_auth_state(config: AppConfigClient) -> AuthState:
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

    oauth_configured = bool(client_id_value and tenant_id_value and client_secret_value)
    default_allow_anonymous = (not running_in_azure_host) or (not oauth_configured)

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


def _create_chainlit_app(config: AppConfigClient, auth_state: AuthState | None = None) -> FastAPI:
    """Create the main Chainlit ASGI app.

    Important: this must configure env vars before importing Chainlit.
    """

    _configure_auth_environment(config, auth_state)

    from chainlit.server import app as chainlit_app
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

    account_name = _get_str_config(config, "STORAGE_ACCOUNT_NAME")
    documents_container = _get_str_config(config, "DOCUMENTS_STORAGE_CONTAINER")
    images_container = _get_str_config(config, "DOCUMENTS_IMAGES_STORAGE_CONTAINER")

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

    def handle_file_download(file_path: str):
        try:
            file_bytes = download_from_blob(file_path)
            if not file_bytes:
                return Response("File not found or empty.", status_code=404, media_type="text/plain")
        except Exception as e:
            error_message = str(e)
            status_code = 404 if "BlobNotFound" in error_message else 500
            logger.exception("Download error for '%s'", file_path)
            return Response(
                f"{'Blob not found' if status_code == 404 else 'Internal server error'}: {error_message}.",
                status_code=status_code,
                media_type="text/plain",
            )

        actual_file_name = os.path.basename(file_path)
        return StreamingResponse(
            BytesIO(file_bytes),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{actual_file_name}"'},
        )

    # Create a separate FastAPI app for blob downloads that will be mounted.
    blob_download_app = FastAPI()
    logger.info("Created FastAPI sub-application for blob downloads")

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

    @blob_download_app.get("/{container_name}/{file_path:path}")
    async def download_blob_file(container_name: str, file_path: str):
        logger.info("Download request received: container=%s file=%s", container_name, file_path)
        normalized = container_name.strip().strip("/")
        target_container = None
        if normalized == documents_container:
            target_container = documents_container
        elif normalized == images_container:
            target_container = images_container

        if not target_container:
            logger.warning("Rejected download for unknown container '%s'", container_name)
            return Response("Container not found", status_code=404, media_type="text/plain")

        return handle_file_download(f"{target_container}/{file_path}")

    logger.debug("Registered download_blob_file route on blob_download_app")

    # Mount the blob download app BEFORE importing Chainlit handlers.
    try:
        chainlit_app.mount("/api/download", blob_download_app)
        logger.info("Mounted blob download app at /api/download")
        logger.debug("Chainlit routes post-mount: %s", [r.path for r in chainlit_app.routes])
    except Exception:
        logger.exception("Failed to mount blob_download_app")
        raise

    # Import Chainlit event handlers.
    import app as chainlit_handlers  # noqa: F401
    logger.info("Chainlit handlers imported")

    # Provide friendly app metadata used by OpenAPI.
    chainlit_app.title = getattr(chainlit_app, "title", "GPT-RAG UI")
    try:
        if os.path.exists("VERSION"):
            with open("VERSION", "r", encoding="utf-8") as f:
                chainlit_app.version = f.read().strip()
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

    FastAPIInstrumentor.instrument_app(chainlit_app)
    HTTPXClientInstrumentor().instrument()
    return chainlit_app


def build_app() -> FastAPI:
    config: AppConfigClient = get_config()
    _startup_banner()

    connected = bool(getattr(config, "connected", False))
    if connected:
        logger.info("Configuration loaded from Azure App Configuration")

        # Configure Chainlit prerequisites (session secret, URL) even when OAuth is missing.
        _configure_chainlit_prereqs(config)
        auth_state = _evaluate_auth_state(config)

        if auth_state.oauth_configured or auth_state.allow_anonymous:
            return _create_chainlit_app(config, auth_state)

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