import logging
import os
import secrets
from io import BytesIO

from fastapi import Response, Request, FastAPI
from fastapi.responses import StreamingResponse

# Configure logging FIRST
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(name)s: %(message)s'
)

# Reduce noise from chatty Azure SDK loggers so troubleshooting signals stand out.
logging.getLogger("azure").setLevel(logging.WARNING)
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)

logger = logging.getLogger("gpt_rag_ui.main")

def _startup_banner() -> None:
    name = "GPT-RAG UI"
    version = None
    try:
        if os.path.exists("VERSION"):
            version = open("VERSION").read().strip()
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

from connectors import BlobClient
from connectors import AppConfigClient
from dependencies import get_config

# Load environment variables from Azure App Configuration
config: AppConfigClient = get_config()
_startup_banner()
connected = bool(getattr(config, "connected", False))

if connected:
    logger.info("Configuration loaded from Azure App Configuration")
else:
    logger.warning(
        "Running without Azure App Configuration (not logged in or unavailable). "
        "Set env vars locally or run 'az login' to enable App Configuration."
    )

if not connected:
    # Don't attempt to initialize the rest of the app (Chainlit, telemetry, blob downloads).
    # Serve a small, explicit error page instead of crashing mid-import.
    app = FastAPI(title="GPT-RAG UI (configuration required)")

    @app.on_event("startup")
    async def _log_not_ready_startup() -> None:
        logger.error(
            "APPLICATION STARTED IN NOT-READY MODE: Azure App Configuration is unavailable. "
            "This instance will return HTTP 503 until configuration is fixed."
        )

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

else:
    # Import chainlit_app AFTER config is ready

    # Chainlit requires env var CHAINLIT_AUTH_SECRET to sign its session JWT.
    # Prefer storing it in App Configuration (key `chainlitAuthSecret`) backed by Key Vault.
    # If missing, generate a temporary secret (sessions will be invalidated on restart).
    if not os.environ.get("CHAINLIT_AUTH_SECRET"):
        chainlit_secret = config.get("chainlitAuthSecret", "", str)
        if chainlit_secret:
            os.environ["CHAINLIT_AUTH_SECRET"] = chainlit_secret
            logger.info("Configured CHAINLIT_AUTH_SECRET from App Configuration key 'chainlitAuthSecret'")
        else:
            temp_secret = secrets.token_urlsafe(48)
            os.environ["CHAINLIT_AUTH_SECRET"] = temp_secret
            logger.warning(
                "App Configuration key 'chainlitAuthSecret' is not set; using a temporary secret. "
                "Set 'chainlitAuthSecret' (ideally Key Vault-backed) to avoid session resets on restart."
            )

    from chainlit.server import app as chainlit_app
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

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

    account_name = config.get("STORAGE_ACCOUNT_NAME", "", str)
    documents_container = config.get("DOCUMENTS_STORAGE_CONTAINER", "", str)
    images_container = config.get("DOCUMENTS_IMAGES_STORAGE_CONTAINER", "", str)

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
                media_type="text/plain"
            )
        
        actual_file_name = os.path.basename(file_path)
        return StreamingResponse(
            BytesIO(file_bytes),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{actual_file_name}"'}
        )

# TODO: Validate blob metadata_security_id to prevent unauthorized access.

    # Create a separate FastAPI app for blob downloads that will be mounted
    blob_download_app = FastAPI()
    logger.info("Created FastAPI sub-application for blob downloads")

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

    # Mount the blob download app BEFORE importing chainlit handlers
    try:
        chainlit_app.mount("/api/download", blob_download_app)
        logger.info("Mounted blob download app at /api/download")
        logger.debug("Chainlit routes post-mount: %s", [r.path for r in chainlit_app.routes])
    except Exception:
        logger.exception("Failed to mount blob_download_app")
        raise

    # Import Chainlit event handlers
    import app as chainlit_handlers

    logger.info("Chainlit handlers imported")

    # ASGI entry point
    app = chainlit_app

    # Provide friendly app metadata used by OpenAPI (read version from VERSION file when present)
    chainlit_app.title = getattr(chainlit_app, "title", "GPT-RAG UI")
    try:
        if os.path.exists("VERSION"):
            chainlit_app.version = open("VERSION").read().strip()
    except Exception:
        chainlit_app.version = getattr(chainlit_app, "version", "dev")

    # Safe OpenAPI generator: try normal get_openapi, fall back to minimal schema on error
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
            # Log the original exception and return a tiny fallback openapi schema so /docs and /openapi.json don't 500
            logger.exception("OpenAPI generation failed; returning fallback schema")
            chainlit_app.openapi_schema = {
                "openapi": "3.0.0",
                "info": {"title": chainlit_app.title, "version": chainlit_app.version},
                "paths": {},
            }
        return chainlit_app.openapi_schema

    chainlit_app.openapi = _safe_openapi

    FastAPIInstrumentor.instrument_app(app)
    HTTPXClientInstrumentor().instrument()