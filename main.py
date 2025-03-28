import logging
import os
from io import BytesIO

from fastapi import Response
from fastapi.responses import StreamingResponse
from chainlit.server import app as chainlit_app

from connectors import BlobClient

def get_env_var(var_name: str) -> str:
    """Retrieve required environment variable or raise error."""
    value = os.getenv(var_name)
    if not value:
        raise EnvironmentError(f"{var_name} is not set.")
    return value

def download_from_blob(file_name: str) -> bytes:
    logging.info("[chainlit_app] Downloading file: %s", file_name)
    
    account_name = get_env_var("STORAGE_ACCOUNT_NAME")

    blob_url = f"https://{account_name}.blob.core.windows.net/{file_name}"
    logging.debug(f"[chainlit_app] Constructed blob URL: {blob_url}")
    
    try:
        blob_client = BlobClient(blob_url=blob_url)
        blob_data = blob_client.download_blob()
        logging.debug(f"[chainlit_app] Successfully downloaded blob data: {file_name}")
        return blob_data
    except Exception as e:
        logging.error(f"[chainlit_app] Error downloading blob {file_name}: {e}")
        raise

@chainlit_app.get("/source/{file_path:path}")
def download_file(file_path: str):
    # TODO: Validate blob metadata_security_id to prevent unauthorized access.
    try:
        file_bytes = download_from_blob(file_path)
        if not file_bytes:
            return Response("File not found or empty.", status_code=404, media_type="text/plain")
    except Exception as e:
        error_message = str(e)
        status_code = 404 if "BlobNotFound" in error_message else 500
        logging.exception(f"[chainlit_app] Download error: {error_message}")
        return Response(
            f"{'Blob not found' if status_code == 404 else 'Internal server error'}: {error_message}.",
            status_code=status_code,
            media_type="text/plain"
        )
    
    # Extract the actual file name if the provided file_name includes slashes.
    actual_file_name = os.path.basename(file_path)
    
    return StreamingResponse(
        BytesIO(file_bytes),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{actual_file_name}"'}
    )

# -----------------------------------
# Ensure source route is prioritized
# -----------------------------------
try:
    source_route = next(
        route for route in chainlit_app.router.routes if getattr(route, "path", "").startswith("/source/")
    )
    chainlit_app.router.routes.remove(source_route)
    chainlit_app.router.routes.insert(0, source_route)
    logging.info("[chainlit_app] Moved source route to the top of the route list.")
except StopIteration:
    logging.warning("[chainlit_app] source route not found; skipping reorder.")

# Import Chainlit event handlers (side-effect registration)
import app

# ASGI entry point
app = chainlit_app
