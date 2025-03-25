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
    
    account_name = get_env_var("BLOB_STORAGE_ACCOUNT_NAME")
    container_name = get_env_var("BLOB_STORAGE_CONTAINER")

    blob_url = f"https://{account_name}.blob.core.windows.net/{container_name}/{file_name}"
    logging.debug(f"[chainlit_app] Constructed blob URL: {blob_url}")
    
    try:
        blob_client = BlobClient(blob_url=blob_url)
        blob_data = blob_client.download_blob()
        logging.debug(f"[chainlit_app] Successfully downloaded blob data: {file_name}")
        return blob_data
    except Exception as e:
        logging.error(f"[chainlit_app] Error downloading blob {file_name}: {e}")
        raise

@chainlit_app.get("/download/{file_name}")
def download_file(file_name: str):
    try:
        file_bytes = download_from_blob(file_name)
        if not file_bytes:
            return Response("File not found or empty.", status_code=404, media_type="text/plain")
    except Exception as e:
        error_message = str(e)
        status_code = 404 if "BlobNotFound" in error_message else 500
        logging.exception(f"[chainlit_app] Download error: {error_message}")
        return Response(f"{'Blob not found' if status_code == 404 else 'Internal server error'}: {error_message}.",
                        status_code=status_code, media_type="text/plain")
    
    return StreamingResponse(
        BytesIO(file_bytes),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'}
    )

# -----------------------------------
# Ensure download route is prioritized
# -----------------------------------
try:
    download_route = next(
        route for route in chainlit_app.router.routes if getattr(route, "path", "").startswith("/download/")
    )
    chainlit_app.router.routes.remove(download_route)
    chainlit_app.router.routes.insert(0, download_route)
    logging.info("[chainlit_app] Moved download route to the top of the route list.")
except StopIteration:
    logging.warning("[chainlit_app] Download route not found; skipping reorder.")

# Import Chainlit event handlers (side-effect registration)
import app

# ASGI entry point
app = chainlit_app
