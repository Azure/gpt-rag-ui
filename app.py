import os
import base64
import json
import re
import uuid
import logging
import urllib.parse
from typing import Optional, Set, Tuple
from datetime import datetime, timedelta

import chainlit as cl
import httpx

from orchestrator_client import call_orchestrator_stream
from feedback import register_feedback_handlers,create_feedback_actions
from dependencies import get_config
from connectors import BlobClient

from constants import APPLICATION_INSIGHTS_CONNECTION_STRING, APP_NAME, UUID_REGEX, REFERENCE_REGEX, TERMINATE_TOKEN
from telemetry import Telemetry
from opentelemetry.trace import SpanKind

logger = logging.getLogger("gpt_rag_ui.app")

config = get_config()

Telemetry.configure_monitoring(config, APPLICATION_INSIGHTS_CONNECTION_STRING, APP_NAME)

ENABLE_FEEDBACK = config.get("ENABLE_USER_FEEDBACK", False, bool)
_is_running_in_azure_host = bool(
    os.environ.get("WEBSITE_SITE_NAME")
    or os.environ.get("CONTAINER_APP_NAME")
    or os.environ.get("CONTAINER_APP_REVISION")
)


def _oauth_is_configured() -> bool:
    # Consider OAuth configured only when the required AAD fields exist.
    # If OAuth isn't configured, we treat requests as anonymous (do not block).
    client_id = config.get("OAUTH_AZURE_AD_CLIENT_ID", "", str) or config.get("CLIENT_ID", "", str)
    client_secret = config.get("OAUTH_AZURE_AD_CLIENT_SECRET", "", str) or config.get("authClientSecret", "", str)
    tenant_id = config.get("OAUTH_AZURE_AD_TENANT_ID", "", str)
    return bool(client_id and client_secret and tenant_id)


OAUTH_CONFIGURED = _oauth_is_configured()

# If OAuth isn't configured, default to allowing anonymous even in Azure.
ALLOW_ANONYMOUS = config.get("ALLOW_ANONYMOUS", (not _is_running_in_azure_host) or (not OAUTH_CONFIGURED), bool)
STORAGE_ACCOUNT_NAME = config.get("STORAGE_ACCOUNT_NAME", "", str)


def _normalize_container_name(container: Optional[str]) -> str:
    if not container:
        return ""
    return container.strip().strip("/")


DOCUMENTS_CONTAINER = _normalize_container_name(
    config.get("DOCUMENTS_STORAGE_CONTAINER", "", str)
)
IMAGES_CONTAINER = _normalize_container_name(
    config.get("DOCUMENTS_IMAGES_STORAGE_CONTAINER", "", str)
)
IMAGE_EXTENSIONS = {"bmp", "jpeg", "jpg", "png", "tiff"}

def extract_conversation_id_from_chunk(chunk: str) -> Tuple[Optional[str], str]:
    match = UUID_REGEX.match(chunk)
    if match:
        conv_id = match.group(1)
        logger.debug("Extracted conversation id %s from stream chunk", conv_id)
        return conv_id, chunk[match.end():]
    return None, chunk

def generate_blob_sas_url(container: str, blob_name: str, expiry_hours: int = 1) -> str:
    """
    Generate a time-limited SAS URL for direct blob download.
    This bypasses Container Apps routing completely.
    Raises FileNotFoundError if the blob does not exist.
    """
    try:
        blob_url = f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net/{container}/{blob_name}"
        blob_client = BlobClient(blob_url=blob_url)
        if not blob_client.exists():
            logger.info("Blob not found: %s/%s - reference will be omitted", container, blob_name)
            raise FileNotFoundError(f"Blob '{container}/{blob_name}' not found")
        
        # Generate SAS token with read permission
        from datetime import datetime, timedelta, timezone
        expiry = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)
        
        # Try to generate SAS URL (requires azure-storage-blob with SAS support)
        try:
            sas_url = blob_client.generate_sas_url(expiry=expiry, permissions="r")
            logger.debug(
                "Generated SAS URL for %s/%s (expires in %sh)",
                container,
                blob_name,
                expiry_hours,
            )
            return sas_url
        except AttributeError:
            # Fallback: return direct blob URL (relies on public access or managed identity at client side)
            logger.warning(
                "SAS generation not supported, using direct blob URL for %s/%s",
                container,
                blob_name,
            )
            return blob_url
    except FileNotFoundError:
        # Re-raise FileNotFoundError so the caller can handle it
        raise
    except Exception as e:
        logger.exception("Failed to generate blob URL for %s/%s", container, blob_name)
        raise

def resolve_reference_href(raw_href: str) -> Optional[str]:
    """
    Resolve a reference href to a SAS URL. Returns None if the blob doesn't exist.
    """
    href = (raw_href or "").strip()
    if not href:
        return None

    split_href = urllib.parse.urlsplit(href)
    if split_href.scheme or split_href.netloc:
        return href

    if href.startswith("/api/download/") or href.startswith("api/download/"):
        return href

    path = urllib.parse.unquote(split_href.path.replace("\\", "/")).lstrip("/")
    query = f"?{split_href.query}" if split_href.query else ""
    fragment = f"#{split_href.fragment}" if split_href.fragment else ""

    extension = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    container = DOCUMENTS_CONTAINER
    if extension in IMAGE_EXTENSIONS and IMAGES_CONTAINER:
        container = IMAGES_CONTAINER
    elif not container and IMAGES_CONTAINER:
        container = IMAGES_CONTAINER

    # Extract clean blob name
    if container:
        if path.startswith(f"{container}/"):
            blob_name = path[len(container)+1:]
        elif path:
            blob_name = path
        else:
            blob_name = ""
    else:
        blob_name = path

    if not blob_name:
        return None

    # Generate direct SAS URL to Azure Blob Storage (bypasses Container Apps completely)
    try:
        sas_url = generate_blob_sas_url(container, blob_name)
    except FileNotFoundError:
        logger.info("Reference '%s' points to missing blob %s/%s - omitting from output", raw_href, container, blob_name)
        return None
    except Exception:
        logger.warning("Failed to build SAS URL for reference '%s' - omitting from output", raw_href)
        return None
    
    # Add original query and fragment if present
    if sas_url and (query or fragment):
        separator = "&" if "?" in sas_url else "?"
        return f"{sas_url}{separator}{query.lstrip('?')}{fragment}"

    return sas_url


def replace_source_reference_links(text: str, references: Optional[Set[str]] = None) -> str:
    """
    Replace source reference links in text. Links that point to non-existent blobs are completely removed.
    """
    def replacer(match):
        display_text = match.group(1)
        raw_href = match.group(2)
        # Resolve the original link into a signed blob URL when possible, otherwise drop it.
        resolved_href = resolve_reference_href(raw_href)
        if resolved_href:
            if references is not None:
                references.add(resolved_href)
            logger.debug("Resolved reference '%s' -> '%s'", raw_href, resolved_href)
            return f"[{display_text}]({resolved_href})"
        # Returning an empty string removes the reference completely when the blob is missing
        logger.debug("Omitting reference '[%s](%s)' - target not found", display_text, raw_href)
        return ""

    return REFERENCE_REGEX.sub(replacer, text)

def check_authorization() -> dict:
    app_user = cl.user_session.get("user")
    if app_user:
        metadata = app_user.metadata or {}
        return {
            'authorized': metadata.get('authorized', True),
            'client_principal_id': metadata.get('client_principal_id', 'no-auth'),
            'client_principal_name': metadata.get('client_principal_name', 'anonymous'),
            'client_group_names': metadata.get('client_group_names', []),
            'access_token': metadata.get('access_token')
        }

    # If OAuth is configured but we don't have a user in session,
    # treat as unauthorized (forces the UI to require auth).
    # Otherwise, allow anonymous.
    return {
        'authorized': (ALLOW_ANONYMOUS if not OAUTH_CONFIGURED else False),
        'client_principal_id': 'no-auth',
        'client_principal_name': 'anonymous',
        'client_group_names': [],
        'access_token': None
    }


async def get_auth_info() -> dict:
    """Return the effective auth info for the current session.

    If OAuth is configured and a user session exists, automatically refreshes the access token
    when it is close to expiry to avoid "invalid token" failures in the orchestrator.
    """

    app_user = cl.user_session.get("user")
    if app_user:
        # Opportunistic token refresh (OAuth mode only).
        if OAUTH_CONFIGURED:
            try:
                # Import is safe because we import auth_oauth only when OAUTH_CONFIGURED.
                refreshed = await auth_oauth.ensure_fresh_user_access_token(app_user, min_ttl_seconds=120)
                if refreshed:
                    cl.user_session.set("user", app_user)
            except Exception:
                # If refresh fails, clear the user session so the UI can re-auth.
                logger.warning("User access token refresh failed; clearing session to force re-auth", exc_info=True)
                cl.user_session.set("user", None)
                return {
                    'authorized': False,
                    'client_principal_id': 'no-auth',
                    'client_principal_name': 'anonymous',
                    'client_group_names': [],
                    'access_token': None,
                    'auth_error': 'session_expired',
                }

        metadata = app_user.metadata or {}
        return {
            'authorized': metadata.get('authorized', True),
            'client_principal_id': metadata.get('client_principal_id', 'no-auth'),
            'client_principal_name': metadata.get('client_principal_name', 'anonymous'),
            'client_group_names': metadata.get('client_group_names', []),
            'access_token': metadata.get('access_token'),
        }

    return {
        'authorized': (ALLOW_ANONYMOUS if not OAUTH_CONFIGURED else False),
        'client_principal_id': 'no-auth',
        'client_principal_name': 'anonymous',
        'client_group_names': [],
        'access_token': None
    }


def _decode_jwt_unverified(token: str) -> dict | None:
    """Decode JWT payload without verifying signature.

    Debug-only helper. Never use this to authorize.
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

    def _short(value: object) -> str:
        s = str(value or "")
        if len(s) <= 10:
            return s
        return f"{s[:4]}…{s[-4:]}"

    return {
        "aud": aud_value,
        "tid": _short(claims.get("tid")) if claims.get("tid") else None,
        "oid": _short(claims.get("oid")) if claims.get("oid") else None,
        "iss": claims.get("iss"),
        "scp": claims.get("scp"),
        "ver": claims.get("ver"),
    }

# Importing `auth_oauth` registers @cl.oauth_callback as a side effect.
# Only register OAuth when the minimum configuration is present.
if OAUTH_CONFIGURED:
    ENABLE_AUTHENTICATION = True
    import auth_oauth  # noqa: F401
    logger.info("Authentication enabled: Chainlit OAuth (Azure AD)")
else:
    ENABLE_AUTHENTICATION = False
    if ALLOW_ANONYMOUS:
        logger.warning(
            "Authentication disabled: OAuth not configured; running in anonymous mode (ALLOW_ANONYMOUS=true)"
        )
    else:
        raise RuntimeError(
            "OAuth is not configured (missing client_id/tenant_id/client_secret) and ALLOW_ANONYMOUS=false. "
            "Set OAUTH_AZURE_AD_CLIENT_ID, OAUTH_AZURE_AD_TENANT_ID, and OAUTH_AZURE_AD_CLIENT_SECRET (or authClientSecret)."
        )

tracer = Telemetry.get_tracer(__name__)

# Register feedback handlers
if ENABLE_FEEDBACK:
    register_feedback_handlers(get_auth_info)

# Chainlit event handlers
@cl.on_chat_start
async def on_chat_start():
    pass
    # app_user = cl.user_session.get("user")
    # if app_user:
        # await cl.Message(content=f"Hello {app_user.metadata.get('user_name')}").send()

@cl.on_message
async def handle_message(message: cl.Message):
    
    with tracer.start_as_current_span('handle_message', kind=SpanKind.SERVER) as span:

        message.id = message.id or str(uuid.uuid4())
        conversation_id = cl.user_session.get("conversation_id") or ""
        response_msg = cl.Message(content="")

        def _trim_for_log(value: str, limit: int = 400) -> str:
            clean_value = (value or "").strip().replace("\n", " ")
            if len(clean_value) > limit:
                return f"{clean_value[:limit].rstrip()}..."
            return clean_value

        auth_info = await get_auth_info()
        principal = auth_info.get('client_principal_name', 'anonymous')

        if auth_info.get('auth_error') == 'session_expired':
            await response_msg.stream_token(
                "Your session has expired. Please sign out and sign in again to continue."
            )
            logger.warning(
                "Blocked request due to expired auth session: conversation=%s",
                conversation_id or "new",
            )
            return

        if not auth_info.get('authorized', False):
            await response_msg.stream_token(
                "Oops! It looks like you don’t have access to this service. "
                "If you think you should, please reach out to your administrator for help."
            )
            logger.warning(
                "Blocked unauthorized request: conversation=%s user=%s",
                conversation_id or "new",
                auth_info.get('client_principal_id', 'unknown'),
            )
            return

        app_user = cl.user_session.get("user")
        
        span.set_attribute('question_id', message.id)
        span.set_attribute('conversation_id', conversation_id)
        span.set_attribute('user_id', auth_info.get('client_principal_id', 'anonymous'))
        logger.info(
            "User request received: conversation=%s question_id=%s user=%s preview='%s'",
            conversation_id or "new",
            message.id,
            principal,
            _trim_for_log(message.content),
        )

        await response_msg.stream_token(" ")

        buffer = ""
        full_text = ""
        references = set()
        logger.info(
            "Forwarding request to orchestrator: conversation=%s question_id=%s user=%s authorized=%s groups=%d",
            conversation_id or "new",
            message.id,
            principal,
            auth_info.get("authorized"),
            len(auth_info.get("client_group_names", [])),
        )

        if logger.isEnabledFor(logging.DEBUG) and auth_info.get("access_token"):
            logger.debug(
                "Orchestrator call access token claims (unverified): conversation=%s question_id=%s %s",
                conversation_id or "new",
                message.id,
                _access_token_debug_summary(str(auth_info.get("access_token"))),
            )
        logger.debug(
            "Orchestrator payload preview: conversation=%s question_id=%s preview='%s'",
            conversation_id or "new",
            message.id,
            _trim_for_log(message.content),
        )
        generator = call_orchestrator_stream(conversation_id, message.content, auth_info, message.id)

        chunk_count = 0
        first_content_seen = False

        try:
            async for chunk in generator:
                # logging.info("[app] Chunk received: %s", chunk)

                # Extract and update conversation ID
                extracted_id, cleaned_chunk = extract_conversation_id_from_chunk(chunk)
                if extracted_id:
                    conversation_id = extracted_id

                cleaned_chunk = cleaned_chunk.replace("\\n", "\n")

                normalized_preview = cleaned_chunk.strip().lower()
                if not first_content_seen and normalized_preview:
                    if (
                        normalized_preview.startswith("<!doctype")
                        or normalized_preview.startswith("<html")
                        or "<html" in normalized_preview[:120]
                        or "azure container apps" in normalized_preview
                    ):
                        logger.error(
                            "Received HTML payload from orchestrator: conversation=%s question_id=%s",
                            conversation_id or "pending",
                            message.id,
                        )
                        raise RuntimeError("orchestrator returned html placeholder")
                    first_content_seen = True

                # Track and rewrite references as blob download links
                chunk_refs: Set[str] = set()
                cleaned_chunk = replace_source_reference_links(cleaned_chunk, chunk_refs)
                if chunk_refs:
                    references.update(chunk_refs)
                    logger.info(
                        "Streaming response references detected: conversation=%s question_id=%s refs=%s",
                        conversation_id or "pending",
                        message.id,
                        sorted(chunk_refs),
                    )

                buffer += cleaned_chunk
                full_text += cleaned_chunk
                chunk_count += 1

                # Handle TERMINATE token
                token_index = buffer.find(TERMINATE_TOKEN)
                if token_index != -1:
                    if token_index > 0:
                        await response_msg.stream_token(buffer[:token_index])
                    logger.debug(
                        "Terminate token detected, draining remaining orchestrator stream: conversation=%s question_id=%s",
                        conversation_id or "pending",
                        message.id,
                    )
                    async for _ in generator:
                        pass  # drain
                    break

                # Stream safe part of buffer
                if token_index != -1:
                    safe_flush_length = len(buffer) - (len(TERMINATE_TOKEN) - 1)
                else:
                    safe_flush_length = len(buffer)

                if safe_flush_length > 0:
                    await response_msg.stream_token(buffer[:safe_flush_length])
                    buffer = buffer[safe_flush_length:]

        except httpx.ConnectError as e:
            logger.error(
                "Orchestrator unreachable (connection error): conversation=%s question_id=%s error=%s",
                conversation_id or "pending",
                message.id,
                e,
            )
            user_error_message = (
                "We couldn't reach the orchestrator service. "
                "Please contact the application support team and share reference "
                f"{message.id}."
            )
            full_text = user_error_message
            buffer = ""
            await response_msg.stream_token(user_error_message)

        except httpx.TimeoutException as e:
            logger.error(
                "Orchestrator request timed out: conversation=%s question_id=%s error=%s",
                conversation_id or "pending",
                message.id,
                e,
            )
            user_error_message = (
                "The orchestrator service took too long to respond. "
                "Please contact the application support team and share reference "
                f"{message.id}."
            )
            full_text = user_error_message
            buffer = ""
            await response_msg.stream_token(user_error_message)

        except Exception as e:
            user_error_message = (
                "We hit a technical issue while processing your request. "
                "Please contact the application support team and share reference "
                f"{message.id}."
            )
            logger.exception(
                "Failed while processing orchestrator response: conversation=%s question_id=%s",
                conversation_id or "pending",
                message.id,
            )
            full_text = user_error_message
            buffer = ""
            await response_msg.stream_token(user_error_message)

        finally:
            try:
                await generator.aclose()
            except RuntimeError as exc:
                if "async generator ignored GeneratorExit" not in str(exc):
                    raise

        cl.user_session.set("conversation_id", conversation_id)
        if references:
            logger.info(
                "Aggregated response references: conversation=%s question_id=%s refs=%s",
                conversation_id,
                message.id,
                sorted(references),
            )
        if ENABLE_FEEDBACK:
            response_msg.actions = create_feedback_actions(
                message.id, conversation_id, message.content
            )
        final_text = replace_source_reference_links(
            full_text.replace(TERMINATE_TOKEN, ""), references
        )
        response_msg.content = final_text
        await response_msg.update()

        logger.info(
            "Response delivered: conversation=%s question_id=%s chunks=%s characters=%s preview='%s'",
            conversation_id,
            message.id,
            chunk_count,
            len(final_text),
            _trim_for_log(final_text),
        )
