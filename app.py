import os
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

    return {
        'authorized': True,
        'client_principal_id': 'no-auth',
        'client_principal_name': 'anonymous',
        'client_group_names': [],
        'access_token': None
    }

# Check if authentication is enabled
ENABLE_AUTHENTICATION = config.get("ENABLE_AUTHENTICATION", False, bool)
if ENABLE_AUTHENTICATION:
    import auth

tracer = Telemetry.get_tracer(__name__)

# Register feedback handlers
if ENABLE_FEEDBACK:
    register_feedback_handlers(check_authorization)

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

        app_user = cl.user_session.get("user")
        if app_user and not app_user.metadata.get('authorized', True):
            await response_msg.stream_token(
                "Oops! It looks like you don’t have access to this service. "
                "If you think you should, please reach out to your administrator for help."
            )
            logger.warning(
                "Blocked unauthorized request: conversation=%s user=%s",
                conversation_id or "new",
                app_user.metadata.get('client_principal_id', 'unknown'),
            )
            return
        
        span.set_attribute('question_id', message.id)
        span.set_attribute('conversation_id', conversation_id)
        span.set_attribute('user_id', app_user.metadata.get('client_principal_id', 'no-auth') if app_user else 'anonymous')

        principal = app_user.metadata.get('client_principal_name', 'anonymous') if app_user else 'anonymous'
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
        auth_info = check_authorization()
        logger.info(
            "Forwarding request to orchestrator: conversation=%s question_id=%s user=%s authorized=%s groups=%d",
            conversation_id or "new",
            message.id,
            principal,
            auth_info.get("authorized"),
            len(auth_info.get("client_group_names", [])),
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
