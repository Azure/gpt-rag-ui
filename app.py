import os
import base64
import json
import re
import uuid
import logging
import time
import urllib.parse
from typing import Optional, Set, Tuple
from datetime import datetime, timedelta

import chainlit as cl
import httpx

from orchestrator_client import call_orchestrator_stream
from feedback import register_feedback_handlers,create_feedback_actions
from dependencies import get_config
from ingestion_client import ingest_files_session
from download_security import get_download_tokens, is_download_target_allowed
from embed_auth import resolve_access_token

from constants import APPLICATION_INSIGHTS_CONNECTION_STRING, APP_NAME, UUID_REGEX, REFERENCE_REGEX, TERMINATE_TOKEN
from telemetry import Telemetry
from opentelemetry.trace import SpanKind
from chainlit.types import ThreadDict

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


COPILOT_ENABLED = (
    os.environ.get("CHAINLIT_COPILOT_ENABLED_EFFECTIVE", "").lower() == "true"
)
OAUTH_CONFIGURED = _oauth_is_configured()

# If OAuth isn't configured, default to allowing anonymous even in Azure.
_allow_anonymous_effective = os.environ.get("ALLOW_ANONYMOUS_EFFECTIVE")
if _allow_anonymous_effective is not None:
    ALLOW_ANONYMOUS = _allow_anonymous_effective.lower() == "true"
else:
    ALLOW_ANONYMOUS = config.get(
        "ALLOW_ANONYMOUS",
        not _is_running_in_azure_host,
        bool,
    )
STORAGE_ACCOUNT_NAME = config.get("STORAGE_ACCOUNT_NAME", "", str)
SHOW_STATISTICS = config.get("SHOW_STATISTICS", False, bool)


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
CONVERSATION_DOCUMENTS_CONTAINER = _normalize_container_name(
    config.get("CONVERSATION_DOCUMENTS_STORAGE_CONTAINER", "", str)
)
SHARED_DOWNLOAD_CONTAINERS = {
    _normalize_container_name(container)
    for container in str(
        config.get("CITATION_SHARED_DOWNLOAD_CONTAINERS", "", str) or ""
    ).split(",")
    if _normalize_container_name(container)
}
IMAGE_EXTENSIONS = {"bmp", "jpeg", "jpg", "png", "tiff"}

def extract_conversation_id_from_chunk(chunk: str) -> Tuple[Optional[str], str]:
    match = UUID_REGEX.match(chunk)
    if match:
        conv_id = match.group(1)
        logger.debug("Extracted conversation id %s from stream chunk", conv_id)
        return conv_id, chunk[match.end():]
    return None, chunk

def resolve_reference_href(
    raw_href: str,
    *,
    conversation_id: str,
    principal_id: str,
) -> Optional[str]:
    """Create an authenticated, principal-bound absolute citation URL."""
    href = (raw_href or "").strip()
    if not href or not conversation_id or not principal_id:
        return None

    split_href = urllib.parse.urlsplit(href)
    if split_href.scheme or split_href.netloc:
        return None

    path = urllib.parse.unquote(split_href.path.replace("\\", "/")).lstrip("/")
    fragment = f"#{split_href.fragment}" if split_href.fragment else ""
    if not path or any(part in {"", ".", ".."} for part in path.split("/")):
        return None

    extension = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    container = DOCUMENTS_CONTAINER
    if extension in IMAGE_EXTENSIONS and IMAGES_CONTAINER:
        container = IMAGES_CONTAINER
    elif not container and IMAGES_CONTAINER:
        container = IMAGES_CONTAINER

    blob_name: str
    # Per-conversation uploads (separate blob container), not used for image extensions.
    if (
        CONVERSATION_DOCUMENTS_CONTAINER
        and not (extension in IMAGE_EXTENSIONS and IMAGES_CONTAINER)
        and (
            path.startswith(f"{CONVERSATION_DOCUMENTS_CONTAINER}/")
            or path.startswith("conversations/")
        )
    ):
        if path.startswith(f"{CONVERSATION_DOCUMENTS_CONTAINER}/"):
            blob_name = path[len(CONVERSATION_DOCUMENTS_CONTAINER) + 1 :]
        else:
            blob_name = path
        container = CONVERSATION_DOCUMENTS_CONTAINER
    elif container:
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
    if not is_download_target_allowed(
        conversation_id=conversation_id,
        container=container,
        blob_name=blob_name,
        conversation_container=CONVERSATION_DOCUMENTS_CONTAINER,
        shared_containers=SHARED_DOWNLOAD_CONTAINERS,
    ):
        logger.warning(
            "Citation download omitted by container authorization policy: container=%s",
            container,
        )
        return None

    try:
        download_url = get_download_tokens().issue(
            principal_id=principal_id,
            conversation_id=conversation_id,
            container=container,
            blob_name=blob_name,
        )
    except (RuntimeError, ValueError):
        logger.warning(
            "Unable to issue an authenticated citation URL for '%s'",
            raw_href,
        )
        return None
    return f"{download_url}{fragment}"


def replace_source_reference_links(
    text: str,
    references: Optional[Set[str]] = None,
    *,
    conversation_id: str,
    principal_id: str,
) -> str:
    """
    Replace source reference links in text. Links that point to non-existent blobs are completely removed.
    """
    def replacer(match):
        display_text = match.group(1)
        raw_href = match.group(2)
        # Resolve the original link into a signed blob URL when possible, otherwise drop it.
        resolved_href = resolve_reference_href(
            raw_href,
            conversation_id=conversation_id,
            principal_id=principal_id,
        )
        if resolved_href:
            if references is not None:
                references.add(resolved_href)
            logger.debug("Resolved reference '%s' -> '%s'", raw_href, resolved_href)
            return f"[{display_text}]({resolved_href})"
        logger.debug("Rendering citation '%s' without an unauthorized link", display_text)
        return display_text

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
            'access_token': (
                metadata.get('access_token')
                if metadata.get("auth_source") != "copilot_session"
                else None
            ),
            'principal_id': metadata.get('principal_id', ''),
            'tenant_id': metadata.get('tenant_id', ''),
            'object_id': metadata.get('object_id', ''),
        }

    # If OAuth is configured but we don't have a user in session,
    # treat as unauthorized (forces the UI to require auth).
    # Otherwise, allow anonymous.
    return {
        'authorized': (
            ALLOW_ANONYMOUS
            if not OAUTH_CONFIGURED
            else False
        ),
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
        metadata = app_user.metadata or {}
        if metadata.get("auth_source") == "copilot_session":
            access_token = await resolve_access_token(metadata)
            if not access_token:
                logger.warning(
                    "Embedded Copilot session expired for user=%s",
                    metadata.get("client_principal_name")
                    or metadata.get("client_principal_id")
                    or app_user.identifier,
                )
                cl.user_session.set("user", None)
                return {
                    'authorized': False,
                    'client_principal_id': 'no-auth',
                    'client_principal_name': 'anonymous',
                    'client_group_names': [],
                    'access_token': None,
                    'auth_error': 'session_expired',
                }
        else:
            access_token = metadata.get("access_token")

        # Opportunistic token refresh (OAuth mode only).
        if metadata.get("auth_source") == "oauth":
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

        return {
            'authorized': metadata.get('authorized', True),
            'client_principal_id': metadata.get('client_principal_id', 'no-auth'),
            'client_principal_name': metadata.get('client_principal_name', 'anonymous'),
            'client_group_names': metadata.get('client_group_names', []),
            'access_token': access_token,
            'principal_id': metadata.get('principal_id', ''),
            'tenant_id': metadata.get('tenant_id', ''),
            'object_id': metadata.get('object_id', ''),
        }

    return {
        'authorized': (
            ALLOW_ANONYMOUS
            if not OAUTH_CONFIGURED
            else False
        ),
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
    import datalayer  # noqa: F401  — registers @cl.data_layer for conversation history
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

@cl.on_chat_resume
async def on_chat_resume(thread: ThreadDict):
    app_user = cl.user_session.get("user")
    if not app_user or thread.get("userIdentifier") != app_user.identifier:
        logger.warning("Blocked unauthorized chat resume: thread=%s", thread["id"])
        raise PermissionError("Thread access denied.")
    cl.user_session.set("conversation_id", thread["id"])
    logger.info("Chat resumed: thread=%s", thread["id"])

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
        
        
        await response_msg.send()
        handler_start = time.time()
        # ====== FILES PROCESSING ======
        allowed_mimes = {
            "application/pdf",
        }
        max_files = 5
        max_file_bytes = 15 * 1024 * 1024
        max_total_bytes = 25 * 1024 * 1024

        uploaded_files: list[dict] = []
        rejected: list[str] = []
        total_declared_bytes = 0
        file_reply_parts: list[str] = []

        if message.elements:
            for element in message.elements:
                if not isinstance(element, cl.File):
                    continue

                mime = (getattr(element, "mime", "") or "").lower()
                name = getattr(element, "name", "upload")
                path = getattr(element, "path", None)
                size = getattr(element, "size", 0) or 0

                if not path:
                    rejected.append(f"{name} (missing path)")
                    continue

                if mime not in allowed_mimes:
                    rejected.append(f"{name} (unsupported type: {mime or 'unknown'})")
                    continue

                if isinstance(size, int) and size > max_file_bytes:
                    rejected.append(f"{name} (too large)")
                    continue

                total_declared_bytes += int(size) if isinstance(size, int) else 0
                if total_declared_bytes > max_total_bytes:
                    rejected.append(f"{name} (total upload too large)")
                    continue

                uploaded_files.append({"name": name, "path": path, "mime": mime, "size": int(size)})
                logger.info(
                    "File queued for ingestion: name=%s mime=%s conversation=%s",
                    name,
                    mime,
                    conversation_id or "new",
                )

        if len(uploaded_files) > max_files:
            rejected.extend([f["name"] + " (too many files)" for f in uploaded_files[max_files:]])
            uploaded_files = uploaded_files[:max_files]

        if rejected:
            _skip_msg = "Some files were skipped:\n- " + "\n- ".join(rejected) + "\n\n"
            file_reply_parts.append(_skip_msg)
            await response_msg.stream_token(_skip_msg)

        if uploaded_files and not (conversation_id or "").strip():
            conversation_id = str(uuid.uuid4())
            cl.user_session.set("conversation_id", conversation_id)

        if uploaded_files:
            try:
                ingestion_success = await ingest_files_session(
                    conversation_id=conversation_id,
                    question_id=message.id,
                    auth_info=auth_info,
                    files=uploaded_files,
                )
            except Exception:
                logger.exception(
                    "File ingestion failed: conversation=%s question_id=%s",
                    conversation_id or "new",
                    message.id,
                )
                _fail_msg = (
                    "File ingestion failed. Please contact the application support team and share reference "
                    f"{message.id}.\n\n"
                )
                file_reply_parts.append(_fail_msg)
                await response_msg.stream_token(_fail_msg)
                ingestion_success = False

            session_docs = cl.user_session.get("uploaded_docs") or []
            session_docs.extend([f["name"] for f in uploaded_files])
            cl.user_session.set("uploaded_docs", session_docs)

            if ingestion_success:
                _ok_msg = f"{len(uploaded_files)} file(s) processed successfully.\n\n"
                file_reply_parts.append(_ok_msg)
                await response_msg.stream_token(_ok_msg)

        user_ask = (message.content or "").strip()
        if uploaded_files and not user_ask:
            final_text = "".join(file_reply_parts).strip() or "Files received."
            if SHOW_STATISTICS:
                final_text += f"\n\n*\u23f1 {time.time() - handler_start:.2f}s*"
            cl.user_session.set("conversation_id", conversation_id)
            span.set_attribute("question_id", message.id)
            span.set_attribute("conversation_id", conversation_id)
            span.set_attribute("user_id", auth_info.get("client_principal_id", "anonymous"))
            logger.info(
                "Skipping orchestrator (files only, empty ask): conversation=%s question_id=%s",
                conversation_id or "new",
                message.id,
            )
            response_msg.content = final_text
            await response_msg.update()
            logger.info(
                "Response delivered: conversation=%s question_id=%s chunks=0 characters=%s preview='%s'",
                conversation_id,
                message.id,
                len(final_text),
                _trim_for_log(final_text),
            )
            return

        # ----------------------------------------------
        

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

        response_start_time = time.time()
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
        is_first_chunk = True
        uuid_buffer = ""

        try:
            async for raw_chunk in generator:
                if not raw_chunk:
                    continue

                if "[ERROR en MAF Streaming]:" in raw_chunk or "[ERROR]:" in raw_chunk:
                    await cl.ErrorMessage(content=f"Error de Servicio: {raw_chunk.strip()}").send()
                    break

                if is_first_chunk:
                    uuid_buffer += raw_chunk
                    if len(uuid_buffer) >= 37:
                        is_first_chunk = False
                        chunk = uuid_buffer
                        uuid_buffer = ""
                    else:
                        continue
                else:
                    chunk = raw_chunk

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
                cleaned_chunk = replace_source_reference_links(
                    cleaned_chunk,
                    chunk_refs,
                    conversation_id=conversation_id,
                    principal_id=str(auth_info.get("principal_id") or ""),
                )
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
        if ENABLE_FEEDBACK and (message.content or "").strip():
            response_msg.actions = create_feedback_actions(
                message.id, conversation_id, message.content
            )
        final_text = replace_source_reference_links(
            full_text.replace(TERMINATE_TOKEN, ""),
            references,
            conversation_id=conversation_id,
            principal_id=str(auth_info.get("principal_id") or ""),
        )
        if SHOW_STATISTICS:
            elapsed = time.time() - response_start_time
            final_text += f"\n\n*\u23f1 {elapsed:.2f}s*"
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
