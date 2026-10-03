"""Compatibility exports; implementation lives in gpt_rag_ui.services.chat."""

from gpt_rag_ui.services.chat import (
    ALLOW_ANONYMOUS as ALLOW_ANONYMOUS,
    CHAT_BACKEND as CHAT_BACKEND,
    COPILOT_ENABLED as COPILOT_ENABLED,
    ENABLE_FEEDBACK as ENABLE_FEEDBACK,
    ENABLE_AUTHENTICATION as ENABLE_AUTHENTICATION,
    HOSTED_CONTINUITY_ENABLED as HOSTED_CONTINUITY_ENABLED,
    OAUTH_CONFIGURED as OAUTH_CONFIGURED,
    PANEL_SETTINGS as PANEL_SETTINGS,
    SHOW_STATISTICS as SHOW_STATISTICS,
    check_authorization as check_authorization,
    extract_conversation_id_from_chunk as extract_conversation_id_from_chunk,
    get_auth_info as get_auth_info,
    handle_message as handle_message,
    on_chat_resume as on_chat_resume,
    on_chat_start as on_chat_start,
)
from gpt_rag_ui.services.citations import (
    CONVERSATION_DOCUMENTS_CONTAINER as CONVERSATION_DOCUMENTS_CONTAINER,
    DOCUMENTS_CONTAINER as DOCUMENTS_CONTAINER,
    IMAGES_CONTAINER as IMAGES_CONTAINER,
    IMAGE_EXTENSIONS as IMAGE_EXTENSIONS,
    SHARED_DOWNLOAD_CONTAINERS as SHARED_DOWNLOAD_CONTAINERS,
    STORAGE_ACCOUNT_NAME as STORAGE_ACCOUNT_NAME,
    format_hosted_citation_sources as format_hosted_citation_sources,
    generate_blob_sas_url as generate_blob_sas_url,
    replace_source_reference_links as replace_source_reference_links,
    resolve_reference_href as resolve_reference_href,
)
from gpt_rag_ui.api.callbacks import register_callbacks

register_callbacks()
