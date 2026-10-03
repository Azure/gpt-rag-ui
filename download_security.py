"""Compatibility exports; implementation lives in gpt_rag_ui.services.download_security."""

from gpt_rag_ui.services.download_security import (
    BlobDownloader as BlobDownloader,
    ConversationResolver as ConversationResolver,
    DownloadGrant as DownloadGrant,
    DownloadPrincipal as DownloadPrincipal,
    DownloadStream as DownloadStream,
    DownloadTokenManager as DownloadTokenManager,
    configure_download_tokens as configure_download_tokens,
    get_download_tokens as get_download_tokens,
    is_download_target_allowed as is_download_target_allowed,
    resolve_download_principal as resolve_download_principal,
)
from gpt_rag_ui.api.download_routes import register_secure_download_route as register_secure_download_route
