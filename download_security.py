import asyncio
import hashlib
import logging
import mimetypes
import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from io import BytesIO
from urllib.parse import quote, urlsplit

from azure.core.exceptions import ResourceNotFoundError
from chainlit.auth import authenticate_user, get_token_from_cookies
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from itsdangerous import BadData, URLSafeTimedSerializer

from conversation_security import (
    get_owned_conversation,
    principal_id_from_metadata,
)
from auth_session import current_user_metadata
from embed_auth import current_copilot_session


_CONTAINER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$")
logger = logging.getLogger("gpt_rag_ui.download_security")


@dataclass(frozen=True)
class DownloadGrant:
    principal_id: str
    conversation_id: str
    container: str
    blob_name: str


@dataclass(frozen=True)
class DownloadPrincipal:
    principal_id: str
    metadata: dict


class DownloadTokenManager:
    def __init__(
        self,
        *,
        secret: str,
        public_url: str,
        max_age_seconds: int = 3600,
    ):
        if not secret:
            raise ValueError("A signing secret is required for download grants.")
        parsed_url = urlsplit(public_url)
        try:
            port = parsed_url.port
        except ValueError as exc:
            raise ValueError(
                "The download public URL must be an absolute origin."
            ) from exc
        if (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.hostname
            or parsed_url.username
            or parsed_url.password
            or parsed_url.path not in {"", "/"}
            or parsed_url.query
            or parsed_url.fragment
            or (port is not None and port <= 0)
        ):
            raise ValueError("The download public URL must be an absolute origin.")
        if max_age_seconds < 1:
            raise ValueError("Download grants require a positive lifetime.")

        self.serializer = URLSafeTimedSerializer(
            secret,
            salt="gpt-rag-download-v1",
            signer_kwargs={"digest_method": hashlib.sha256},
        )
        self.public_url = public_url.rstrip("/")
        self.max_age_seconds = max_age_seconds

    @staticmethod
    def _valid_target(
        *,
        principal_id: str,
        conversation_id: str,
        container: str,
        blob_name: str,
    ) -> bool:
        normalized_blob = blob_name.replace("\\", "/")
        return bool(
            principal_id
            and conversation_id
            and _CONTAINER_PATTERN.fullmatch(container)
            and normalized_blob
            and len(normalized_blob) <= 1024
            and not normalized_blob.startswith("/")
            and not any(ord(char) < 32 for char in normalized_blob)
            and not any(
                part in {"", ".", ".."} for part in normalized_blob.split("/")
            )
        )

    def issue(
        self,
        *,
        principal_id: str,
        conversation_id: str,
        container: str,
        blob_name: str,
    ) -> str:
        if not self._valid_target(
            principal_id=principal_id,
            conversation_id=conversation_id,
            container=container,
            blob_name=blob_name,
        ):
            raise ValueError("Invalid download grant.")
        token = self.serializer.dumps(
            {
                "v": 1,
                "p": principal_id,
                "c": conversation_id,
                "n": container,
                "b": blob_name.replace("\\", "/"),
            }
        )
        return f"{self.public_url}/api/download/{quote(token, safe='')}"

    def verify(self, token: str) -> DownloadGrant | None:
        if not token or len(token) > 8192:
            return None
        try:
            payload = self.serializer.loads(
                token,
                max_age=self.max_age_seconds,
            )
        except BadData:
            return None
        if not isinstance(payload, dict) or payload.get("v") != 1:
            return None

        required = ("p", "c", "n", "b")
        if any(
            not isinstance(payload.get(key), str) or not payload[key]
            for key in required
        ):
            return None
        if not self._valid_target(
            principal_id=payload["p"],
            conversation_id=payload["c"],
            container=payload["n"],
            blob_name=payload["b"],
        ):
            return None
        return DownloadGrant(
            principal_id=payload["p"],
            conversation_id=payload["c"],
            container=payload["n"],
            blob_name=payload["b"],
        )


def is_download_target_allowed(
    *,
    conversation_id: str,
    container: str,
    blob_name: str,
    conversation_container: str,
    shared_containers: set[str],
) -> bool:
    if container == conversation_container:
        normalized = blob_name.replace("\\", "/").lstrip("/")
        return normalized.startswith(f"conversations/{conversation_id}/")
    return container in shared_containers


async def resolve_download_principal(
    request: Request,
) -> DownloadPrincipal | None:
    opaque_session = current_copilot_session()
    if opaque_session:
        return DownloadPrincipal(
            principal_id=opaque_session.principal_id,
            metadata=opaque_session.user_metadata(),
        )

    chainlit_token = get_token_from_cookies(request.cookies)
    if not chainlit_token:
        return None
    try:
        user = await authenticate_user(chainlit_token)
    except HTTPException:
        return None
    if not user or not (user.metadata or {}).get("authorized", True):
        return None

    persisted_metadata = dict(user.metadata or {})
    principal_id = principal_id_from_metadata(persisted_metadata)
    if not principal_id or principal_id != user.identifier:
        return None

    runtime_metadata = current_user_metadata() or {}
    if runtime_metadata:
        runtime_principal = principal_id_from_metadata(runtime_metadata)
        if runtime_principal != principal_id:
            return None
        metadata = runtime_metadata
    else:
        metadata = persisted_metadata
    return DownloadPrincipal(
        principal_id=principal_id,
        metadata=metadata,
    )


ConversationResolver = Callable[[str, dict | None], Awaitable[dict | None]]
BlobDownloader = Callable[[str], bytes]


def register_secure_download_route(
    app: FastAPI,
    *,
    manager: DownloadTokenManager,
    download_blob: BlobDownloader,
    allowed_containers: set[str],
    conversation_container: str,
    shared_containers: set[str],
    conversation_resolver: ConversationResolver = get_owned_conversation,
) -> None:
    @app.get("/api/download/{grant_token}")
    async def download_blob_file(grant_token: str, request: Request):
        principal = await resolve_download_principal(request)
        if not principal:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"Cache-Control": "no-store"},
            )

        grant = manager.verify(grant_token)
        if not grant or grant.principal_id != principal.principal_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Not found",
            )
        if not await conversation_resolver(
            grant.conversation_id,
            principal.metadata,
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Not found",
            )
        if grant.container not in allowed_containers:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Not found",
            )
        if not is_download_target_allowed(
            conversation_id=grant.conversation_id,
            container=grant.container,
            blob_name=grant.blob_name,
            conversation_container=conversation_container,
            shared_containers=shared_containers,
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Not found",
            )

        try:
            file_bytes = await asyncio.to_thread(
                download_blob,
                f"{grant.container}/{grant.blob_name}",
            )
        except ResourceNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Not found",
            ) from exc
        except Exception as exc:
            logger.exception(
                "Authorized download failed: conversation=%s container=%s",
                grant.conversation_id,
                grant.container,
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Download failed",
            ) from exc
        if not file_bytes:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Not found",
            )

        file_name = os.path.basename(grant.blob_name)
        content_type = (
            mimetypes.guess_type(file_name)[0]
            or "application/octet-stream"
        )
        return StreamingResponse(
            BytesIO(file_bytes),
            media_type=content_type,
            headers={
                "Content-Disposition": (
                    "attachment; filename*=UTF-8''"
                    f"{quote(file_name, safe='')}"
                ),
                "Cache-Control": "private, no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )


_manager: DownloadTokenManager | None = None


def configure_download_tokens(
    *,
    secret: str,
    public_url: str,
) -> DownloadTokenManager:
    global _manager
    _manager = DownloadTokenManager(secret=secret, public_url=public_url)
    return _manager


def get_download_tokens() -> DownloadTokenManager:
    if _manager is None:
        raise RuntimeError("Download token manager has not been configured.")
    return _manager
