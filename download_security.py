import time
from dataclasses import dataclass
from urllib.parse import quote

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


@dataclass(frozen=True)
class DownloadGrant:
    principal_id: str
    conversation_id: str
    container: str
    blob_name: str


class DownloadTokenManager:
    def __init__(self, *, secret: str, public_url: str, max_age_seconds: int = 3600):
        if not secret:
            raise ValueError("A signing secret is required for download grants.")
        self.serializer = URLSafeTimedSerializer(secret, salt="gpt-rag-download-v1")
        self.public_url = public_url.rstrip("/")
        self.max_age_seconds = max_age_seconds

    def issue(
        self,
        *,
        principal_id: str,
        conversation_id: str,
        container: str,
        blob_name: str,
    ) -> str:
        if (
            not principal_id
            or not conversation_id
            or not container
            or not blob_name
            or any(part in {"", ".", ".."} for part in blob_name.replace("\\", "/").split("/"))
        ):
            raise ValueError("Invalid download grant.")
        token = self.serializer.dumps(
            {
                "p": principal_id,
                "c": conversation_id,
                "n": container,
                "b": blob_name,
                "iat": int(time.time()),
            }
        )
        return f"{self.public_url}/api/download/{quote(token, safe='')}"

    def verify(self, token: str) -> DownloadGrant | None:
        try:
            payload = self.serializer.loads(token, max_age=self.max_age_seconds)
        except (BadSignature, SignatureExpired):
            return None
        required = ("p", "c", "n", "b")
        if not isinstance(payload, dict) or any(
            not isinstance(payload.get(key), str) or not payload[key]
            for key in required
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


_manager: DownloadTokenManager | None = None


def configure_download_tokens(*, secret: str, public_url: str) -> DownloadTokenManager:
    global _manager
    _manager = DownloadTokenManager(secret=secret, public_url=public_url)
    return _manager


def get_download_tokens() -> DownloadTokenManager:
    if _manager is None:
        raise RuntimeError("Download token manager has not been configured.")
    return _manager
