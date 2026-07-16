"""Request-local access to the authenticated Chainlit session.

The data layer and signed Chainlit token contain only a safe profile plus an
opaque OAuth session identifier. OAuth credentials remain in bounded,
process-local server memory.
"""

import asyncio
import secrets
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from collections.abc import AsyncIterator

from chainlit.auth import decode_jwt
from chainlit.user import PersistedUser, User

from auth_common import canonical_principal_id


_current_chainlit_user: ContextVar[User | PersistedUser | None] = ContextVar(
    "current_chainlit_user",
    default=None,
)
OAUTH_SESSION_ID_KEY = "oauth_session_id"
OAUTH_SESSION_SOURCE = "oauth_session"
_MAX_OAUTH_CREDENTIALS = 1000


@dataclass(frozen=True)
class OAuthCredential:
    session_id: str
    principal_id: str
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_at: int


class OAuthCredentialStore:
    """Bounded process-local storage for standalone OAuth credentials."""

    def __init__(self, max_credentials: int = _MAX_OAUTH_CREDENTIALS):
        self.max_credentials = max_credentials
        self._credentials: OrderedDict[str, OAuthCredential] = OrderedDict()
        self._refresh_locks: dict[str, asyncio.Lock] = {}
        self._lock = asyncio.Lock()

    def _remove_locked(self, session_id: str) -> None:
        self._credentials.pop(session_id, None)
        self._refresh_locks.pop(session_id, None)

    def _prune_locked(self, now: int) -> None:
        for session_id, credential in list(self._credentials.items()):
            if credential.expires_at <= now:
                self._remove_locked(session_id)

    async def replace(
        self,
        *,
        previous_session_id: str | None,
        principal_id: str,
        access_token: str,
        refresh_token: str,
        ttl_seconds: int,
    ) -> OAuthCredential:
        now = int(time.time())
        session_id = secrets.token_urlsafe(32)
        credential = OAuthCredential(
            session_id=session_id,
            principal_id=principal_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=now + max(1, int(ttl_seconds)),
        )
        async with self._lock:
            self._prune_locked(now)
            if previous_session_id:
                self._remove_locked(previous_session_id)
            self._credentials[session_id] = credential
            self._refresh_locks[session_id] = asyncio.Lock()
            while len(self._credentials) > self.max_credentials:
                self._remove_locked(next(iter(self._credentials)))
        return credential

    async def get(
        self,
        session_id: str | None,
        *,
        principal_id: str,
    ) -> OAuthCredential | None:
        if not session_id:
            return None
        async with self._lock:
            self._prune_locked(int(time.time()))
            credential = self._credentials.get(session_id)
            if not credential or credential.principal_id != principal_id:
                return None
            self._credentials.move_to_end(session_id)
            return credential

    async def update(
        self,
        session_id: str,
        *,
        principal_id: str,
        access_token: str,
        refresh_token: str,
    ) -> bool:
        async with self._lock:
            self._prune_locked(int(time.time()))
            credential = self._credentials.get(session_id)
            if not credential or credential.principal_id != principal_id:
                return False
            self._credentials[session_id] = OAuthCredential(
                session_id=session_id,
                principal_id=principal_id,
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at=credential.expires_at,
            )
            self._credentials.move_to_end(session_id)
            return True

    async def delete(self, session_id: str | None) -> None:
        if not session_id:
            return
        async with self._lock:
            self._remove_locked(session_id)

    @asynccontextmanager
    async def refresh_lock(self, session_id: str) -> AsyncIterator[None]:
        async with self._lock:
            lock = self._refresh_locks.get(session_id)
        if lock is None:
            yield
            return
        async with lock:
            yield

    async def count(self) -> int:
        async with self._lock:
            self._prune_locked(int(time.time()))
            return len(self._credentials)

    def clear_for_testing(self) -> None:
        self._credentials.clear()
        self._refresh_locks.clear()


_oauth_credentials = OAuthCredentialStore()


def get_oauth_credential_store() -> OAuthCredentialStore:
    return _oauth_credentials


def oauth_session_id_from_metadata(metadata: dict | None) -> str:
    metadata = metadata or {}
    if metadata.get("auth_source") != OAUTH_SESSION_SOURCE:
        return ""
    return str(metadata.get(OAUTH_SESSION_ID_KEY) or "").strip()


def _principal_id_from_metadata(metadata: dict | None) -> str:
    metadata = metadata or {}
    try:
        return canonical_principal_id(
            str(metadata.get("tenant_id") or ""),
            str(metadata.get("object_id") or ""),
        )
    except ValueError:
        return ""


async def current_oauth_credential(
    metadata: dict | None = None,
) -> OAuthCredential | None:
    runtime_metadata = current_user_metadata() or {}
    candidate_metadata = runtime_metadata or (metadata or {})
    session_id = oauth_session_id_from_metadata(candidate_metadata)
    principal_id = _principal_id_from_metadata(candidate_metadata)
    if not session_id or not principal_id:
        return None

    declared_principal = _principal_id_from_metadata(metadata)
    if declared_principal and declared_principal != principal_id:
        return None
    return await _oauth_credentials.get(
        session_id,
        principal_id=principal_id,
    )


async def delete_current_oauth_credential() -> None:
    metadata = current_user_metadata() or {}
    await _oauth_credentials.delete(oauth_session_id_from_metadata(metadata))


def _cookie_value(scope: dict, name: str) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() != b"cookie":
            continue
        cookie = SimpleCookie()
        try:
            cookie.load(value.decode("latin-1"))
        except Exception:
            return None
        morsel = cookie.get(name)
        return morsel.value if morsel else None
    return None


def current_chainlit_user() -> User | PersistedUser | None:
    """Return the authenticated user for only the current request/session."""

    request_user = _current_chainlit_user.get()
    if request_user:
        return request_user

    try:
        from chainlit.context import context

        session = context.session
        runtime_user = session.user
        runtime_metadata = getattr(runtime_user, "metadata", None) or {}
        if runtime_user and runtime_metadata.get("access_token"):
            return runtime_user
        if session.token:
            return decode_jwt(session.token)
        return runtime_user
    except Exception:
        return None


def current_user_metadata() -> dict | None:
    user = current_chainlit_user()
    metadata = getattr(user, "metadata", None) if user else None
    return dict(metadata) if metadata else None


class ChainlitAuthContextMiddleware:
    """Bind signed Chainlit JWT metadata to the current ASGI request only."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        user = None
        token = _cookie_value(scope, "access_token")
        if token:
            try:
                user = decode_jwt(token)
            except Exception:
                user = None

        context_token = _current_chainlit_user.set(user)
        try:
            await self.app(scope, receive, send)
        finally:
            _current_chainlit_user.reset(context_token)
