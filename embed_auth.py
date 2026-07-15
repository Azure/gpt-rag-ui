import asyncio
import os
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field

import jwt
from chainlit.auth import create_jwt
from chainlit.user import User
from starlette.requests import Request
from starlette.responses import Response

from auth_common import canonical_principal_id


COPILOT_SESSION_COOKIE = "gpt_rag_copilot_session"


@dataclass(frozen=True)
class CopilotSession:
    session_id: str
    principal_id: str
    tenant_id: str
    object_id: str
    access_token: str = field(repr=False)
    chainlit_token: str = field(repr=False)
    expires_at: int


class CopilotSessionStore:
    def __init__(self, *, max_sessions: int, ttl_seconds: int):
        self.max_sessions = max_sessions
        self.ttl_seconds = ttl_seconds
        self._sessions: OrderedDict[str, CopilotSession] = OrderedDict()
        self._lock = asyncio.Lock()

    def _prune_locked(self, now: int) -> None:
        expired = [
            session_id
            for session_id, session in self._sessions.items()
            if session.expires_at <= now
        ]
        for session_id in expired:
            self._sessions.pop(session_id, None)

    async def replace(
        self,
        *,
        previous_session_id: str | None,
        access_token: str,
        claims: dict,
        display_name: str,
        principal_name: str,
    ) -> CopilotSession:
        now = int(time.time())
        token_expires_at = int(claims["exp"])
        expires_at = min(token_expires_at, now + self.ttl_seconds)
        if expires_at <= now:
            raise ValueError("The Entra access token has expired.")

        tenant_id = str(claims["tid"]).lower()
        object_id = str(claims["oid"]).lower()
        principal_id = canonical_principal_id(tenant_id, object_id)
        session_id = secrets.token_urlsafe(32)
        user = User(
            identifier=principal_id,
            display_name=display_name,
            metadata={
                "authorized": True,
                "auth_source": "copilot_session",
                "copilot_session_id": session_id,
                "tenant_id": tenant_id,
                "object_id": object_id,
                "principal_id": principal_id,
                # Preserve the downstream orchestrator/ingestion oid contract.
                # Chainlit identity and thread ownership use principal_id (tid:oid).
                "client_principal_id": object_id,
                "client_principal_name": principal_name,
                "user_name": principal_id,
                "client_group_names": [
                    str(group)
                    for group in claims.get("groups", [])
                    if isinstance(group, str)
                ],
            },
        )
        chainlit_token = create_embed_session_jwt(user, expires_at)
        session = CopilotSession(
            session_id=session_id,
            principal_id=principal_id,
            tenant_id=tenant_id,
            object_id=object_id,
            access_token=access_token,
            chainlit_token=chainlit_token,
            expires_at=expires_at,
        )

        async with self._lock:
            self._prune_locked(now)
            if previous_session_id:
                self._sessions.pop(previous_session_id, None)
            self._sessions[session_id] = session
            while len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)
        return session

    async def get(self, session_id: str | None) -> CopilotSession | None:
        if not session_id:
            return None
        now = int(time.time())
        async with self._lock:
            self._prune_locked(now)
            session = self._sessions.get(session_id)
            if session:
                self._sessions.move_to_end(session_id)
            return session

    async def delete(self, session_id: str | None) -> None:
        if not session_id:
            return
        async with self._lock:
            self._sessions.pop(session_id, None)

    async def count(self) -> int:
        async with self._lock:
            self._prune_locked(int(time.time()))
            return len(self._sessions)


_session_store: CopilotSessionStore | None = None


def configure_session_store(*, max_sessions: int, ttl_seconds: int) -> CopilotSessionStore:
    global _session_store
    _session_store = CopilotSessionStore(
        max_sessions=max_sessions,
        ttl_seconds=ttl_seconds,
    )
    return _session_store


def get_session_store() -> CopilotSessionStore:
    if _session_store is None:
        raise RuntimeError("Copilot session state has not been configured.")
    return _session_store


def create_embed_session_jwt(user: User, expires_at: int) -> str:
    session_token = create_jwt(user)
    payload = jwt.decode(
        session_token,
        options={"verify_signature": False},
        algorithms=["HS256"],
    )
    payload["exp"] = min(int(payload["exp"]), int(expires_at))
    secret = os.environ.get("CHAINLIT_AUTH_SECRET")
    if not secret:
        raise RuntimeError("CHAINLIT_AUTH_SECRET is required for authenticated sessions.")
    return jwt.encode(payload, secret, algorithm="HS256")


def set_copilot_session_cookie(
    response: Response,
    session: CopilotSession,
    *,
    same_site: str,
) -> None:
    response.set_cookie(
        key=COPILOT_SESSION_COOKIE,
        value=session.session_id,
        max_age=max(0, session.expires_at - int(time.time())),
        path="/",
        secure=True,
        httponly=True,
        samesite=same_site,
    )


def clear_copilot_session_cookie(response: Response, *, same_site: str) -> None:
    response.delete_cookie(
        key=COPILOT_SESSION_COOKIE,
        path="/",
        secure=True,
        httponly=True,
        samesite=same_site,
    )


def session_id_from_request(request: Request) -> str | None:
    return request.cookies.get(COPILOT_SESSION_COOKIE)


async def resolve_access_token(metadata: dict | None) -> str | None:
    metadata = metadata or {}
    if metadata.get("auth_source") != "copilot_session":
        token = str(metadata.get("access_token") or "").strip()
        return token or None

    session = await get_session_store().get(
        str(metadata.get("copilot_session_id") or "")
    )
    if not session or session.principal_id != metadata.get("principal_id"):
        return None
    return session.access_token
