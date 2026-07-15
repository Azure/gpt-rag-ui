import asyncio
import logging
import os
import re
import secrets
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from typing import Protocol

import httpx
import jwt
from chainlit.auth import create_jwt
from chainlit.user import User
from fastapi import FastAPI, status
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from auth_common import canonical_principal_id, is_user_authorized
from connectors.appconfig import AppConfigClient
from embed_config import EmbedSettings
from entra_token import EntraTokenError


COPILOT_SESSION_COOKIE = "gpt_rag_copilot_session"
logger = logging.getLogger("gpt_rag_ui.embed_auth")
_SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")

SessionInvalidationCallback = Callable[[str], Awaitable[None]]


@dataclass(frozen=True)
class CopilotSession:
    session_id: str
    principal_id: str
    tenant_id: str
    object_id: str
    access_token: str = field(repr=False)
    chainlit_token: str = field(repr=False)
    expires_at: int
    display_name: str
    principal_name: str
    group_ids: tuple[str, ...] = ()

    def user_metadata(self) -> dict:
        return {
            "authorized": True,
            "auth_source": "copilot_session",
            "copilot_session_id": self.session_id,
            "tenant_id": self.tenant_id,
            "object_id": self.object_id,
            "principal_id": self.principal_id,
            # Downstream ACL and orchestrator contracts use a bare Entra oid.
            "client_principal_id": self.object_id,
            "client_principal_name": self.principal_name,
            "user_name": self.principal_id,
            "client_group_names": list(self.group_ids),
        }


class CopilotSessionStore:
    def __init__(
        self,
        *,
        max_sessions: int,
        ttl_seconds: int,
        on_invalidate: SessionInvalidationCallback | None = None,
    ):
        if max_sessions < 1 or ttl_seconds < 1:
            raise ValueError("Copilot session bounds must be positive.")
        self.max_sessions = max_sessions
        self.ttl_seconds = ttl_seconds
        self._sessions: OrderedDict[str, CopilotSession] = OrderedDict()
        self._expiry_tasks: dict[str, asyncio.Task[None]] = {}
        self._lock = asyncio.Lock()
        self._on_invalidate = on_invalidate

    def _cancel_expiry_locked(self, session_id: str) -> None:
        task = self._expiry_tasks.pop(session_id, None)
        if task and task is not asyncio.current_task():
            task.cancel()

    def _remove_locked(self, session_id: str) -> CopilotSession | None:
        session = self._sessions.pop(session_id, None)
        self._cancel_expiry_locked(session_id)
        return session

    def _prune_locked(self, now: int) -> list[str]:
        expired = [
            session_id
            for session_id, session in self._sessions.items()
            if session.expires_at <= now
        ]
        for session_id in expired:
            self._remove_locked(session_id)
        return expired

    async def _expire_at(self, session_id: str, expires_at: int) -> None:
        try:
            while True:
                delay = expires_at - time.time()
                if delay > 0:
                    await asyncio.sleep(delay)

                async with self._lock:
                    session = self._sessions.get(session_id)
                    if not session or session.expires_at != expires_at:
                        return
                    if session.expires_at > time.time():
                        continue
                    self._sessions.pop(session_id, None)
                    self._expiry_tasks.pop(session_id, None)
                await self._notify_invalidated([session_id])
                return
        except asyncio.CancelledError:
            return

    async def _notify_invalidated(self, session_ids: list[str]) -> None:
        if not self._on_invalidate:
            return
        for session_id in dict.fromkeys(session_ids):
            try:
                await self._on_invalidate(session_id)
            except Exception:
                logger.exception(
                    "Failed to disconnect invalidated Copilot session"
                )

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

        tenant_id = str(claims["tid"])
        object_id = str(claims["oid"])
        principal_id = canonical_principal_id(tenant_id, object_id)
        tenant_id, object_id = principal_id.split(":", 1)
        session_id = secrets.token_urlsafe(32)
        group_ids = tuple(
            str(group)
            for group in claims.get("groups", [])
            if isinstance(group, str)
        )
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
                "client_principal_id": object_id,
                "client_principal_name": principal_name,
                "user_name": principal_id,
                "client_group_names": list(group_ids),
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
            display_name=display_name,
            principal_name=principal_name,
            group_ids=group_ids,
        )

        invalidated: list[str] = []
        async with self._lock:
            invalidated.extend(self._prune_locked(now))
            if previous_session_id:
                self._remove_locked(previous_session_id)
                invalidated.append(previous_session_id)
            self._sessions[session_id] = session
            self._expiry_tasks[session_id] = asyncio.create_task(
                self._expire_at(session_id, expires_at),
                name=f"copilot-session-expiry-{session_id[:8]}",
            )
            while len(self._sessions) > self.max_sessions:
                evicted_id, _ = self._sessions.popitem(last=False)
                self._cancel_expiry_locked(evicted_id)
                invalidated.append(evicted_id)
        await self._notify_invalidated(invalidated)
        return session

    async def get(self, session_id: str | None) -> CopilotSession | None:
        if not is_valid_session_id(session_id):
            return None
        now = int(time.time())
        async with self._lock:
            invalidated = self._prune_locked(now)
            session = self._sessions.get(session_id)
            if session:
                self._sessions.move_to_end(session_id)
        await self._notify_invalidated(invalidated)
        return session

    async def delete(self, session_id: str | None) -> None:
        if not is_valid_session_id(session_id):
            return
        async with self._lock:
            self._remove_locked(session_id)
        # Always notify. The process may still have a live upgraded socket after
        # the bounded state entry was evicted or expired.
        await self._notify_invalidated([session_id])

    async def count(self) -> int:
        async with self._lock:
            invalidated = self._prune_locked(int(time.time()))
            count = len(self._sessions)
        await self._notify_invalidated(invalidated)
        return count


_session_store: CopilotSessionStore | None = None
_request_copilot_session: ContextVar[CopilotSession | None] = ContextVar(
    "request_copilot_session",
    default=None,
)


def configure_session_store(
    *,
    max_sessions: int,
    ttl_seconds: int,
    on_invalidate: SessionInvalidationCallback | None = None,
) -> CopilotSessionStore:
    global _session_store
    _session_store = CopilotSessionStore(
        max_sessions=max_sessions,
        ttl_seconds=ttl_seconds,
        on_invalidate=on_invalidate,
    )
    return _session_store


def get_session_store() -> CopilotSessionStore:
    if _session_store is None:
        raise RuntimeError("Copilot session state has not been configured.")
    return _session_store


def bind_request_copilot_session(
    session: CopilotSession,
) -> Token[CopilotSession | None]:
    return _request_copilot_session.set(session)


def reset_request_copilot_session(token: Token[CopilotSession | None]) -> None:
    _request_copilot_session.reset(token)


def get_request_copilot_session() -> CopilotSession | None:
    return _request_copilot_session.get()


def is_valid_session_id(value: str | None) -> bool:
    return bool(value and _SESSION_ID_PATTERN.fullmatch(value))


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
        raise RuntimeError(
            "CHAINLIT_AUTH_SECRET is required for authenticated sessions."
        )
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
    raw_cookie_headers = request.headers.getlist("Cookie")
    occurrences = 0
    session_id = None
    for raw_cookie in raw_cookie_headers:
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except (CookieError, TypeError, ValueError):
            return None
        if raw_cookie.strip() and not cookie:
            return None
        occurrences += sum(
            1
            for part in raw_cookie.split(";")
            if part.partition("=")[0].strip() == COPILOT_SESSION_COOKIE
        )
        if COPILOT_SESSION_COOKIE in cookie:
            if session_id is not None:
                return None
            session_id = cookie[COPILOT_SESSION_COOKIE].value
    if occurrences != 1:
        return None
    return session_id if is_valid_session_id(session_id) else None


class TokenValidator(Protocol):
    async def validate(self, token: str) -> dict:
        ...


def _auth_error_response(
    *,
    status_code: int,
    detail: str,
    settings: EmbedSettings,
    clear_cookie: bool = True,
) -> JSONResponse:
    headers = {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "Vary": "Origin",
    }
    response = JSONResponse(
        {"detail": detail},
        status_code=status_code,
        headers=headers,
    )
    if clear_cookie:
        clear_copilot_session_cookie(
            response,
            same_site=settings.cookie_samesite,
        )
    return response


def register_copilot_auth_routes(
    app: FastAPI,
    *,
    settings: EmbedSettings,
    sessions: CopilotSessionStore,
    validator: TokenValidator,
    config: AppConfigClient,
) -> None:
    @app.post("/copilot/auth/bootstrap")
    async def bootstrap_copilot(request: Request):
        previous_session_id = session_id_from_request(request)
        previous_session = await sessions.get(previous_session_id)

        def auth_error(
            *,
            status_code: int,
            detail: str,
            clear_cookie: bool | None = None,
        ) -> JSONResponse:
            return _auth_error_response(
                status_code=status_code,
                detail=detail,
                settings=settings,
                clear_cookie=(
                    previous_session is None
                    if clear_cookie is None
                    else clear_cookie
                ),
            )

        authorization_values = request.headers.getlist("Authorization")
        authorization = (
            authorization_values[0] if len(authorization_values) == 1 else ""
        )
        scheme, separator, access_token = authorization.partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or not access_token.strip()
        ):
            return auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )

        access_token = access_token.strip()
        try:
            claims = await validator.validate(access_token)
        except EntraTokenError:
            logger.warning("Copilot bootstrap rejected an invalid Entra token")
            return auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
            )
        except httpx.HTTPError:
            logger.exception("Copilot bootstrap could not reach Entra JWKS")
            return auth_error(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable",
            )

        try:
            tenant_id = str(claims["tid"])
            object_id = str(claims["oid"])
            principal_id = canonical_principal_id(tenant_id, object_id)
        except (KeyError, TypeError, ValueError):
            logger.warning("Copilot bootstrap rejected invalid identity claims")
            return auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
            )

        principal_name = str(
            claims.get("preferred_username")
            or claims.get("email")
            or claims.get("upn")
            or ""
        )
        if not is_user_authorized(
            config,
            principal_name,
            principal_id,
        ):
            logger.warning("Copilot bootstrap denied principal=%s", principal_id)
            if previous_session:
                await sessions.delete(previous_session.session_id)
            return auth_error(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied",
                clear_cookie=True,
            )

        try:
            session = await sessions.replace(
                previous_session_id=previous_session_id,
                access_token=access_token,
                claims=claims,
                display_name=str(
                    claims.get("name") or principal_name or principal_id
                ),
                principal_name=principal_name,
            )
        except (KeyError, TypeError, ValueError):
            logger.warning("Copilot bootstrap rejected invalid token claims")
            return auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
            )

        response = JSONResponse(
            {"success": True, "expiresAt": session.expires_at},
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Vary": "Origin",
            },
        )
        set_copilot_session_cookie(
            response,
            session,
            same_site=settings.cookie_samesite,
        )
        return response

    @app.post("/copilot/auth/logout")
    async def logout_copilot(request: Request):
        await sessions.delete(session_id_from_request(request))
        response = JSONResponse(
            {"success": True},
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Vary": "Origin",
            },
        )
        clear_copilot_session_cookie(
            response,
            same_site=settings.cookie_samesite,
        )
        return response

async def resolve_access_token(metadata: dict | None) -> str | None:
    metadata = metadata or {}
    if metadata.get("auth_source") != "copilot_session":
        token = str(metadata.get("access_token") or "").strip()
        return token or None

    try:
        store = get_session_store()
    except RuntimeError:
        return None
    session = await store.get(str(metadata.get("copilot_session_id") or ""))
    if not session or session.principal_id != metadata.get("principal_id"):
        return None
    return session.access_token


async def is_copilot_session_active(metadata: dict | None) -> bool:
    metadata = metadata or {}
    if metadata.get("auth_source") != "copilot_session":
        return True
    return bool(await resolve_access_token(metadata))
