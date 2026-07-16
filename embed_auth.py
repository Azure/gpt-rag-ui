import asyncio
import logging
import os
import re
import secrets
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
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

from auth_common import (
    canonical_principal_id,
    is_user_authorized,
    safe_profile_metadata,
)
from auth_session import current_oauth_credential
from connectors.appconfig import AppConfigClient
from embed_config import EmbedSettings
from entra_token import EntraTokenError


logger = logging.getLogger("gpt_rag_ui.embed_auth")

COPILOT_SESSION_COOKIE = "gpt_rag_copilot_session"
COPILOT_SCOPE_SESSION_KEY = "gpt_rag.copilot_session_id"
DEFAULT_MAX_CONNECTIONS_PER_SESSION = 4
_SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


@dataclass(frozen=True)
class CopilotSession:
    session_id: str
    principal_id: str
    tenant_id: str
    object_id: str
    access_token: str = field(repr=False)
    chainlit_token: str = field(repr=False)
    expires_at: int
    group_ids: tuple[str, ...] = ()

    def user_metadata(self) -> dict:
        """Return only canonical profile data for the current request."""

        return safe_profile_metadata(
            {
                "authorized": True,
                "tenant_id": self.tenant_id,
                "object_id": self.object_id,
                "principal_id": self.principal_id,
                "client_group_names": list(self.group_ids),
            }
        )


@dataclass(frozen=True)
class CopilotSessionInvalidation:
    session: CopilotSession
    reason: str
    socket_ids: tuple[str, ...] = ()
    chainlit_session_ids: tuple[str, ...] = ()
    terminate_chainlit_sessions: bool = True


InvalidationHandler = Callable[[CopilotSessionInvalidation], Awaitable[None]]

_current_copilot_session: ContextVar[CopilotSession | None] = ContextVar(
    "current_copilot_session",
    default=None,
)


@contextmanager
def bind_copilot_session(session: CopilotSession) -> Iterator[None]:
    token = _current_copilot_session.set(session)
    try:
        yield
    finally:
        _current_copilot_session.reset(token)


def current_copilot_session() -> CopilotSession | None:
    return _current_copilot_session.get()


class CopilotSessionStore:
    def __init__(
        self,
        *,
        max_sessions: int,
        ttl_seconds: int,
        max_connections_per_session: int = DEFAULT_MAX_CONNECTIONS_PER_SESSION,
    ):
        self.max_sessions = max_sessions
        self.ttl_seconds = ttl_seconds
        self.max_connections_per_session = max_connections_per_session
        self._sessions: OrderedDict[str, CopilotSession] = OrderedDict()
        self._principal_sessions: dict[str, str] = {}
        self._session_sockets: dict[str, set[str]] = {}
        self._socket_sessions: dict[str, str] = {}
        self._socket_chainlit_sessions: dict[str, str] = {}
        self._session_chainlit_sessions: dict[str, OrderedDict[str, None]] = {}
        self._chainlit_sessions: dict[str, str] = {}
        self._expiry_handles: dict[str, asyncio.TimerHandle] = {}
        self._on_invalidate: InvalidationHandler | None = None
        self._lock = asyncio.Lock()
        self._connection_lock = asyncio.Lock()
        self._invalidating_sockets: set[str] = set()

    def set_invalidation_handler(
        self,
        handler: InvalidationHandler | None,
    ) -> None:
        self._on_invalidate = handler

    def _schedule_expiry_locked(self, session: CopilotSession) -> None:
        delay = max(0, session.expires_at - int(time.time()))
        loop = asyncio.get_running_loop()
        self._expiry_handles[session.session_id] = loop.call_later(
            delay,
            lambda: asyncio.create_task(
                self._expire_if_due(session.session_id)
            ),
        )

    def _remove_locked(
        self,
        session_id: str,
        *,
        reason: str,
    ) -> CopilotSessionInvalidation | None:
        session = self._sessions.pop(session_id, None)
        if not session:
            return None

        handle = self._expiry_handles.pop(session_id, None)
        if handle:
            handle.cancel()
        if self._principal_sessions.get(session.principal_id) == session_id:
            self._principal_sessions.pop(session.principal_id, None)

        socket_ids = tuple(
            sorted(self._session_sockets.pop(session_id, set()))
        )
        self._invalidating_sockets.update(socket_ids)
        chainlit_ids = list(
            self._session_chainlit_sessions.pop(
                session_id,
                OrderedDict(),
            )
        )
        for socket_id in socket_ids:
            chainlit_id = self._socket_chainlit_sessions.get(socket_id)
            if chainlit_id and chainlit_id not in chainlit_ids:
                chainlit_ids.append(chainlit_id)
        for chainlit_id in chainlit_ids:
            if self._chainlit_sessions.get(chainlit_id) == session_id:
                self._chainlit_sessions.pop(chainlit_id, None)

        return CopilotSessionInvalidation(
            session=session,
            reason=reason,
            socket_ids=socket_ids,
            chainlit_session_ids=tuple(chainlit_ids),
        )

    def _prune_locked(self, now: int) -> list[CopilotSessionInvalidation]:
        expired_ids = [
            session_id
            for session_id, session in self._sessions.items()
            if session.expires_at <= now
        ]
        return [
            invalidation
            for session_id in expired_ids
            if (
                invalidation := self._remove_locked(
                    session_id,
                    reason="expired",
                )
            )
        ]

    async def _cleanup_socket_associations(
        self,
        invalidation: CopilotSessionInvalidation,
    ) -> None:
        async with self._lock:
            for socket_id in invalidation.socket_ids:
                self._invalidating_sockets.discard(socket_id)
                if (
                    self._socket_sessions.get(socket_id)
                    == invalidation.session.session_id
                ):
                    self._socket_sessions.pop(socket_id, None)
                    self._socket_chainlit_sessions.pop(socket_id, None)
                    session_sockets = self._session_sockets.get(
                        invalidation.session.session_id
                    )
                    if session_sockets is not None:
                        session_sockets.discard(socket_id)
                        if not session_sockets:
                            self._session_sockets.pop(
                                invalidation.session.session_id,
                                None,
                            )

    async def _notify_invalidations(
        self,
        invalidations: list[CopilotSessionInvalidation],
        *,
        cleanup_on_failure: bool = True,
    ) -> bool:
        all_succeeded = True
        for invalidation in invalidations:
            succeeded = True
            try:
                if self._on_invalidate:
                    await self._on_invalidate(invalidation)
                elif invalidation.socket_ids:
                    succeeded = False
            except Exception:
                succeeded = False
                logger.exception(
                    "Failed to invalidate Copilot session resources: reason=%s",
                    invalidation.reason,
                )
            if succeeded or cleanup_on_failure:
                await self._cleanup_socket_associations(invalidation)
            all_succeeded = all_succeeded and succeeded
        return all_succeeded

    async def _expire_if_due(self, session_id: str) -> None:
        invalidations: list[CopilotSessionInvalidation] = []
        async with self._lock:
            session = self._sessions.get(session_id)
            if session and session.expires_at <= int(time.time()):
                invalidation = self._remove_locked(
                    session_id,
                    reason="expired",
                )
                if invalidation:
                    invalidations.append(invalidation)
        await self._notify_invalidations(invalidations)

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
        profile = safe_profile_metadata(
            {
                "authorized": True,
                "tenant_id": tenant_id,
                "object_id": object_id,
                "principal_id": principal_id,
                "client_principal_name": principal_name,
                "client_group_names": claims.get("groups", []),
            }
        )
        group_ids = tuple(profile["client_group_names"])
        user = User(
            identifier=principal_id,
            display_name=display_name,
            metadata=profile,
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
            group_ids=group_ids,
        )

        invalidations: list[CopilotSessionInvalidation] = []
        async with self._lock:
            invalidations.extend(self._prune_locked(now))

            if previous_session_id:
                previous = self._remove_locked(
                    previous_session_id,
                    reason="replaced",
                )
                if previous:
                    invalidations.append(previous)

            principal_session_id = self._principal_sessions.get(principal_id)
            if principal_session_id:
                previous = self._remove_locked(
                    principal_session_id,
                    reason="principal_replaced",
                )
                if previous:
                    invalidations.append(previous)

            self._sessions[session_id] = session
            self._principal_sessions[principal_id] = session_id
            self._schedule_expiry_locked(session)

            while len(self._sessions) > self.max_sessions:
                oldest_session_id = next(iter(self._sessions))
                evicted = self._remove_locked(
                    oldest_session_id,
                    reason="capacity",
                )
                if evicted:
                    invalidations.append(evicted)

        await self._notify_invalidations(invalidations)
        return session

    async def get(self, session_id: str | None) -> CopilotSession | None:
        if not session_id:
            return None
        invalidations: list[CopilotSessionInvalidation] = []
        async with self._lock:
            invalidations.extend(self._prune_locked(int(time.time())))
            session = self._sessions.get(session_id)
            if session:
                self._sessions.move_to_end(session_id)
        await self._notify_invalidations(invalidations)
        return session

    async def delete(
        self,
        session_id: str | None,
        *,
        reason: str = "logout",
    ) -> None:
        if not session_id:
            return
        invalidations: list[CopilotSessionInvalidation] = []
        async with self._lock:
            invalidation = self._remove_locked(session_id, reason=reason)
            if invalidation:
                invalidations.append(invalidation)
        await self._notify_invalidations(invalidations)

    async def bind_connection(
        self,
        *,
        session_id: str,
        socket_id: str,
        chainlit_session_id: str,
    ) -> bool:
        async with self._connection_lock:
            invalidations: list[CopilotSessionInvalidation] = []
            replacement: CopilotSessionInvalidation | None = None
            candidate_session: CopilotSession | None = None
            idempotent = False

            async with self._lock:
                invalidations.extend(self._prune_locked(int(time.time())))
                candidate_session = self._sessions.get(session_id)
                if candidate_session:
                    socket_owner = self._socket_sessions.get(socket_id)
                    socket_chainlit_id = self._socket_chainlit_sessions.get(
                        socket_id
                    )
                    idempotent = (
                        socket_owner == session_id
                        and socket_chainlit_id == chainlit_session_id
                    )
                    socket_already_bound = bool(
                        socket_owner or socket_chainlit_id
                    )
                    chainlit_owner = self._chainlit_sessions.get(
                        chainlit_session_id
                    )
                    session_sockets = self._session_sockets.get(
                        session_id,
                        set(),
                    )
                    replacement_socket_ids = tuple(
                        sorted(
                            existing_socket_id
                            for existing_socket_id in session_sockets
                            if existing_socket_id != socket_id
                            and self._socket_chainlit_sessions.get(
                                existing_socket_id
                            )
                            == chainlit_session_id
                        )
                    )
                    has_physical_capacity = (
                        bool(replacement_socket_ids)
                        or len(session_sockets)
                        < self.max_connections_per_session
                    )
                    can_bind = (
                        not socket_already_bound
                        and chainlit_owner in {None, session_id}
                        and has_physical_capacity
                        and (
                            not replacement_socket_ids
                            or self._on_invalidate is not None
                        )
                    )
                    if can_bind and replacement_socket_ids:
                        self._invalidating_sockets.update(
                            replacement_socket_ids
                        )
                        replacement = CopilotSessionInvalidation(
                            session=candidate_session,
                            reason="socket_replaced",
                            socket_ids=replacement_socket_ids,
                            terminate_chainlit_sessions=False,
                        )
                    elif not can_bind and not idempotent:
                        candidate_session = None

            await self._notify_invalidations(invalidations)
            if idempotent:
                return True
            if not candidate_session:
                return False
            if replacement:
                disconnected = await self._notify_invalidations(
                    [replacement],
                    cleanup_on_failure=False,
                )
                if not disconnected:
                    return False

            async with self._lock:
                if self._sessions.get(session_id) is not candidate_session:
                    return False
                if (
                    self._socket_sessions.get(socket_id) is not None
                    or self._socket_chainlit_sessions.get(socket_id) is not None
                ):
                    return False

                chainlit_owner = self._chainlit_sessions.get(
                    chainlit_session_id
                )
                if chainlit_owner not in {None, session_id}:
                    return False
                chainlit_ids = self._session_chainlit_sessions.setdefault(
                    session_id,
                    OrderedDict(),
                )
                session_sockets = self._session_sockets.setdefault(
                    session_id,
                    set(),
                )
                if len(session_sockets) >= self.max_connections_per_session:
                    return False

                chainlit_ids[chainlit_session_id] = None
                chainlit_ids.move_to_end(chainlit_session_id)
                self._chainlit_sessions[chainlit_session_id] = session_id
                session_sockets.add(socket_id)
                self._socket_sessions[socket_id] = session_id
                self._socket_chainlit_sessions[
                    socket_id
                ] = chainlit_session_id
                return True

    async def unbind_socket(self, socket_id: str) -> None:
        async with self._lock:
            self._invalidating_sockets.discard(socket_id)
            session_id = self._socket_sessions.pop(socket_id, None)
            self._socket_chainlit_sessions.pop(socket_id, None)
            if session_id:
                session_sockets = self._session_sockets.get(session_id)
                if session_sockets is not None:
                    session_sockets.discard(socket_id)
                    if not session_sockets:
                        self._session_sockets.pop(session_id, None)

    async def release_chainlit_session(self, chainlit_session_id: str) -> None:
        async with self._lock:
            if any(
                mapped_chainlit_id == chainlit_session_id
                for mapped_chainlit_id in self._socket_chainlit_sessions.values()
            ):
                return
            session_id = self._chainlit_sessions.pop(
                chainlit_session_id,
                None,
            )
            if session_id:
                self._session_chainlit_sessions.get(
                    session_id,
                    OrderedDict(),
                ).pop(chainlit_session_id, None)

    async def chainlit_session_owner(
        self,
        chainlit_session_id: str,
    ) -> str | None:
        async with self._lock:
            return self._chainlit_sessions.get(chainlit_session_id)

    async def socket_is_active(self, socket_id: str) -> bool:
        invalidations: list[CopilotSessionInvalidation] = []
        async with self._lock:
            invalidations.extend(self._prune_locked(int(time.time())))
            session_id = self._socket_sessions.get(socket_id)
            active = bool(
                session_id
                and session_id in self._sessions
                and socket_id not in self._invalidating_sockets
            )
        await self._notify_invalidations(invalidations)
        return active

    async def count(self) -> int:
        invalidations: list[CopilotSessionInvalidation] = []
        async with self._lock:
            invalidations.extend(self._prune_locked(int(time.time())))
            count = len(self._sessions)
        await self._notify_invalidations(invalidations)
        return count


_session_store: CopilotSessionStore | None = None


def configure_session_store(
    *,
    max_sessions: int,
    ttl_seconds: int,
) -> CopilotSessionStore:
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
    safe_user = User(
        identifier=user.identifier,
        display_name=user.display_name,
        metadata=safe_profile_metadata(user.metadata),
    )
    session_token = create_jwt(safe_user)
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


def clear_copilot_session_cookie(
    response: Response,
    *,
    same_site: str,
) -> None:
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


def is_valid_session_id(value: str | None) -> bool:
    return bool(value and _SESSION_ID_PATTERN.fullmatch(value))


def _metadata_principal_id(metadata: dict | None) -> str:
    metadata = metadata or {}
    try:
        return canonical_principal_id(
            str(metadata.get("tenant_id") or ""),
            str(metadata.get("object_id") or ""),
        )
    except ValueError:
        return ""


async def resolve_access_token(metadata: dict | None) -> str | None:
    """Resolve a credential from only the current authenticated session."""

    metadata = metadata or {}
    copilot_session = current_copilot_session()
    if copilot_session:
        active_session = await get_session_store().get(
            copilot_session.session_id
        )
        if not active_session:
            return None
        metadata_principal = _metadata_principal_id(metadata)
        if (
            metadata_principal
            and metadata_principal != active_session.principal_id
        ):
            return None
        return active_session.access_token

    credential = await current_oauth_credential(metadata)
    return credential.access_token if credential else None


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
    response = JSONResponse(
        {"detail": detail},
        status_code=status_code,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Vary": "Origin",
        },
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
        if not is_user_authorized(config, principal_name, principal_id):
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
