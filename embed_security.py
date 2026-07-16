import asyncio
import logging
from http.cookies import SimpleCookie
from urllib.parse import urlsplit

from starlette.responses import PlainTextResponse

from embed_auth import (
    bind_copilot_session,
    COPILOT_SCOPE_SESSION_KEY,
    COPILOT_SESSION_COOKIE,
    CopilotSessionInvalidation,
    CopilotSessionStore,
    current_copilot_session,
    is_valid_session_id,
)
from embed_config import EmbedSettings


logger = logging.getLogger("gpt_rag_ui.embed_security")
_COPILOT_AUTH_PATHS = {
    "/copilot/auth/bootstrap",
    "/copilot/auth/logout",
}
_DISABLED_CHAINLIT_AUTH_PATHS = {"/auth/jwt", "/auth/header"}


def canonical_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    if (
        parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return ""
    default_port = 80 if parsed.scheme == "http" else 443
    host = (
        f"[{parsed.hostname.lower()}]"
        if ":" in parsed.hostname
        else parsed.hostname.lower()
    )
    suffix = f":{port}" if port and port != default_port else ""
    return f"{parsed.scheme}://{host}{suffix}"


def origin_from_referer(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return ""
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        return ""
    default_port = 80 if parsed.scheme == "http" else 443
    host = (
        f"[{parsed.hostname.lower()}]"
        if ":" in parsed.hostname
        else parsed.hostname.lower()
    )
    suffix = f":{port}" if port and port != default_port else ""
    return f"{parsed.scheme}://{host}{suffix}"


def _header_values(scope, name: bytes) -> list[str]:
    return [
        value.decode("latin-1")
        for key, value in scope.get("headers", [])
        if key.lower() == name
    ]


def _cookie_value(scope, name: str) -> str | None:
    raw_cookie_headers = _header_values(scope, b"cookie")
    occurrences = 0
    cookie_value = None
    for raw_cookie in raw_cookie_headers:
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except Exception:
            return None
        if raw_cookie.strip() and not cookie:
            return None
        occurrences += sum(
            1
            for part in raw_cookie.split(";")
            if part.partition("=")[0].strip() == name
        )
        if name in cookie:
            if cookie_value is not None:
                return None
            cookie_value = cookie[name].value
    if occurrences != 1:
        return None
    return cookie_value


def _inject_chainlit_cookie(scope, token: str) -> dict:
    headers = []
    existing: list[str] = []
    for key, value in scope.get("headers", []):
        if key.lower() != b"cookie":
            headers.append((key, value))
            continue
        cookie = SimpleCookie()
        cookie.load(value.decode("latin-1"))
        existing.extend(
            f"{name}={morsel.value}"
            for name, morsel in cookie.items()
            if name != "access_token" and not name.startswith("access_token_")
        )
    existing.append(f"access_token={token}")
    headers.append((b"cookie", "; ".join(existing).encode("latin-1")))
    updated = dict(scope)
    updated["headers"] = headers
    return updated


class CopilotRequestMiddleware:
    def __init__(
        self,
        app,
        *,
        settings: EmbedSettings,
        sessions: CopilotSessionStore,
    ):
        self.app = app
        self.settings = settings
        self.sessions = sessions
        self.portal_origins = set(settings.allowed_origins)

    @staticmethod
    def _is_public(path: str) -> bool:
        return path == "/copilot" or path.startswith("/copilot/")

    async def _reject(self, scope, receive, send, status_code: int) -> None:
        if scope["type"] == "websocket":
            await send(
                {
                    "type": "websocket.close",
                    "code": 4401 if status_code == 401 else 1008,
                }
            )
            return
        response = PlainTextResponse(
            "Unauthorized" if status_code == 401 else "Origin not allowed",
            status_code=status_code,
            headers={"Cache-Control": "no-store"},
        )
        await response(scope, receive, send)

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        raw_origins = _header_values(scope, b"origin")
        raw_origin = raw_origins[0] if len(raw_origins) == 1 else ""
        origin = canonical_origin(raw_origin) if raw_origin else ""
        raw_session_id = _cookie_value(scope, COPILOT_SESSION_COOKIE)
        session_id = (
            raw_session_id if is_valid_session_id(raw_session_id) else None
        )
        referer_values = _header_values(scope, b"referer")
        used_referer = False
        if (
            not origin
            and session_id
            and scope["type"] == "http"
            and scope.get("method", "").upper() == "GET"
            and referer_values
        ):
            used_referer = True
            if len(referer_values) == 1:
                origin = origin_from_referer(referer_values[0])
        is_portal = origin in self.portal_origins
        is_standalone = origin == self.settings.ui_origin

        if len(raw_origins) > 1 or (
            raw_origin and not (is_portal or is_standalone)
        ):
            await self._reject(scope, receive, send, 403)
            return
        if used_referer and not (is_portal or is_standalone):
            await self._reject(scope, receive, send, 403)
            return
        if scope["type"] == "websocket" and not raw_origin:
            await self._reject(scope, receive, send, 403)
            return
        if path in _COPILOT_AUTH_PATHS and not is_portal:
            await self._reject(scope, receive, send, 403)
            return
        if is_portal and path in _DISABLED_CHAINLIT_AUTH_PATHS:
            response = PlainTextResponse("Not found", status_code=404)
            await response(scope, receive, send)
            return

        is_preflight = (
            scope["type"] == "http"
            and scope.get("method", "").upper() == "OPTIONS"
        )
        if is_portal and not self._is_public(path) and not is_preflight:
            session = await self.sessions.get(session_id)
            if not session:
                await self._reject(scope, receive, send, 401)
                return
            scope = _inject_chainlit_cookie(scope, session.chainlit_token)
            scope[COPILOT_SCOPE_SESSION_KEY] = session_id
            with bind_copilot_session(session):
                await self.app(scope, receive, send)
            return

        await self.app(scope, receive, send)


def _is_copilot_socket(socket_id: str) -> bool:
    from chainlit.session import WebsocketSession

    session = WebsocketSession.get(socket_id)
    if not session:
        return False
    if session.client_type == "copilot":
        return True
    return bool(
        session.user
        and (session.user.metadata or {}).get("auth_source") == "copilot_session"
    )


def _has_copilot_sockets() -> bool:
    from chainlit.session import ws_sessions_sid

    return any(
        _is_copilot_socket(socket_id)
        for socket_id in list(ws_sessions_sid)
    )


def _socket_target(args, kwargs) -> str | None:
    target = kwargs.get("to") or kwargs.get("room")
    if target is None and len(args) > 1:
        target = args[1]
    return target if isinstance(target, str) and target else None


def _existing_socket_session(session_id: str | None):
    if not session_id:
        return None
    from chainlit.session import WebsocketSession

    return WebsocketSession.get_by_id(session_id)


async def _authenticated_socket_user(environ):
    from chainlit.socket import _authenticate_connection

    user, _ = await _authenticate_connection(environ)
    return user


def _copilot_session_id_from_environ(environ) -> str:
    current = current_copilot_session()
    if current:
        return current.session_id
    scope = (environ or {}).get("asgi.scope") or {}
    return str(scope.get(COPILOT_SCOPE_SESSION_KEY) or "")


async def _terminate_chainlit_session(
    sio,
    *,
    socket_id: str | None = None,
    chainlit_session_id: str | None = None,
) -> None:
    from chainlit.session import WebsocketSession

    session = (
        WebsocketSession.get_by_id(chainlit_session_id)
        if chainlit_session_id
        else WebsocketSession.get(socket_id)
    )
    if not session:
        return

    session.to_clear = True
    task = session.current_task
    if (
        task
        and task is not asyncio.current_task()
        and not task.done()
    ):
        task.cancel()

    active_socket_id = session.socket_id
    try:
        await sio.disconnect(active_socket_id, namespace="/")
    except Exception:
        logger.warning(
            "Failed to disconnect invalidated Copilot socket",
            exc_info=True,
        )
    finally:
        if WebsocketSession.get_by_id(session.id) is session:
            await session.delete()


async def _invalidate_chainlit_sessions(
    sio,
    invalidation: CopilotSessionInvalidation,
) -> None:
    from chainlit.session import WebsocketSession

    chainlit_session_ids = set(invalidation.chainlit_session_ids)
    for socket_id in invalidation.socket_ids:
        if session := WebsocketSession.get(socket_id):
            chainlit_session_ids.add(session.id)

    for chainlit_session_id in chainlit_session_ids:
        await _terminate_chainlit_session(
            sio,
            chainlit_session_id=chainlit_session_id,
        )


def configure_copilot_bridge_guards(
    sio,
    sessions: CopilotSessionStore,
) -> None:
    if getattr(sio, "_gpt_rag_copilot_guards", False):
        return

    original_emit = sio.emit
    original_call = sio.call
    handlers = sio.handlers.get("/", {})
    original_connect = handlers.get("connect")
    original_disconnect = handlers.get("disconnect")

    async def invalidate_session(
        invalidation: CopilotSessionInvalidation,
    ) -> None:
        await _invalidate_chainlit_sessions(sio, invalidation)

    sessions.set_invalidation_handler(invalidate_session)

    async def guarded_emit(event, *args, **kwargs):
        target = _socket_target(args, kwargs)
        copilot_recipient = (
            _is_copilot_socket(target)
            if target
            else _has_copilot_sockets()
        )
        if event == "window_message" and copilot_recipient:
            logger.warning("Blocked window_message for a Copilot session")
            return None
        return await original_emit(event, *args, **kwargs)

    async def guarded_call(event, *args, **kwargs):
        target = _socket_target(args, kwargs)
        if event == "call_fn" and target and _is_copilot_socket(target):
            raise PermissionError("Browser function calls are disabled for Copilot sessions.")
        return await original_call(event, *args, **kwargs)

    sio.emit = guarded_emit
    sio.call = guarded_call

    if original_connect:
        async def guarded_connect(socket_id, environ, auth):
            existing = _existing_socket_session((auth or {}).get("sessionId"))
            copilot_session_id = _copilot_session_id_from_environ(environ)
            existing_owner = (
                await sessions.chainlit_session_owner(existing.id)
                if existing
                else None
            )
            existing_is_copilot = bool(
                existing and getattr(existing, "client_type", None) == "copilot"
            )

            if copilot_session_id:
                active_session = await sessions.get(copilot_session_id)
                if (
                    not active_session
                    or (auth or {}).get("clientType") != "copilot"
                ):
                    raise ConnectionRefusedError("authentication failed")
                current_user = await _authenticated_socket_user(environ)
                same_principal = bool(
                    current_user
                    and active_session
                    and current_user.identifier == active_session.principal_id
                )
                if not same_principal:
                    raise ConnectionRefusedError("authentication failed")

                if existing and existing.user:
                    same_principal = bool(
                        current_user
                        and current_user.identifier == existing.user.identifier
                    )
                    same_copilot_session = (
                        existing_owner == copilot_session_id
                    )
                    if not same_principal or not same_copilot_session:
                        logger.warning(
                            "Blocked Socket.IO session restore across authenticated sessions"
                        )
                        raise ConnectionRefusedError("authentication failed")
            elif existing_owner or existing_is_copilot:
                logger.warning(
                    "Blocked standalone restore of a Copilot Socket.IO session"
                )
                raise ConnectionRefusedError("authentication failed")

            result = await original_connect(socket_id, environ, auth)
            if copilot_session_id:
                from chainlit.session import WebsocketSession

                websocket_session = WebsocketSession.get(socket_id)
                admitted = bool(
                    websocket_session
                    and await sessions.bind_connection(
                        session_id=copilot_session_id,
                        socket_id=socket_id,
                        chainlit_session_id=websocket_session.id,
                    )
                )
                if not admitted:
                    await _terminate_chainlit_session(
                        sio,
                        socket_id=socket_id,
                    )
                    raise ConnectionRefusedError("authentication failed")
            return result

        sio.on("connect", handler=guarded_connect)

    if original_disconnect:
        async def guarded_disconnect(socket_id, *args, **kwargs):
            from chainlit.session import WebsocketSession

            websocket_session = WebsocketSession.get(socket_id)
            chainlit_session_id = (
                websocket_session.id if websocket_session else None
            )
            try:
                return await original_disconnect(
                    socket_id,
                    *args,
                    **kwargs,
                )
            finally:
                await sessions.unbind_socket(socket_id)
                if (
                    chainlit_session_id
                    and not WebsocketSession.get_by_id(chainlit_session_id)
                ):
                    await sessions.release_chainlit_session(
                        chainlit_session_id
                    )

        sio.on("disconnect", handler=guarded_disconnect)

    guarded_active_events = (
        "audio_chunk",
        "audio_end",
        "audio_start",
        "chat_settings_change",
        "clear_session",
        "client_message",
        "connection_successful",
        "edit_message",
        "stop",
    )
    for event_name in guarded_active_events:
        original_handler = handlers.get(event_name)
        if not original_handler:
            continue

        def create_guarded_handler(event, handler):
            async def guarded_handler(socket_id, *args, **kwargs):
                if (
                    _is_copilot_socket(socket_id)
                    and not await sessions.socket_is_active(socket_id)
                ):
                    logger.warning(
                        "Blocked %s for an invalidated Copilot session",
                        event,
                    )
                    await _terminate_chainlit_session(
                        sio,
                        socket_id=socket_id,
                    )
                    return None
                return await handler(socket_id, *args, **kwargs)

            return guarded_handler

        sio.on(
            event_name,
            handler=create_guarded_handler(
                event_name,
                original_handler,
            ),
        )

    for event_name in ("call_fn", "window_message"):
        original_handler = handlers.get(event_name)
        if not original_handler:
            continue

        def create_bridge_handler(event, handler):
            async def guarded_bridge_handler(socket_id, *args, **kwargs):
                if _is_copilot_socket(socket_id):
                    logger.warning(
                        "Blocked inbound %s for a Copilot session",
                        event,
                    )
                    return None
                return await handler(socket_id, *args, **kwargs)

            return guarded_bridge_handler

        sio.on(
            event_name,
            handler=create_bridge_handler(event_name, original_handler),
        )

    sio._gpt_rag_copilot_guards = True
