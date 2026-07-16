import asyncio
import logging
from http.cookies import CookieError, SimpleCookie
from urllib.parse import urlsplit

from starlette.responses import PlainTextResponse

from embed_auth import (
    bind_request_copilot_session,
    COPILOT_SESSION_COOKIE,
    CopilotSessionStore,
    is_valid_session_id,
    reset_request_copilot_session,
)
from embed_config import EmbedSettings


logger = logging.getLogger("gpt_rag_ui.embed_security")
_COPILOT_AUTH_PATHS = {
    "/copilot/auth/bootstrap",
    "/copilot/auth/logout",
}
_DISABLED_CHAINLIT_AUTH_PATHS = {"/auth/jwt", "/auth/header"}
_BLOCKED_BRIDGE_EVENTS = {"call_fn", "window_message"}
_copilot_sio = None


def canonical_origin(value: str) -> str:
    if not value or value != value.strip() or any(ord(char) < 32 for char in value):
        return ""
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
        or (port is not None and port <= 0)
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


def _parsed_cookies(scope) -> dict[str, str] | None:
    parsed: dict[str, str] = {}
    for raw_cookie in _header_values(scope, b"cookie"):
        segments = [segment.strip() for segment in raw_cookie.split(";")]
        if any(not segment or "=" not in segment for segment in segments):
            return None
        names = [segment.partition("=")[0].strip() for segment in segments]
        if any(not name or name in parsed for name in names):
            return None
        if len(names) != len(set(names)):
            return None

        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except (CookieError, TypeError, ValueError):
            return None
        if raw_cookie.strip() and not cookie:
            return None
        for name, morsel in cookie.items():
            if name in parsed:
                return None
            parsed[name] = morsel.value
    return parsed


def _cookie_value(scope, name: str) -> str | None:
    cookies = _parsed_cookies(scope)
    if cookies is None:
        return None
    return cookies.get(name)


def _inject_chainlit_cookie(scope, token: str) -> dict:
    cookies = _parsed_cookies(scope)
    existing = []
    if cookies:
        for name, value in cookies.items():
            if name == "access_token" or name.startswith("access_token_"):
                continue
            cookie = SimpleCookie()
            cookie[name] = value
            existing.append(f"{name}={cookie[name].coded_value}")
    existing.append(f"access_token={token}")

    headers = [
        (key, value)
        for key, value in scope.get("headers", [])
        if key.lower() != b"cookie"
    ]
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
    def _is_public_copilot_path(path: str) -> bool:
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
        is_portal = origin in self.portal_origins
        is_standalone = origin == self.settings.ui_origin

        if len(raw_origins) > 1 or (
            raw_origins and not (is_portal or is_standalone)
        ):
            await self._reject(scope, receive, send, 403)
            return
        if scope["type"] == "websocket" and not raw_origins:
            await self._reject(scope, receive, send, 403)
            return
        if path in _COPILOT_AUTH_PATHS and not is_portal:
            await self._reject(scope, receive, send, 403)
            return
        if is_portal and path in _DISABLED_CHAINLIT_AUTH_PATHS:
            response = PlainTextResponse(
                "Not found",
                status_code=404,
                headers={"Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
            return

        is_preflight = (
            scope["type"] == "http"
            and scope.get("method", "").upper() == "OPTIONS"
        )
        request_session = None
        if (
            is_portal
            and not self._is_public_copilot_path(path)
            and not is_preflight
        ):
            request_session = await self.sessions.get(session_id)
            if not request_session:
                await self._reject(scope, receive, send, 401)
                return
            scope = _inject_chainlit_cookie(
                scope,
                request_session.chainlit_token,
            )

        if not request_session:
            await self.app(scope, receive, send)
            return

        context_token = bind_request_copilot_session(request_session)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_request_copilot_session(context_token)


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


def _target_has_copilot_sockets(sio, target: str | None) -> bool:
    if not target:
        return _has_copilot_sockets()
    if _is_copilot_socket(target):
        return True

    try:
        participants = sio.manager.get_participants("/", target)
        for participant in participants:
            socket_id = participant[0] if isinstance(participant, tuple) else participant
            if isinstance(socket_id, str) and _is_copilot_socket(socket_id):
                return True
        return False
    except Exception:
        logger.exception("Could not resolve Socket.IO bridge recipients")
        # Default deny only when a Copilot socket could receive the event.
        return _has_copilot_sockets()


def _existing_socket_session(session_id: str | None):
    if not session_id:
        return None
    from chainlit.session import WebsocketSession

    return WebsocketSession.get_by_id(session_id)


async def _authenticated_socket_user(environ):
    from chainlit.socket import _authenticate_connection

    user, _ = await _authenticate_connection(environ)
    return user


def _copilot_session_marker(user) -> str:
    return str(
        ((getattr(user, "metadata", None) or {}).get("copilot_session_id") or "")
    )


async def disconnect_copilot_session(session_id: str) -> int:
    """Disconnect every live Chainlit socket bound to an opaque session."""

    if not _copilot_sio or not is_valid_session_id(session_id):
        return 0

    from chainlit.session import ws_sessions_sid

    matches = [
        session
        for session in list(ws_sessions_sid.values())
        if _copilot_session_marker(session.user) == session_id
    ]
    disconnected = 0
    current_task = asyncio.current_task()
    for session in matches:
        session.to_clear = True
        task = getattr(session, "current_task", None)
        if task and task is not current_task and not task.done():
            task.cancel()
        try:
            await _copilot_sio.disconnect(session.socket_id)
            disconnected += 1
        except Exception:
            logger.exception("Failed to disconnect a Copilot socket")
    return disconnected


def configure_copilot_bridge_guards(
    sio,
    *,
    sessions: CopilotSessionStore,
) -> None:
    global _copilot_sio
    _copilot_sio = sio

    if getattr(sio, "_gpt_rag_copilot_guards", False):
        return

    original_emit = sio.emit
    original_call = sio.call
    handlers = sio.handlers.get("/", {})
    original_connect = handlers.get("connect")

    async def guarded_emit(event, *args, **kwargs):
        target = _socket_target(args, kwargs)
        if event in _BLOCKED_BRIDGE_EVENTS and _target_has_copilot_sockets(
            sio, target
        ):
            logger.warning("Blocked outbound %s for a Copilot session", event)
            return None
        return await original_emit(event, *args, **kwargs)

    async def guarded_call(event, *args, **kwargs):
        target = _socket_target(args, kwargs)
        if event in _BLOCKED_BRIDGE_EVENTS and _target_has_copilot_sockets(
            sio, target
        ):
            raise PermissionError(
                "Browser bridge calls are disabled for Copilot sessions."
            )
        return await original_call(event, *args, **kwargs)

    sio.emit = guarded_emit
    sio.call = guarded_call

    if original_connect:

        async def guarded_connect(socket_id, environ, auth):
            auth_payload = auth if isinstance(auth, dict) else {}
            current_user = await _authenticated_socket_user(environ)
            metadata = (
                (getattr(current_user, "metadata", None) or {})
                if current_user
                else {}
            )
            copilot_session_id = _copilot_session_marker(current_user)
            is_copilot_identity = (
                metadata.get("auth_source") == "copilot_session"
            )
            if is_copilot_identity:
                active_session = await sessions.get(copilot_session_id)
                if (
                    not active_session
                    or active_session.principal_id != current_user.identifier
                    or auth_payload.get("clientType") != "copilot"
                ):
                    logger.warning(
                        "Blocked Socket.IO connection for an inactive or "
                        "invalid Copilot session"
                    )
                    raise ConnectionRefusedError("authentication failed")

            existing = _existing_socket_session(auth_payload.get("sessionId"))
            if existing and existing.user:
                same_principal = bool(
                    current_user
                    and current_user.identifier == existing.user.identifier
                )
                same_copilot_session = (
                    _copilot_session_marker(current_user)
                    == _copilot_session_marker(existing.user)
                )
                if not same_principal or not same_copilot_session:
                    logger.warning(
                        "Blocked Socket.IO session restore across authenticated sessions"
                    )
                    raise ConnectionRefusedError("authentication failed")
            return await original_connect(socket_id, environ, auth)

        sio.on("connect", handler=guarded_connect)

    for event in ("call_fn", "window_message"):
        original_handler = handlers.get(event)
        if not original_handler:
            continue

        async def guarded_handler(
            socket_id,
            *args,
            _event=event,
            _handler=original_handler,
            **kwargs,
        ):
            if _is_copilot_socket(socket_id):
                logger.warning(
                    "Blocked inbound %s for a Copilot session",
                    _event,
                )
                return None
            return await _handler(socket_id, *args, **kwargs)

        sio.on(event, handler=guarded_handler)

    sio._gpt_rag_copilot_guards = True
