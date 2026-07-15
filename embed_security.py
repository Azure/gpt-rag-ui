import logging
from http.cookies import SimpleCookie
from urllib.parse import urlsplit

from starlette.responses import PlainTextResponse

from embed_auth import COPILOT_SESSION_COOKIE, CopilotSessionStore
from embed_config import EmbedSettings


logger = logging.getLogger("gpt_rag_ui.embed_security")
_PUBLIC_COPILOT_PATHS = (
    "/copilot/",
    "/copilot/auth/bootstrap",
    "/copilot/auth/logout",
)
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


def _header_value(scope, name: bytes) -> str:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return value.decode("latin-1")
    return ""


def _cookie_value(scope, name: str) -> str | None:
    raw_cookie = _header_value(scope, b"cookie")
    if not raw_cookie:
        return None
    cookie = SimpleCookie()
    try:
        cookie.load(raw_cookie)
    except Exception:
        return None
    morsel = cookie.get(name)
    return morsel.value if morsel else None


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
        return any(
            path == prefix or path.startswith(prefix)
            for prefix in _PUBLIC_COPILOT_PATHS
        )

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
        )
        await response(scope, receive, send)

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        raw_origin = _header_value(scope, b"origin")
        origin = canonical_origin(raw_origin) if raw_origin else ""
        session_id = _cookie_value(scope, COPILOT_SESSION_COOKIE)
        raw_referer = _header_value(scope, b"referer")
        if (
            not origin
            and session_id
            and scope["type"] == "http"
            and scope.get("method", "").upper() == "GET"
        ):
            origin = origin_from_referer(raw_referer)
            if raw_referer and not origin:
                await self._reject(scope, receive, send, 403)
                return
        is_portal = origin in self.portal_origins
        is_standalone = origin == self.settings.ui_origin

        if raw_origin and not (is_portal or is_standalone):
            await self._reject(scope, receive, send, 403)
            return
        if session_id and scope["type"] == "websocket" and not raw_origin:
            await self._reject(scope, receive, send, 403)
            return
        if path == "/copilot/auth/bootstrap" and not is_portal:
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


def _copilot_session_marker(user) -> str:
    return str(
        ((getattr(user, "metadata", None) or {}).get("copilot_session_id") or "")
    )


def configure_copilot_bridge_guards(sio) -> None:
    if getattr(sio, "_gpt_rag_copilot_guards", False):
        return

    original_emit = sio.emit
    original_call = sio.call
    handlers = sio.handlers.get("/", {})
    original_connect = handlers.get("connect")

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
            if existing and existing.user:
                current_user = await _authenticated_socket_user(environ)
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

    original_window_handler = handlers.get("window_message")
    if original_window_handler:
        async def guarded_window_message(socket_id, *args, **kwargs):
            if _is_copilot_socket(socket_id):
                logger.warning("Blocked inbound window_message for a Copilot session")
                return None
            return await original_window_handler(socket_id, *args, **kwargs)

        sio.on("window_message", handler=guarded_window_message)

    sio._gpt_rag_copilot_guards = True
