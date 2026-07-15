from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from embed_config import EmbedSettings


def build_frame_ancestors(origins: tuple[str, ...]) -> str:
    return "frame-ancestors " + " ".join(("'self'", *origins))


def merge_frame_ancestors(
    current_policy: str | None,
    origins: tuple[str, ...],
) -> str:
    directives = [
        directive.strip()
        for directive in (current_policy or "").split(";")
        if directive.strip()
        and not directive.strip().lower().startswith("frame-ancestors ")
    ]
    directives.append(build_frame_ancestors(origins))
    return "; ".join(directives)


class CopilotSecurityMiddleware(BaseHTTPMiddleware):
    """Constrain iframe parents for enabled Copilot deployments."""

    def __init__(self, app, settings: EmbedSettings):
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = merge_frame_ancestors(
            response.headers.get("Content-Security-Policy"),
            self.settings.allowed_origins,
        )
        if "X-Frame-Options" in response.headers:
            del response.headers["X-Frame-Options"]
        return response


def _header_value(scope, name: bytes) -> str:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return value.decode("latin-1")
    return ""


def _canonical_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    default_port = 80 if parsed.scheme == "http" else 443
    host = f"[{parsed.hostname.lower()}]" if ":" in parsed.hostname else parsed.hostname.lower()
    suffix = f":{port}" if port and port != default_port else ""
    return f"{parsed.scheme}://{host}{suffix}"


class CopilotOriginMiddleware:
    """Reject untrusted HTTP and WebSocket origins before Chainlit handles them."""

    def __init__(self, app, allowed_origins: tuple[str, ...]):
        self.app = app
        self.allowed_origins = {
            _canonical_origin(origin) for origin in allowed_origins
        }

    def _is_allowed(self, scope) -> bool:
        raw_origin = _header_value(scope, b"origin")
        if not raw_origin:
            return True

        origin = _canonical_origin(raw_origin)
        if origin in self.allowed_origins:
            return True

        host = _header_value(scope, b"host")
        scheme = scope.get("scheme", "http")
        if scheme == "ws":
            scheme = "http"
        elif scheme == "wss":
            scheme = "https"
        return origin == _canonical_origin(f"{scheme}://{host}")

    async def __call__(self, scope, receive, send):
        if scope["type"] in {"http", "websocket"} and not self._is_allowed(scope):
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            response = PlainTextResponse("Origin not allowed", status_code=403)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
