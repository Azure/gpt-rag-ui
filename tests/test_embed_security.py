import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Request, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from embed_auth import COPILOT_SESSION_COOKIE
from embed_config import EmbedSettings
from embed_security import (
    _is_copilot_socket,
    configure_copilot_bridge_guards,
    CopilotRequestMiddleware,
)


PORTAL = "https://portal.example.com"
CHAT = "https://chat.example.com"


class FakeSessions:
    def __init__(self, session=None):
        self.session = session

    async def get(self, session_id):
        return self.session if session_id == "opaque-session" else None


def create_app(session=None):
    app = FastAPI()

    @app.get("/protected")
    async def protected(request: Request):
        return {"cookie": request.cookies.get("access_token")}

    @app.post("/copilot/auth/bootstrap")
    async def bootstrap():
        return {"ok": True}

    @app.post("/auth/jwt")
    async def jwt_auth():
        return {"unsafe": True}

    @app.websocket("/ws/socket.io")
    async def websocket_endpoint(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_text("connected")

    settings = EmbedSettings(
        enabled=True,
        ui_origin=CHAT,
        allowed_origins=(PORTAL,),
    )
    app.add_middleware(
        CopilotRequestMiddleware,
        settings=settings,
        sessions=FakeSessions(session),
    )
    return app


class EmbedSecurityTests(unittest.TestCase):
    def test_bootstrap_requires_exact_origin(self):
        with TestClient(create_app(), base_url=CHAT) as client:
            self.assertEqual(
                403,
                client.post("/copilot/auth/bootstrap").status_code,
            )
            self.assertEqual(
                403,
                client.post(
                    "/copilot/auth/bootstrap",
                    headers={"Origin": "https://attacker.example.com"},
                ).status_code,
            )
            self.assertEqual(
                200,
                client.post(
                    "/copilot/auth/bootstrap",
                    headers={"Origin": PORTAL},
                ).status_code,
            )

    def test_bootstrap_rejects_non_origin_url_syntax(self):
        with TestClient(create_app(), base_url=CHAT) as client:
            for origin in (
                "https://user@portal.example.com",
                "https://portal.example.com/path",
                "https://portal.example.com?query=value",
                "https://portal.example.com#fragment",
            ):
                with self.subTest(origin=origin):
                    response = client.post(
                        "/copilot/auth/bootstrap",
                        headers={"Origin": origin},
                    )
                    self.assertEqual(403, response.status_code)

    def test_portal_protected_request_requires_session(self):
        with TestClient(create_app(), base_url=CHAT) as client:
            response = client.get("/protected", headers={"Origin": PORTAL})
        self.assertEqual(401, response.status_code)

    def test_valid_session_injects_internal_chainlit_cookie(self):
        session = SimpleNamespace(chainlit_token="internal-chainlit-jwt")
        with TestClient(create_app(session), base_url=CHAT) as client:
            response = client.get(
                "/protected",
                headers={
                    "Origin": PORTAL,
                    "Cookie": (
                        f"{COPILOT_SESSION_COOKIE}=opaque-session; "
                        "access_token=attacker-controlled"
                    ),
                },
            )
        self.assertEqual(200, response.status_code)
        self.assertEqual("internal-chainlit-jwt", response.json()["cookie"])

    def test_cookie_without_portal_origin_does_not_override_standalone_auth(self):
        session = SimpleNamespace(chainlit_token="internal-chainlit-jwt")
        with TestClient(create_app(session), base_url=CHAT) as client:
            response = client.get(
                "/protected",
                headers={"Cookie": f"{COPILOT_SESSION_COOKIE}=opaque-session"},
            )
        self.assertEqual(200, response.status_code)
        self.assertIsNone(response.json()["cookie"])

    def test_safe_get_navigation_accepts_exact_portal_referer(self):
        session = SimpleNamespace(chainlit_token="internal-chainlit-jwt")
        with TestClient(create_app(session), base_url=CHAT) as client:
            response = client.get(
                "/protected",
                headers={
                    "Referer": f"{PORTAL}/page",
                    "Cookie": f"{COPILOT_SESSION_COOKIE}=opaque-session",
                },
            )
        self.assertEqual(200, response.status_code)

    def test_safe_get_navigation_rejects_credentialed_referer(self):
        session = SimpleNamespace(chainlit_token="internal-chainlit-jwt")
        with TestClient(create_app(session), base_url=CHAT) as client:
            response = client.get(
                "/protected",
                headers={
                    "Referer": "https://attacker@portal.example.com/page",
                    "Cookie": f"{COPILOT_SESSION_COOKIE}=opaque-session",
                },
            )
        self.assertEqual(403, response.status_code)

    def test_standalone_exact_origin_is_unchanged(self):
        with TestClient(create_app(), base_url=CHAT) as client:
            response = client.get("/protected", headers={"Origin": CHAT})
        self.assertEqual(200, response.status_code)
        self.assertIsNone(response.json()["cookie"])

    def test_chainlit_jwt_and_header_routes_are_disabled_for_portal(self):
        with TestClient(create_app(), base_url=CHAT) as client:
            response = client.post("/auth/jwt", headers={"Origin": PORTAL})
        self.assertEqual(404, response.status_code)

    def test_websocket_rejects_wrong_origin_and_missing_session(self):
        with TestClient(create_app(), base_url=CHAT) as client:
            with self.assertRaises(WebSocketDisconnect) as wrong_origin:
                with client.websocket_connect(
                    "/ws/socket.io",
                    headers={"Origin": "https://attacker.example.com"},
                ):
                    pass
            self.assertEqual(1008, wrong_origin.exception.code)

            with self.assertRaises(WebSocketDisconnect) as missing_session:
                with client.websocket_connect(
                    "/ws/socket.io",
                    headers={"Origin": PORTAL},
                ):
                    pass
            self.assertEqual(4401, missing_session.exception.code)

            with self.assertRaises(WebSocketDisconnect) as missing_origin:
                with client.websocket_connect(
                    "/ws/socket.io",
                    headers={
                        "Cookie": f"{COPILOT_SESSION_COOKIE}=opaque-session",
                    },
                ):
                    pass
            self.assertEqual(1008, missing_origin.exception.code)

    def test_websocket_accepts_exact_origin_with_session(self):
        session = SimpleNamespace(chainlit_token="internal-chainlit-jwt")
        with TestClient(create_app(session), base_url=CHAT) as client:
            with client.websocket_connect(
                "/ws/socket.io",
                headers={
                    "Origin": PORTAL,
                    "Cookie": f"{COPILOT_SESSION_COOKIE}=opaque-session",
                },
            ) as websocket:
                self.assertEqual("connected", websocket.receive_text())


class BridgeGuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_copilot_bridge_events_are_denied(self):
        original_window_handler = AsyncMock()

        class FakeSio:
            def __init__(self):
                self.emit = AsyncMock()
                self.call = AsyncMock()
                self.handlers = {"/": {"window_message": original_window_handler}}

            def on(self, event, handler):
                self.handlers["/"][event] = handler

        sio = FakeSio()
        configure_copilot_bridge_guards(sio)

        with patch("embed_security._is_copilot_socket", return_value=True):
            self.assertIsNone(
                await sio.emit("window_message", {"secret": True}, to="socket")
            )
            with self.assertRaises(PermissionError):
                await sio.call("call_fn", {}, to="socket")
            self.assertIsNone(
                await sio.handlers["/"]["window_message"](
                    "socket",
                    {"secret": True},
                )
            )

        original_window_handler.assert_not_awaited()

    async def test_positional_bridge_target_is_denied(self):
        class FakeSio:
            def __init__(self):
                self.emit = AsyncMock()
                self.call = AsyncMock()
                self.handlers = {"/": {}}

            def on(self, event, handler):
                self.handlers["/"][event] = handler

        sio = FakeSio()
        configure_copilot_bridge_guards(sio)

        with patch("embed_security._is_copilot_socket", return_value=True):
            self.assertIsNone(
                await sio.emit("window_message", {"secret": True}, "socket")
            )
            with self.assertRaises(PermissionError):
                await sio.call("call_fn", {}, "socket")

    async def test_window_message_broadcast_is_denied_with_copilot_connected(self):
        class FakeSio:
            def __init__(self):
                self.emit = AsyncMock()
                self.call = AsyncMock()
                self.handlers = {"/": {}}

            def on(self, event, handler):
                self.handlers["/"][event] = handler

        sio = FakeSio()
        configure_copilot_bridge_guards(sio)

        with patch("embed_security._has_copilot_sockets", return_value=True):
            self.assertIsNone(
                await sio.emit("window_message", {"secret": True})
            )

    def test_copilot_client_type_is_guarded_without_metadata_marker(self):
        session = SimpleNamespace(client_type="copilot", user=None)
        with patch(
            "chainlit.session.WebsocketSession.get",
            return_value=session,
        ):
            self.assertTrue(_is_copilot_socket("socket"))

    async def test_cross_principal_socket_restore_is_denied(self):
        original_connect = AsyncMock(return_value=True)

        class FakeSio:
            def __init__(self):
                self.emit = AsyncMock()
                self.call = AsyncMock()
                self.handlers = {"/": {"connect": original_connect}}

            def on(self, event, handler):
                self.handlers["/"][event] = handler

        existing_user = SimpleNamespace(
            identifier="tenant:old-user",
            metadata={"copilot_session_id": "old-copilot-session"},
        )
        existing_session = SimpleNamespace(user=existing_user)
        current_user = SimpleNamespace(
            identifier="tenant:new-user",
            metadata={"copilot_session_id": "new-copilot-session"},
        )
        sio = FakeSio()
        configure_copilot_bridge_guards(sio)

        with (
            patch(
                "embed_security._existing_socket_session",
                return_value=existing_session,
            ),
            patch(
                "embed_security._authenticated_socket_user",
                AsyncMock(return_value=current_user),
            ),
        ):
            with self.assertRaises(ConnectionRefusedError):
                await sio.handlers["/"]["connect"](
                    "socket",
                    {},
                    {"sessionId": "reused-session"},
                )

        original_connect.assert_not_awaited()

    async def test_matching_socket_restore_reaches_chainlit(self):
        original_connect = AsyncMock(return_value=True)

        class FakeSio:
            def __init__(self):
                self.emit = AsyncMock()
                self.call = AsyncMock()
                self.handlers = {"/": {"connect": original_connect}}

            def on(self, event, handler):
                self.handlers["/"][event] = handler

        user = SimpleNamespace(
            identifier="tenant:user",
            metadata={"copilot_session_id": "copilot-session"},
        )
        sio = FakeSio()
        configure_copilot_bridge_guards(sio)

        with (
            patch(
                "embed_security._existing_socket_session",
                return_value=SimpleNamespace(user=user),
            ),
            patch(
                "embed_security._authenticated_socket_user",
                AsyncMock(return_value=user),
            ),
        ):
            self.assertTrue(
                await sio.handlers["/"]["connect"](
                    "socket",
                    {},
                    {"sessionId": "existing-session"},
                )
            )

        original_connect.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
