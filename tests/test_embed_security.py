import os
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from fastapi import FastAPI, Request, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from embed_auth import (
    COPILOT_SCOPE_SESSION_KEY,
    COPILOT_SESSION_COOKIE,
    CopilotSessionStore,
)
from embed_config import EmbedSettings
from embed_security import (
    _is_copilot_socket,
    configure_copilot_bridge_guards,
    CopilotRequestMiddleware,
)


PORTAL = "https://portal.example.com"
CHAT = "https://chat.example.com"
SESSION_ID = "s" * 43


class FakeSessions:
    def __init__(self, session=None):
        self.session = session
        if self.session and not hasattr(self.session, "session_id"):
            self.session.session_id = "opaque-session"

    async def get(self, session_id):
        return self.session if session_id == SESSION_ID else None


class FakeBridgeSessions:
    def __init__(
        self,
        *,
        active_session=None,
        owners=None,
        admit=True,
        socket_active=True,
    ):
        self.active_session = active_session
        self.owners = owners or {}
        self.admit = admit
        self.socket_active = socket_active
        self.invalidation_handler = None

    def set_invalidation_handler(self, handler):
        self.invalidation_handler = handler

    async def get(self, session_id):
        if (
            self.active_session
            and session_id == self.active_session.session_id
        ):
            return self.active_session
        return None

    async def chainlit_session_owner(self, chainlit_session_id):
        return self.owners.get(chainlit_session_id)

    async def bind_connection(self, **_):
        return self.admit

    async def unbind_socket(self, _):
        return None

    async def release_chainlit_session(self, _):
        return None

    async def socket_is_active(self, _):
        return self.socket_active


def create_app(session=None):
    app = FastAPI()

    @app.get("/protected")
    async def protected(request: Request):
        return {"cookie": request.cookies.get("access_token")}

    @app.post("/copilot/auth/bootstrap")
    async def bootstrap():
        return {"ok": True}

    @app.post("/copilot/auth/logout")
    async def logout():
        return {"ok": True}

    @app.get("/copilot")
    async def copilot_root():
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

    def test_logout_requires_exact_portal_origin(self):
        with TestClient(create_app(), base_url=CHAT) as client:
            self.assertEqual(
                403,
                client.post("/copilot/auth/logout").status_code,
            )
            self.assertEqual(
                403,
                client.post(
                    "/copilot/auth/logout",
                    headers={"Origin": "https://attacker.example.com"},
                ).status_code,
            )
            self.assertEqual(
                200,
                client.post(
                    "/copilot/auth/logout",
                    headers={"Origin": PORTAL},
                ).status_code,
            )

    def test_exact_copilot_root_is_public_to_portal(self):
        with TestClient(create_app(), base_url=CHAT) as client:
            response = client.get("/copilot", headers={"Origin": PORTAL})
        self.assertEqual(200, response.status_code)

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
                        f"{COPILOT_SESSION_COOKIE}={SESSION_ID}; "
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
                headers={"Cookie": f"{COPILOT_SESSION_COOKIE}={SESSION_ID}"},
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
                    "Cookie": f"{COPILOT_SESSION_COOKIE}={SESSION_ID}",
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
                    "Cookie": f"{COPILOT_SESSION_COOKIE}={SESSION_ID}",
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
                        "Cookie": f"{COPILOT_SESSION_COOKIE}={SESSION_ID}",
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
                    "Cookie": f"{COPILOT_SESSION_COOKIE}={SESSION_ID}",
                },
            ) as websocket:
                self.assertEqual("connected", websocket.receive_text())


class BridgeGuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_physical_socket_cap_disconnects_all_hundred_restores(self):
        active_socket_ids = set()
        disconnected_socket_ids = []

        async def disconnect(socket_id, *, namespace):
            self.assertEqual("/", namespace)
            disconnected_socket_ids.append(socket_id)
            active_socket_ids.discard(socket_id)

        class FakeSio:
            def __init__(self):
                self.emit = AsyncMock()
                self.call = AsyncMock()
                self.disconnect = AsyncMock(side_effect=disconnect)
                self.handlers = {"/": {}}

            def on(self, event, handler):
                self.handlers["/"][event] = handler

        sio = FakeSio()
        with patch.dict(
            os.environ,
            {"CHAINLIT_AUTH_SECRET": "test-secret-with-adequate-length"},
        ):
            store = CopilotSessionStore(
                max_sessions=1,
                ttl_seconds=120,
                max_connections_per_session=4,
            )
            configure_copilot_bridge_guards(sio, store)
            session = await store.replace(
                previous_session_id=None,
                access_token="entra-secret",
                claims={
                    "tid": "11111111-2222-3333-4444-555555555555",
                    "oid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    "exp": int(time.time()) + 600,
                },
                display_name="User",
                principal_name="user@example.com",
            )

            admitted_socket_ids = []
            max_active_sockets = 0
            with (
                patch(
                    "chainlit.session.WebsocketSession.get",
                    return_value=None,
                ),
                patch(
                    "chainlit.session.WebsocketSession.get_by_id",
                    return_value=None,
                ),
            ):
                for index in range(4):
                    socket_id = f"socket-{index}"
                    self.assertTrue(
                        await store.bind_connection(
                            session_id=session.session_id,
                            socket_id=socket_id,
                            chainlit_session_id=f"chainlit-{index}",
                        )
                    )
                    admitted_socket_ids.append(socket_id)
                    active_socket_ids.add(socket_id)
                    max_active_sockets = max(
                        max_active_sockets,
                        len(active_socket_ids),
                    )

                for index in range(4, 100):
                    socket_id = f"socket-{index}"
                    self.assertTrue(
                        await store.bind_connection(
                            session_id=session.session_id,
                            socket_id=socket_id,
                            chainlit_session_id="chainlit-0",
                        )
                    )
                    admitted_socket_ids.append(socket_id)
                    active_socket_ids.add(socket_id)
                    max_active_sockets = max(
                        max_active_sockets,
                        len(active_socket_ids),
                    )

                self.assertEqual(4, max_active_sockets)
                self.assertEqual(4, len(active_socket_ids))
                self.assertEqual(
                    set(admitted_socket_ids) - active_socket_ids,
                    set(disconnected_socket_ids),
                )

                await store.delete(session.session_id)

        self.assertFalse(active_socket_ids)
        self.assertEqual(
            set(admitted_socket_ids),
            set(disconnected_socket_ids),
        )
        self.assertEqual(100, sio.disconnect.await_count)

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
        configure_copilot_bridge_guards(sio, FakeBridgeSessions())

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
        configure_copilot_bridge_guards(sio, FakeBridgeSessions())

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
        configure_copilot_bridge_guards(sio, FakeBridgeSessions())

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
            metadata={},
        )
        existing_session = SimpleNamespace(
            id="reused-session",
            user=existing_user,
        )
        current_user = SimpleNamespace(
            identifier="tenant:new-user",
            metadata={},
        )
        active_session = SimpleNamespace(
            session_id="new-copilot-session",
            principal_id=current_user.identifier,
        )
        sessions = FakeBridgeSessions(
            active_session=active_session,
            owners={"reused-session": "old-copilot-session"},
        )
        sio = FakeSio()
        configure_copilot_bridge_guards(sio, sessions)

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
                    {
                        "asgi.scope": {
                            COPILOT_SCOPE_SESSION_KEY: "new-copilot-session"
                        }
                    },
                    {
                        "sessionId": "reused-session",
                        "clientType": "copilot",
                    },
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
            metadata={},
        )
        active_session = SimpleNamespace(
            session_id="copilot-session",
            principal_id=user.identifier,
        )
        sessions = FakeBridgeSessions(
            active_session=active_session,
            owners={"existing-session": "copilot-session"},
        )
        sio = FakeSio()
        configure_copilot_bridge_guards(sio, sessions)

        with (
            patch(
                "embed_security._existing_socket_session",
                return_value=SimpleNamespace(
                    id="existing-session",
                    user=user,
                ),
            ),
            patch(
                "embed_security._authenticated_socket_user",
                AsyncMock(return_value=user),
            ),
            patch(
                "chainlit.session.WebsocketSession.get",
                return_value=SimpleNamespace(id="existing-session"),
            ),
        ):
            self.assertTrue(
                await sio.handlers["/"]["connect"](
                    "socket",
                    {
                        "asgi.scope": {
                            COPILOT_SCOPE_SESSION_KEY: "copilot-session"
                        }
                    },
                    {
                        "sessionId": "existing-session",
                        "clientType": "copilot",
                    },
                )
            )

        original_connect.assert_awaited_once()

    async def test_matching_restore_preserves_chainlit_session_state(self):
        user = SimpleNamespace(identifier="tenant:user", metadata={})
        task = SimpleNamespace(done=Mock(return_value=False), cancel=Mock())
        websocket_session = SimpleNamespace(
            id="chainlit-session",
            socket_id="old-socket",
            client_type="copilot",
            user=user,
            current_task=task,
            to_clear=False,
            delete=AsyncMock(),
        )

        async def original_connect(socket_id, _environ, _auth):
            websocket_session.socket_id = socket_id
            return True

        class FakeSio:
            def __init__(self):
                self.emit = AsyncMock()
                self.call = AsyncMock()
                self.disconnect = AsyncMock()
                self.handlers = {
                    "/": {"connect": AsyncMock(side_effect=original_connect)}
                }

            def on(self, event, handler):
                self.handlers["/"][event] = handler

        with patch.dict(
            os.environ,
            {"CHAINLIT_AUTH_SECRET": "test-secret-with-adequate-length"},
        ):
            store = CopilotSessionStore(max_sessions=1, ttl_seconds=120)
            session = await store.replace(
                previous_session_id=None,
                access_token="entra-secret",
                claims={
                    "tid": "11111111-2222-3333-4444-555555555555",
                    "oid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    "exp": int(time.time()) + 600,
                },
                display_name="User",
                principal_name="user@example.com",
            )
            user.identifier = session.principal_id
            await store.bind_connection(
                session_id=session.session_id,
                socket_id="old-socket",
                chainlit_session_id=websocket_session.id,
            )
            sio = FakeSio()
            original_handler = sio.handlers["/"]["connect"]
            configure_copilot_bridge_guards(sio, store)

            with (
                patch(
                    "embed_security._existing_socket_session",
                    return_value=websocket_session,
                ),
                patch(
                    "embed_security._authenticated_socket_user",
                    AsyncMock(return_value=user),
                ),
                patch(
                    "chainlit.session.WebsocketSession.get",
                    side_effect=lambda socket_id: (
                        websocket_session
                        if socket_id == websocket_session.socket_id
                        else None
                    ),
                ),
                patch(
                    "chainlit.session.WebsocketSession.get_by_id",
                    return_value=websocket_session,
                ),
            ):
                self.assertTrue(
                    await sio.handlers["/"]["connect"](
                        "new-socket",
                        {
                            "asgi.scope": {
                                COPILOT_SCOPE_SESSION_KEY: session.session_id
                            }
                        },
                        {
                            "sessionId": websocket_session.id,
                            "clientType": "copilot",
                        },
                    )
                )

        original_handler.assert_awaited_once()
        sio.disconnect.assert_awaited_once_with(
            "old-socket",
            namespace="/",
        )
        task.cancel.assert_not_called()
        websocket_session.delete.assert_not_awaited()
        self.assertFalse(websocket_session.to_clear)
        self.assertFalse(await store.socket_is_active("old-socket"))
        self.assertTrue(await store.socket_is_active("new-socket"))

    async def test_invalidated_runtime_copilot_session_cannot_restore_standalone(
        self,
    ):
        original_connect = AsyncMock(return_value=True)

        class FakeSio:
            def __init__(self):
                self.emit = AsyncMock()
                self.call = AsyncMock()
                self.handlers = {"/": {"connect": original_connect}}

            def on(self, event, handler):
                self.handlers["/"][event] = handler

        existing_session = SimpleNamespace(
            id="invalidated-session",
            user=SimpleNamespace(identifier="tenant:user", metadata={}),
            client_type="copilot",
        )
        sio = FakeSio()
        configure_copilot_bridge_guards(sio, FakeBridgeSessions())

        with patch(
            "embed_security._existing_socket_session",
            return_value=existing_session,
        ):
            with self.assertRaises(ConnectionRefusedError):
                await sio.handlers["/"]["connect"](
                    "socket",
                    {"asgi.scope": {}},
                    {
                        "sessionId": "invalidated-session",
                        "clientType": "webapp",
                    },
                )

        original_connect.assert_not_awaited()

    async def test_invalidated_socket_cannot_clear_or_stop_session(self):
        original_clear = AsyncMock()
        original_stop = AsyncMock()

        class FakeSio:
            def __init__(self):
                self.emit = AsyncMock()
                self.call = AsyncMock()
                self.handlers = {
                    "/": {
                        "clear_session": original_clear,
                        "stop": original_stop,
                    }
                }

            def on(self, event, handler):
                self.handlers["/"][event] = handler

        sio = FakeSio()
        configure_copilot_bridge_guards(
            sio,
            FakeBridgeSessions(socket_active=False),
        )

        with (
            patch("embed_security._is_copilot_socket", return_value=True),
            patch(
                "embed_security._terminate_chainlit_session",
                AsyncMock(),
            ),
        ):
            await sio.handlers["/"]["clear_session"]("socket")
            await sio.handlers["/"]["stop"]("socket")

        original_clear.assert_not_awaited()
        original_stop.assert_not_awaited()

    async def test_eviction_cancels_disconnects_and_denies_surviving_socket(self):
        original_message = AsyncMock()

        class FakeSio:
            def __init__(self):
                self.emit = AsyncMock()
                self.call = AsyncMock()
                self.disconnect = AsyncMock()
                self.handlers = {"/": {"client_message": original_message}}

            def on(self, event, handler):
                self.handlers["/"][event] = handler

        task = SimpleNamespace(done=Mock(return_value=False), cancel=Mock())
        websocket_session = SimpleNamespace(
            id="chainlit-session",
            socket_id="socket",
            client_type="copilot",
            user=None,
            current_task=task,
            to_clear=False,
            delete=AsyncMock(),
        )
        sio = FakeSio()

        with patch.dict(
            os.environ,
            {"CHAINLIT_AUTH_SECRET": "test-secret-with-adequate-length"},
        ):
            store = CopilotSessionStore(max_sessions=1, ttl_seconds=120)
            configure_copilot_bridge_guards(sio, store)
            session = await store.replace(
                previous_session_id=None,
                access_token="entra-secret",
                claims={
                    "tid": "11111111-2222-3333-4444-555555555555",
                    "oid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    "exp": int(time.time()) + 600,
                },
                display_name="User",
                principal_name="user@example.com",
            )
            await store.bind_connection(
                session_id=session.session_id,
                socket_id="socket",
                chainlit_session_id="chainlit-session",
            )

            with (
                patch(
                    "chainlit.session.WebsocketSession.get",
                    return_value=websocket_session,
                ),
                patch(
                    "chainlit.session.WebsocketSession.get_by_id",
                    return_value=websocket_session,
                ),
            ):
                await store.delete(session.session_id, reason="capacity")
                await sio.handlers["/"]["client_message"](
                    "socket",
                    {"content": "must not run"},
                )

        task.cancel.assert_called()
        sio.disconnect.assert_awaited()
        websocket_session.delete.assert_awaited()
        original_message.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
