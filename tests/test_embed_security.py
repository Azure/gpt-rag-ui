import unittest

from fastapi import FastAPI, Response, WebSocket
from fastapi.testclient import TestClient
from starlette.middleware.cors import CORSMiddleware
from starlette.websockets import WebSocketDisconnect

from embed_config import EmbedSettings
from embed_security import (
    CopilotOriginMiddleware,
    CopilotSecurityMiddleware,
    merge_frame_ancestors,
)


class EmbedSecurityTests(unittest.TestCase):
    def test_replaces_existing_frame_ancestors_without_losing_other_directives(self):
        policy = merge_frame_ancestors(
            "default-src 'self'; frame-ancestors 'none'",
            ("https://portal.example.com",),
        )

        self.assertEqual(
            "default-src 'self'; frame-ancestors 'self' https://portal.example.com",
            policy,
        )

    def test_enabled_mode_adds_cors_and_safe_framing_headers(self):
        app = FastAPI()

        @app.post("/auth/jwt")
        async def jwt_auth():
            return Response(
                '{"route":"jwt"}',
                media_type="application/json",
                headers={"X-Frame-Options": "DENY"},
            )

        settings = EmbedSettings(
            enabled=True,
            allowed_origins=("https://portal.example.com",),
            auth_mode="entra",
            entra_tenant_id="11111111-2222-3333-4444-555555555555",
            entra_audience="api://test",
        )
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.allowed_origins),
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        app.add_middleware(
            CopilotOriginMiddleware,
            allowed_origins=settings.allowed_origins,
        )
        app.add_middleware(CopilotSecurityMiddleware, settings=settings)

        with TestClient(app) as client:
            response = client.post(
                "/auth/jwt",
                headers={"Origin": "https://portal.example.com"},
            )

        self.assertEqual({"route": "jwt"}, response.json())
        self.assertEqual(
            "https://portal.example.com",
            response.headers["access-control-allow-origin"],
        )
        self.assertNotIn("x-frame-options", response.headers)
        self.assertIn(
            "frame-ancestors 'self' https://portal.example.com",
            response.headers["content-security-policy"],
        )

    def test_unlisted_origin_is_rejected(self):
        app = FastAPI()

        @app.get("/")
        async def root():
            return {"ok": True}

        settings = EmbedSettings(
            enabled=True,
            allowed_origins=("https://portal.example.com",),
        )
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.allowed_origins),
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        app.add_middleware(
            CopilotOriginMiddleware,
            allowed_origins=settings.allowed_origins,
        )
        app.add_middleware(CopilotSecurityMiddleware, settings=settings)

        with TestClient(app) as client:
            response = client.get(
                "/",
                headers={"Origin": "https://attacker.example.com"},
            )

        self.assertEqual(403, response.status_code)
        self.assertNotIn("access-control-allow-origin", response.headers)

    def test_unlisted_websocket_origin_is_closed(self):
        app = FastAPI()

        @app.websocket("/ws/socket.io")
        async def websocket_endpoint(websocket: WebSocket):
            await websocket.accept()
            await websocket.send_text("connected")

        settings = EmbedSettings(
            enabled=True,
            allowed_origins=("https://portal.example.com",),
        )
        app.add_middleware(
            CopilotOriginMiddleware,
            allowed_origins=settings.allowed_origins,
        )

        with TestClient(app) as client:
            with self.assertRaises(WebSocketDisconnect) as context:
                with client.websocket_connect(
                    "/ws/socket.io",
                    headers={"Origin": "https://attacker.example.com"},
                ):
                    pass

        self.assertEqual(1008, context.exception.code)

    def test_same_origin_requests_remain_allowed(self):
        app = FastAPI()

        @app.get("/")
        async def root():
            return {"ok": True}

        app.add_middleware(
            CopilotOriginMiddleware,
            allowed_origins=("https://portal.example.com",),
        )

        with TestClient(app, base_url="https://chat.example.com") as client:
            response = client.get(
                "/",
                headers={"Origin": "https://chat.example.com"},
            )

        self.assertEqual(200, response.status_code)

    def test_disabled_app_is_unchanged(self):
        app = FastAPI()

        @app.post("/auth/jwt")
        async def jwt_auth():
            return Response(
                '{"route":"jwt"}',
                media_type="application/json",
                headers={"X-Frame-Options": "DENY"},
            )

        with TestClient(app) as client:
            response = client.post("/auth/jwt")

        self.assertEqual({"route": "jwt"}, response.json())
        self.assertEqual("DENY", response.headers["x-frame-options"])
        self.assertNotIn("content-security-policy", response.headers)


if __name__ == "__main__":
    unittest.main()
