import asyncio
import os
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import jwt
from chainlit.user import User
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import Response

from embed_config import EmbedSettings
from embed_auth import (
    COPILOT_SESSION_COOKIE,
    CopilotSessionStore,
    clear_copilot_session_cookie,
    create_embed_session_jwt,
    register_copilot_auth_routes,
    session_id_from_request,
    set_copilot_session_cookie,
)
from embed_security import CopilotRequestMiddleware
from entra_token import EntraTokenError


TENANT_ID = "11111111-2222-3333-4444-555555555555"
OBJECT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
PRINCIPAL_ID = f"{TENANT_ID}:{OBJECT_ID}"


class FakeConfig:
    def __init__(self, values=None):
        self.values = values or {}

    def get(self, key, default=None, type=str):
        value = self.values.get(key, default)
        return type(value) if value is not None and type is not None else value


class EmbedAuthTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.secret_patch = patch.dict(
            os.environ,
            {"CHAINLIT_AUTH_SECRET": "test-secret-with-adequate-length"},
        )
        self.secret_patch.start()
        self.addCleanup(self.secret_patch.stop)

    def test_internal_chainlit_jwt_contains_no_entra_token(self):
        expires_at = int(time.time()) + 120
        user = User(
            identifier=f"{TENANT_ID}:{OBJECT_ID}",
            metadata={"copilot_session_id": "opaque-id"},
        )

        session_token = create_embed_session_jwt(user, expires_at)
        claims = jwt.decode(
            session_token,
            "test-secret-with-adequate-length",
            algorithms=["HS256"],
        )

        self.assertEqual(expires_at, claims["exp"])
        self.assertNotIn("access_token", str(claims))

    async def test_sensitive_tokens_are_not_in_session_repr(self):
        store = CopilotSessionStore(max_sessions=1, ttl_seconds=120)
        session = await store.replace(
            previous_session_id=None,
            access_token="entra-secret",
            claims={
                "tid": TENANT_ID,
                "oid": OBJECT_ID,
                "exp": int(time.time()) + 600,
            },
            display_name="User",
            principal_name="user@example.com",
        )
        representation = repr(session)
        self.assertNotIn("entra-secret", representation)
        self.assertNotIn(session.chainlit_token, representation)

        claims = jwt.decode(
            session.chainlit_token,
            "test-secret-with-adequate-length",
            algorithms=["HS256"],
        )
        self.assertEqual(
            f"{TENANT_ID}:{OBJECT_ID}",
            claims["identifier"],
        )
        self.assertEqual(
            OBJECT_ID,
            claims["metadata"]["client_principal_id"],
        )

    async def test_store_caps_expiry_and_replaces_previous_session(self):
        store = CopilotSessionStore(max_sessions=2, ttl_seconds=120)
        claims = {
            "tid": TENANT_ID,
            "oid": OBJECT_ID,
            "exp": int(time.time()) + 600,
        }
        first = await store.replace(
            previous_session_id=None,
            access_token="entra-one",
            claims=claims,
            display_name="User",
            principal_name="user@example.com",
        )
        second = await store.replace(
            previous_session_id=first.session_id,
            access_token="entra-two",
            claims=claims,
            display_name="User",
            principal_name="user@example.com",
        )

        self.assertIsNone(await store.get(first.session_id))
        self.assertEqual("entra-two", (await store.get(second.session_id)).access_token)
        self.assertLessEqual(second.expires_at, int(time.time()) + 120)
        self.assertNotEqual(first.session_id, second.session_id)

    async def test_store_is_bounded_and_rejects_expired_tokens(self):
        store = CopilotSessionStore(max_sessions=1, ttl_seconds=120)
        claims = {
            "tid": TENANT_ID,
            "oid": OBJECT_ID,
            "exp": int(time.time()) + 600,
        }
        first = await store.replace(
            previous_session_id=None,
            access_token="one",
            claims=claims,
            display_name="User",
            principal_name="",
        )
        second = await store.replace(
            previous_session_id=None,
            access_token="two",
            claims=claims,
            display_name="User",
            principal_name="",
        )
        self.assertIsNone(await store.get(first.session_id))
        self.assertIsNotNone(await store.get(second.session_id))
        self.assertEqual(1, await store.count())

        with self.assertRaisesRegex(ValueError, "expired"):
            await store.replace(
                previous_session_id=None,
                access_token="expired",
                claims={**claims, "exp": int(time.time()) - 1},
                display_name="User",
                principal_name="",
            )

    async def test_cookie_less_rebootstrap_replaces_same_principal(self):
        invalidated = []

        async def on_invalidate(session_id):
            invalidated.append(session_id)

        store = CopilotSessionStore(
            max_sessions=5,
            ttl_seconds=120,
            on_invalidate=on_invalidate,
        )
        claims = {
            "tid": TENANT_ID,
            "oid": OBJECT_ID,
            "exp": int(time.time()) + 600,
        }
        first = await store.replace(
            previous_session_id=None,
            access_token="first",
            claims=claims,
            display_name="User",
            principal_name="user@example.com",
        )
        second = await store.replace(
            previous_session_id=None,
            access_token="second",
            claims=claims,
            display_name="User",
            principal_name="user@example.com",
        )

        self.assertIsNone(await store.get(first.session_id))
        self.assertEqual(second, await store.get(second.session_id))
        self.assertIn(first.session_id, invalidated)
        self.assertEqual(1, await store.count())

    async def test_stale_account_switch_replaces_latest_successor(self):
        invalidated = []

        async def on_invalidate(session_id):
            invalidated.append(session_id)

        store = CopilotSessionStore(
            max_sessions=5,
            ttl_seconds=120,
            on_invalidate=on_invalidate,
        )
        base_claims = {
            "tid": TENANT_ID,
            "exp": int(time.time()) + 600,
        }
        original = await store.replace(
            previous_session_id=None,
            access_token="original",
            claims={**base_claims, "oid": OBJECT_ID},
            display_name="Original",
            principal_name="original@example.com",
        )
        first_successor = await store.replace(
            previous_session_id=original.session_id,
            access_token="first",
            claims={
                **base_claims,
                "oid": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
            },
            display_name="First",
            principal_name="first@example.com",
        )
        latest = await store.replace(
            previous_session_id=original.session_id,
            access_token="latest",
            claims={
                **base_claims,
                "oid": "cccccccc-dddd-eeee-ffff-000000000000",
            },
            display_name="Latest",
            principal_name="latest@example.com",
        )
        for index in range(20):
            latest = await store.replace(
                previous_session_id=original.session_id,
                access_token=f"latest-{index}",
                claims={
                    **base_claims,
                    "oid": (
                        "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
                        if index % 2
                        else "cccccccc-dddd-eeee-ffff-000000000000"
                    ),
                },
                display_name="Latest",
                principal_name="latest@example.com",
            )

        self.assertIsNone(await store.get(first_successor.session_id))
        self.assertEqual(latest, await store.get(latest.session_id))
        self.assertIn(first_successor.session_id, invalidated)
        self.assertEqual(1, await store.count())

        await store.delete(first_successor.session_id)

        self.assertIsNone(await store.get(latest.session_id))
        self.assertIn(latest.session_id, invalidated)
        self.assertEqual(0, await store.count())

    async def test_cookie_is_opaque_http_only_and_secure(self):
        store = CopilotSessionStore(max_sessions=1, ttl_seconds=120)
        session = await store.replace(
            previous_session_id=None,
            access_token="entra-secret",
            claims={
                "tid": TENANT_ID,
                "oid": OBJECT_ID,
                "exp": int(time.time()) + 600,
            },
            display_name="User",
            principal_name="",
        )
        response = Response()
        set_copilot_session_cookie(response, session, same_site="none")
        cookie = response.headers["set-cookie"]
        self.assertIn(f"{COPILOT_SESSION_COOKIE}={session.session_id}", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=none", cookie)
        self.assertNotIn("entra-secret", cookie)

        clear_response = Response()
        clear_copilot_session_cookie(clear_response, same_site="none")
        self.assertIn("Max-Age=0", clear_response.headers["set-cookie"])

    async def test_store_invalidation_covers_replacement_eviction_and_expiry(self):
        invalidated = []
        expired = asyncio.Event()

        async def on_invalidate(session_id):
            invalidated.append(session_id)
            expired.set()

        store = CopilotSessionStore(
            max_sessions=1,
            ttl_seconds=1,
            on_invalidate=on_invalidate,
        )
        claims = {
            "tid": TENANT_ID,
            "oid": OBJECT_ID,
            "exp": int(time.time()) + 30,
        }
        first = await store.replace(
            previous_session_id=None,
            access_token="one",
            claims=claims,
            display_name="User",
            principal_name="",
        )
        second = await store.replace(
            previous_session_id=first.session_id,
            access_token="two",
            claims=claims,
            display_name="User",
            principal_name="",
        )
        self.assertIn(first.session_id, invalidated)

        third = await store.replace(
            previous_session_id=None,
            access_token="three",
            claims={
                **claims,
                "oid": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
            },
            display_name="User",
            principal_name="",
        )
        self.assertIn(second.session_id, invalidated)
        expired.clear()
        await asyncio.wait_for(expired.wait(), timeout=2)
        self.assertIn(third.session_id, invalidated)
        self.assertIsNone(await store.get(third.session_id))

    async def test_bootstrap_logout_and_error_contract(self):
        settings = EmbedSettings(
            enabled=True,
            ui_origin="https://chat.example.com",
            allowed_origins=("https://portal.example.com",),
            cookie_samesite="none",
            max_sessions=10,
            session_ttl_seconds=120,
        )
        invalidated = []

        async def on_invalidate(session_id):
            invalidated.append(session_id)

        sessions = CopilotSessionStore(
            max_sessions=10,
            ttl_seconds=120,
            on_invalidate=on_invalidate,
        )
        validator = AsyncMock(
            return_value={
                "tid": TENANT_ID,
                "oid": OBJECT_ID,
                "exp": int(time.time()) + 600,
                "preferred_username": "user@example.com",
                "name": "Portal User",
            }
        )
        app = FastAPI()
        register_copilot_auth_routes(
            app,
            settings=settings,
            sessions=sessions,
            validator=SimpleNamespace(validate=validator),
            config=FakeConfig(),
        )
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://chat.example.com",
        ) as client:
            first = await client.post(
                "/copilot/auth/bootstrap",
                headers={"Authorization": "Bearer entra-one"},
            )
            first_session_id = client.cookies.get(COPILOT_SESSION_COOKIE)
            second = await client.post(
                "/copilot/auth/bootstrap",
                headers={"Authorization": "Bearer entra-two"},
            )
            second_session_id = client.cookies.get(COPILOT_SESSION_COOKIE)
            logout = await client.post("/copilot/auth/logout")

        self.assertEqual(200, first.status_code)
        self.assertEqual(200, second.status_code)
        self.assertTrue(first.json()["expiresAt"])
        self.assertNotEqual(first_session_id, second_session_id)
        self.assertIsNone(await sessions.get(first_session_id))
        self.assertIsNone(await sessions.get(second_session_id))
        self.assertIn(first_session_id, invalidated)
        self.assertIn(second_session_id, invalidated)
        self.assertEqual(200, logout.status_code)
        self.assertIn("Max-Age=0", logout.headers["set-cookie"])
        self.assertNotIn("entra-one", first.text + first.headers["set-cookie"])
        self.assertNotIn("entra-two", second.text + second.headers["set-cookie"])

    async def test_failed_rebootstrap_preserves_valid_current_session(self):
        settings = EmbedSettings(
            enabled=True,
            ui_origin="https://chat.example.com",
            allowed_origins=("https://portal.example.com",),
            cookie_samesite="none",
            max_sessions=10,
            session_ttl_seconds=120,
        )
        invalidated = []

        async def on_invalidate(session_id):
            invalidated.append(session_id)

        sessions = CopilotSessionStore(
            max_sessions=10,
            ttl_seconds=120,
            on_invalidate=on_invalidate,
        )
        valid_claims = {
            "tid": TENANT_ID,
            "oid": OBJECT_ID,
            "exp": int(time.time()) + 600,
            "preferred_username": "user@example.com",
        }
        validator = AsyncMock(
            side_effect=[valid_claims, EntraTokenError("invalid")]
        )
        app = FastAPI()
        register_copilot_auth_routes(
            app,
            settings=settings,
            sessions=sessions,
            validator=SimpleNamespace(validate=validator),
            config=FakeConfig(),
        )
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://chat.example.com",
        ) as client:
            first = await client.post(
                "/copilot/auth/bootstrap",
                headers={"Authorization": "Bearer " + "token-one"},
            )
            session_id = client.cookies.get(COPILOT_SESSION_COOKIE)
            failed = await client.post(
                "/copilot/auth/bootstrap",
                headers={"Authorization": "Bearer " + "invalid-token"},
            )
            current_cookie = client.cookies.get(COPILOT_SESSION_COOKIE)

        self.assertEqual(200, first.status_code)
        self.assertEqual(401, failed.status_code)
        self.assertEqual(session_id, current_cookie)
        self.assertIsNotNone(await sessions.get(session_id))
        self.assertNotIn(session_id, invalidated)
        self.assertNotIn("set-cookie", failed.headers)

    async def test_denied_account_switch_clears_previous_session(self):
        settings = EmbedSettings(
            enabled=True,
            ui_origin="https://chat.example.com",
            allowed_origins=("https://portal.example.com",),
            cookie_samesite="none",
            max_sessions=10,
            session_ttl_seconds=120,
        )
        invalidated = []

        async def on_invalidate(session_id):
            invalidated.append(session_id)

        sessions = CopilotSessionStore(
            max_sessions=10,
            ttl_seconds=120,
            on_invalidate=on_invalidate,
        )
        validator = AsyncMock(
            side_effect=[
                {
                    "tid": TENANT_ID,
                    "oid": OBJECT_ID,
                    "exp": int(time.time()) + 600,
                    "preferred_username": "allowed@example.com",
                },
                {
                    "tid": TENANT_ID,
                    "oid": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
                    "exp": int(time.time()) + 600,
                    "preferred_username": "denied@example.com",
                },
            ]
        )
        app = FastAPI()
        register_copilot_auth_routes(
            app,
            settings=settings,
            sessions=sessions,
            validator=SimpleNamespace(validate=validator),
            config=FakeConfig(
                {"ALLOWED_USER_NAMES": "allowed@example.com"}
            ),
        )
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://chat.example.com",
        ) as client:
            first = await client.post(
                "/copilot/auth/bootstrap",
                headers={"Authorization": "Bearer " + "token-one"},
            )
            first_session_id = client.cookies.get(COPILOT_SESSION_COOKIE)
            denied = await client.post(
                "/copilot/auth/bootstrap",
                headers={"Authorization": "Bearer " + "token-two"},
            )
            current_cookie = client.cookies.get(COPILOT_SESSION_COOKIE)

        self.assertEqual(200, first.status_code)
        self.assertEqual(403, denied.status_code)
        self.assertIsNone(current_cookie)
        self.assertIsNone(await sessions.get(first_session_id))
        self.assertIn(first_session_id, invalidated)

    async def test_bootstrap_negative_responses(self):
        settings = EmbedSettings(
            enabled=True,
            ui_origin="https://chat.example.com",
            allowed_origins=("https://portal.example.com",),
            cookie_samesite="none",
            max_sessions=10,
            session_ttl_seconds=120,
        )

        async def run_request(validator, config=None, headers=None):
            app = FastAPI()
            sessions = CopilotSessionStore(
                max_sessions=10,
                ttl_seconds=120,
            )
            register_copilot_auth_routes(
                app,
                settings=settings,
                sessions=sessions,
                validator=SimpleNamespace(validate=validator),
                config=config or FakeConfig(),
            )
            transport = httpx.ASGITransport(
                app=app,
                raise_app_exceptions=False,
            )
            async with httpx.AsyncClient(
                transport=transport,
                base_url="https://chat.example.com",
            ) as client:
                return await client.post(
                    "/copilot/auth/bootstrap",
                    headers=headers,
                )

        missing = await run_request(AsyncMock())
        self.assertEqual(401, missing.status_code)

        invalid = await run_request(
            AsyncMock(side_effect=EntraTokenError("invalid")),
            headers={"Authorization": "Bearer invalid"},
        )
        self.assertEqual(401, invalid.status_code)

        unavailable = await run_request(
            AsyncMock(
                side_effect=httpx.ConnectError(
                    "unavailable",
                    request=httpx.Request("GET", "https://login.example"),
                )
            ),
            headers={"Authorization": "Bearer token"},
        )
        self.assertEqual(503, unavailable.status_code)

        claims = {
            "tid": TENANT_ID,
            "oid": OBJECT_ID,
            "exp": int(time.time()) + 600,
            "preferred_username": "user@example.com",
        }
        denied = await run_request(
            AsyncMock(return_value=claims),
            config=FakeConfig({"ALLOWED_USER_NAMES": "other@example.com"}),
            headers={"Authorization": "Bearer token"},
        )
        self.assertEqual(403, denied.status_code)

        duplicate = await run_request(
            AsyncMock(return_value=claims),
            headers=[
                ("Authorization", "Bearer token-one"),
                ("Authorization", "Bearer token-two"),
            ],
        )
        self.assertEqual(401, duplicate.status_code)

    def test_duplicate_or_malformed_session_cookie_is_rejected(self):
        for headers in (
            [
                (
                    b"cookie",
                    (
                        f"{COPILOT_SESSION_COOKIE}={'a' * 43}; "
                        f"{COPILOT_SESSION_COOKIE}={'b' * 43}"
                    ).encode(),
                )
            ],
            [(b"cookie", COPILOT_SESSION_COOKIE.encode())],
            [
                (
                    b"cookie",
                    f"{COPILOT_SESSION_COOKIE}={'a' * 43}".encode(),
                ),
                (
                    b"cookie",
                    f"{COPILOT_SESSION_COOKIE}={'b' * 43}".encode(),
                ),
            ],
        ):
            with self.subTest(headers=headers):
                request = Request(
                    {
                        "type": "http",
                        "method": "GET",
                        "path": "/",
                        "headers": headers,
                    }
                )
                self.assertIsNone(session_id_from_request(request))

    async def test_auth_errors_and_rate_limit_are_cors_visible(self):
        portal = "https://portal.example.com"
        settings = EmbedSettings(
            enabled=True,
            ui_origin="https://chat.example.com",
            allowed_origins=(portal,),
            max_sessions=10,
            session_ttl_seconds=120,
            bootstrap_rate_limit_per_minute=2,
        )
        sessions = CopilotSessionStore(max_sessions=10, ttl_seconds=120)
        claims = {
            "tid": TENANT_ID,
            "oid": OBJECT_ID,
            "exp": int(time.time()) + 600,
            "preferred_username": "denied@example.com",
        }
        app = FastAPI()
        register_copilot_auth_routes(
            app,
            settings=settings,
            sessions=sessions,
            validator=SimpleNamespace(
                validate=AsyncMock(return_value=claims)
            ),
            config=FakeConfig(
                {"ALLOWED_USER_NAMES": "allowed@example.com"}
            ),
        )
        app.add_middleware(
            CopilotRequestMiddleware,
            settings=settings,
            sessions=sessions,
        )
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[portal],
            allow_credentials=True,
            allow_methods=["POST"],
            allow_headers=["Authorization", "Content-Type"],
        )
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://chat.example.com",
        ) as client:
            unauthorized = await client.post(
                "/copilot/auth/bootstrap",
                headers={"Origin": portal},
            )
            forbidden = await client.post(
                "/copilot/auth/bootstrap",
                headers={
                    "Origin": portal,
                    "Authorization": "Bearer denied",
                },
            )
            limited = await client.post(
                "/copilot/auth/bootstrap",
                headers={
                    "Origin": portal,
                    "Authorization": "Bearer denied",
                },
            )

        self.assertEqual(401, unauthorized.status_code)
        self.assertEqual(403, forbidden.status_code)
        self.assertEqual(429, limited.status_code)
        for response in (unauthorized, forbidden, limited):
            self.assertEqual(
                portal,
                response.headers["access-control-allow-origin"],
            )
            self.assertEqual("Origin", response.headers["vary"])
        self.assertGreaterEqual(int(limited.headers["retry-after"]), 1)

    async def test_rate_limit_preserves_current_session(self):
        portal = "https://portal.example.com"
        settings = EmbedSettings(
            enabled=True,
            ui_origin="https://chat.example.com",
            allowed_origins=(portal,),
            max_sessions=10,
            session_ttl_seconds=120,
            bootstrap_rate_limit_per_minute=1,
        )
        sessions = CopilotSessionStore(max_sessions=10, ttl_seconds=120)
        claims = {
            "tid": TENANT_ID,
            "oid": OBJECT_ID,
            "exp": int(time.time()) + 600,
            "preferred_username": "user@example.com",
        }
        validator = AsyncMock(return_value=claims)
        app = FastAPI()
        register_copilot_auth_routes(
            app,
            settings=settings,
            sessions=sessions,
            validator=SimpleNamespace(validate=validator),
            config=FakeConfig(),
        )
        app.add_middleware(
            CopilotRequestMiddleware,
            settings=settings,
            sessions=sessions,
        )
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://chat.example.com",
        ) as client:
            first = await client.post(
                "/copilot/auth/bootstrap",
                headers={
                    "Origin": portal,
                    "Authorization": "Bearer valid",
                },
            )
            session_id = client.cookies.get(COPILOT_SESSION_COOKIE)
            limited = await client.post(
                "/copilot/auth/bootstrap",
                headers={
                    "Origin": portal,
                    "Authorization": "Bearer another",
                },
            )

        self.assertEqual(200, first.status_code)
        self.assertEqual(429, limited.status_code)
        self.assertIsNotNone(await sessions.get(session_id))
        validator.assert_awaited_once_with("valid")


if __name__ == "__main__":
    unittest.main()
