import os
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import jwt
from chainlit.user import User
from fastapi import FastAPI
from starlette.responses import Response

from embed_auth import (
    COPILOT_SESSION_COOKIE,
    CopilotSessionStore,
    clear_copilot_session_cookie,
    create_embed_session_jwt,
    register_copilot_auth_routes,
    set_copilot_session_cookie,
)
from embed_config import EmbedSettings
from entra_token import EntraTokenError


TENANT_ID = "11111111-2222-3333-4444-555555555555"
OBJECT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
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
            metadata={
                "tenant_id": TENANT_ID,
                "object_id": OBJECT_ID,
                "principal_id": f"{TENANT_ID}:{OBJECT_ID}",
                "copilot_session_id": "opaque-id",
                "access_token": "entra-secret",
                "refresh_token": "refresh-secret",
            },
        )

        session_token = create_embed_session_jwt(user, expires_at)
        claims = jwt.decode(
            session_token,
            "test-secret-with-adequate-length",
            algorithms=["HS256"],
        )

        self.assertEqual(expires_at, claims["exp"])
        self.assertNotIn("access_token", str(claims))
        self.assertNotIn("refresh_token", str(claims))
        self.assertNotIn("copilot_session_id", str(claims))
        self.assertNotIn("opaque-id", str(claims))
        self.assertNotIn("entra-secret", str(claims))

    async def test_sensitive_tokens_are_not_in_session_repr(self):
        store = CopilotSessionStore(max_sessions=1, ttl_seconds=120)
        session = await store.replace(
            previous_session_id=None,
            access_token="entra-secret",
            claims={
                "tid": TENANT_ID,
                "oid": OBJECT_ID,
                "exp": int(time.time()) + 600,
                "groups": [GROUP_ID.upper(), "not-a-group-id"],
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
        self.assertEqual((GROUP_ID,), session.group_ids)
        self.assertEqual(
            [GROUP_ID],
            claims["metadata"]["client_group_names"],
        )
        self.assertNotIn("auth_source", claims["metadata"])
        self.assertNotIn("copilot_session_id", claims["metadata"])
        self.assertNotIn("access_token", claims["metadata"])
        self.assertNotIn("refresh_token", claims["metadata"])

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
        invalidated = AsyncMock()
        store = CopilotSessionStore(max_sessions=5, ttl_seconds=120)
        store.set_invalidation_handler(invalidated)
        claims = {
            "tid": TENANT_ID,
            "oid": OBJECT_ID,
            "exp": int(time.time()) + 600,
        }
        first = await store.replace(
            previous_session_id=None,
            access_token="first-token",
            claims=claims,
            display_name="User",
            principal_name="user@example.com",
        )
        self.assertTrue(
            await store.bind_connection(
                session_id=first.session_id,
                socket_id="socket-one",
                chainlit_session_id="chainlit-one",
            )
        )

        second = await store.replace(
            previous_session_id=None,
            access_token="second-token",
            claims=claims,
            display_name="User",
            principal_name="user@example.com",
        )

        self.assertIsNone(await store.get(first.session_id))
        self.assertEqual(second, await store.get(second.session_id))
        invalidation = invalidated.await_args.args[0]
        self.assertEqual("principal_replaced", invalidation.reason)
        self.assertEqual(("socket-one",), invalidation.socket_ids)
        self.assertEqual(("chainlit-one",), invalidation.chainlit_session_ids)
        self.assertEqual(1, await store.count())

    async def test_capacity_evicts_and_invalidates_unique_principal(self):
        invalidated = AsyncMock()
        store = CopilotSessionStore(max_sessions=1, ttl_seconds=120)
        store.set_invalidation_handler(invalidated)
        first = await store.replace(
            previous_session_id=None,
            access_token="first-token",
            claims={
                "tid": TENANT_ID,
                "oid": OBJECT_ID,
                "exp": int(time.time()) + 600,
            },
            display_name="First",
            principal_name="first@example.com",
        )
        await store.bind_connection(
            session_id=first.session_id,
            socket_id="socket-one",
            chainlit_session_id="chainlit-one",
        )

        second = await store.replace(
            previous_session_id=None,
            access_token="second-token",
            claims={
                "tid": TENANT_ID,
                "oid": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
                "exp": int(time.time()) + 600,
            },
            display_name="Second",
            principal_name="second@example.com",
        )

        self.assertIsNone(await store.get(first.session_id))
        self.assertEqual(second, await store.get(second.session_id))
        invalidation = invalidated.await_args.args[0]
        self.assertEqual("capacity", invalidation.reason)
        self.assertEqual(("socket-one",), invalidation.socket_ids)

    async def test_logout_invalidates_bound_connections(self):
        invalidated = AsyncMock()
        store = CopilotSessionStore(max_sessions=1, ttl_seconds=120)
        store.set_invalidation_handler(invalidated)
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
        await store.bind_connection(
            session_id=session.session_id,
            socket_id="socket",
            chainlit_session_id="chainlit",
        )

        await store.delete(session.session_id)

        self.assertIsNone(await store.get(session.session_id))
        invalidation = invalidated.await_args.args[0]
        self.assertEqual("logout", invalidation.reason)
        self.assertEqual(("socket",), invalidation.socket_ids)

    async def test_scheduled_expiry_invalidates_bound_connections(self):
        invalidated = AsyncMock()
        store = CopilotSessionStore(max_sessions=1, ttl_seconds=1)
        store.set_invalidation_handler(invalidated)
        now = int(time.time())
        with patch("embed_auth.time.time", return_value=now):
            session = await store.replace(
                previous_session_id=None,
                access_token="entra-secret",
                claims={
                    "tid": TENANT_ID,
                    "oid": OBJECT_ID,
                    "exp": now + 600,
                },
                display_name="User",
                principal_name="",
            )
        await store.bind_connection(
            session_id=session.session_id,
            socket_id="socket",
            chainlit_session_id="chainlit",
        )

        with patch("embed_auth.time.time", return_value=now + 2):
            await store._expire_if_due(session.session_id)

        self.assertIsNone(await store.get(session.session_id))
        invalidation = invalidated.await_args.args[0]
        self.assertEqual("expired", invalidation.reason)
        self.assertEqual(("socket",), invalidation.socket_ids)
        self.assertEqual(("chainlit",), invalidation.chainlit_session_ids)

    async def test_per_session_connection_admission_is_bounded(self):
        store = CopilotSessionStore(
            max_sessions=1,
            ttl_seconds=120,
            max_connections_per_session=1,
        )
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
        self.assertTrue(
            await store.bind_connection(
                session_id=session.session_id,
                socket_id="socket-one",
                chainlit_session_id="chainlit-one",
            )
        )
        self.assertFalse(
            await store.bind_connection(
                session_id=session.session_id,
                socket_id="socket-two",
                chainlit_session_id="chainlit-two",
            )
        )

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

    async def test_bootstrap_replaces_then_logout_invalidates_session(self):
        settings = EmbedSettings(
            enabled=True,
            ui_origin="https://chat.example.com",
            allowed_origins=("https://portal.example.com",),
            cookie_samesite="none",
            max_sessions=10,
            session_ttl_seconds=120,
        )
        invalidated = []

        async def on_invalidate(invalidation):
            invalidated.append(invalidation.session.session_id)

        sessions = CopilotSessionStore(max_sessions=10, ttl_seconds=120)
        sessions.set_invalidation_handler(on_invalidate)
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
                headers={"Authorization": "Bearer bootstrap-token-one"},
            )
            first_session_id = client.cookies.get(COPILOT_SESSION_COOKIE)
            second = await client.post(
                "/copilot/auth/bootstrap",
                headers={"Authorization": "Bearer bootstrap-token-two"},
            )
            second_session_id = client.cookies.get(COPILOT_SESSION_COOKIE)
            logout = await client.post("/copilot/auth/logout")

        self.assertEqual(200, first.status_code)
        self.assertEqual(200, second.status_code)
        self.assertNotEqual(first_session_id, second_session_id)
        self.assertIsNone(await sessions.get(first_session_id))
        self.assertIsNone(await sessions.get(second_session_id))
        self.assertIn(first_session_id, invalidated)
        self.assertIn(second_session_id, invalidated)
        self.assertEqual(200, logout.status_code)
        self.assertIn("Max-Age=0", logout.headers["set-cookie"])
        serialized = first.text + second.text
        set_cookies = (
            first.headers["set-cookie"] + second.headers["set-cookie"]
        )
        self.assertNotIn("bootstrap-token-one", serialized + set_cookies)
        self.assertNotIn("bootstrap-token-two", serialized + set_cookies)

    async def test_failed_rebootstrap_preserves_valid_current_session(self):
        settings = EmbedSettings(
            enabled=True,
            ui_origin="https://chat.example.com",
            allowed_origins=("https://portal.example.com",),
            cookie_samesite="none",
            max_sessions=10,
            session_ttl_seconds=120,
        )
        invalidated = AsyncMock()
        sessions = CopilotSessionStore(max_sessions=10, ttl_seconds=120)
        sessions.set_invalidation_handler(invalidated)
        validator = AsyncMock(
            side_effect=[
                {
                    "tid": TENANT_ID,
                    "oid": OBJECT_ID,
                    "exp": int(time.time()) + 600,
                    "preferred_username": "user@example.com",
                },
                EntraTokenError("invalid"),
            ]
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
                headers={"Authorization": "Bearer valid-token"},
            )
            session_id = client.cookies.get(COPILOT_SESSION_COOKIE)
            failed = await client.post(
                "/copilot/auth/bootstrap",
                headers={"Authorization": "Bearer invalid-token"},
            )

        self.assertEqual(200, first.status_code)
        self.assertEqual(401, failed.status_code)
        self.assertEqual(
            session_id,
            client.cookies.get(COPILOT_SESSION_COOKIE),
        )
        self.assertIsNotNone(await sessions.get(session_id))
        invalidated.assert_not_awaited()
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
        invalidated = AsyncMock()
        sessions = CopilotSessionStore(max_sessions=10, ttl_seconds=120)
        sessions.set_invalidation_handler(invalidated)
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
                headers={"Authorization": "Bearer allowed-token"},
            )
            first_session_id = client.cookies.get(COPILOT_SESSION_COOKIE)
            denied = await client.post(
                "/copilot/auth/bootstrap",
                headers={"Authorization": "Bearer denied-token"},
            )

        self.assertEqual(200, first.status_code)
        self.assertEqual(403, denied.status_code)
        self.assertIsNone(client.cookies.get(COPILOT_SESSION_COOKIE))
        self.assertIsNone(await sessions.get(first_session_id))
        self.assertEqual(
            first_session_id,
            invalidated.await_args.args[0].session.session_id,
        )

    async def test_bootstrap_rejects_missing_duplicate_and_unavailable_auth(self):
        settings = EmbedSettings(
            enabled=True,
            ui_origin="https://chat.example.com",
            allowed_origins=("https://portal.example.com",),
            cookie_samesite="none",
            max_sessions=10,
            session_ttl_seconds=120,
        )

        async def request(validator, headers=None):
            app = FastAPI()
            register_copilot_auth_routes(
                app,
                settings=settings,
                sessions=CopilotSessionStore(
                    max_sessions=10,
                    ttl_seconds=120,
                ),
                validator=SimpleNamespace(validate=validator),
                config=FakeConfig(),
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

        self.assertEqual(401, (await request(AsyncMock())).status_code)
        unavailable = await request(
            AsyncMock(
                side_effect=httpx.ConnectError(
                    "unavailable",
                    request=httpx.Request(
                        "GET",
                        "https://login.example",
                    ),
                )
            ),
            headers={"Authorization": "Bearer token"},
        )
        self.assertEqual(503, unavailable.status_code)
        duplicate = await request(
            AsyncMock(),
            headers=[
                ("Authorization", "Bearer token-one"),
                ("Authorization", "Bearer token-two"),
            ],
        )
        self.assertEqual(401, duplicate.status_code)


if __name__ == "__main__":
    unittest.main()
