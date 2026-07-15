import os
import time
import unittest
from unittest.mock import patch

import jwt
from chainlit.user import User
from starlette.responses import Response

from embed_auth import (
    COPILOT_SESSION_COOKIE,
    CopilotSessionStore,
    clear_copilot_session_cookie,
    create_embed_session_jwt,
    set_copilot_session_cookie,
)


TENANT_ID = "11111111-2222-3333-4444-555555555555"
OBJECT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


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


if __name__ == "__main__":
    unittest.main()
