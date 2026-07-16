import os
import time
import unittest
from unittest.mock import patch

from chainlit.auth import create_jwt, decode_jwt
from chainlit.user import User
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse

from auth_session import (
    ChainlitAuthContextMiddleware,
    OAUTH_SESSION_ID_KEY,
    OAUTH_SESSION_SOURCE,
    OAuthCredentialStore,
    current_user_metadata,
    delete_current_oauth_credential,
    get_oauth_credential_store,
)
from embed_auth import resolve_access_token


TENANT_ID = "11111111-2222-3333-4444-555555555555"
OBJECT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
PRINCIPAL_ID = f"{TENANT_ID}:{OBJECT_ID}"


class AuthSessionTests(unittest.TestCase):
    def setUp(self):
        self.secret_patch = patch.dict(
            os.environ,
            {"CHAINLIT_AUTH_SECRET": "test-secret-with-adequate-length"},
        )
        self.secret_patch.start()
        self.addCleanup(self.secret_patch.stop)
        self.store = get_oauth_credential_store()
        self.store.clear_for_testing()
        self.addCleanup(self.store.clear_for_testing)

    def test_oauth_tokens_stay_server_side_and_logout_removes_them(self):
        observed_tokens = []
        app = FastAPI()
        app.add_middleware(ChainlitAuthContextMiddleware)

        @app.post("/login")
        async def login():
            credential = await self.store.replace(
                previous_session_id=None,
                principal_id=PRINCIPAL_ID,
                access_token="oauth-access-secret",
                refresh_token="oauth-refresh-secret",
                ttl_seconds=3600,
            )
            oauth_user = User(
                identifier=PRINCIPAL_ID,
                metadata={
                    "auth_source": OAUTH_SESSION_SOURCE,
                    OAUTH_SESSION_ID_KEY: credential.session_id,
                    "tenant_id": TENANT_ID,
                    "object_id": OBJECT_ID,
                    "principal_id": PRINCIPAL_ID,
                },
            )
            response = JSONResponse({"success": True})
            response.set_cookie("access_token", create_jwt(oauth_user))
            return response

        @app.get("/protected")
        async def protected():
            safe_profile = {
                "tenant_id": TENANT_ID,
                "object_id": OBJECT_ID,
                "principal_id": PRINCIPAL_ID,
            }
            observed_tokens.append(await resolve_access_token(safe_profile))
            return {"ok": True}

        @app.post("/logout")
        async def logout():
            await delete_current_oauth_credential()
            return {"success": True}

        with TestClient(app) as client:
            self.assertEqual(200, client.post("/login").status_code)
            chainlit_token = client.cookies.get("access_token")
            decoded_user = decode_jwt(chainlit_token)
            serialized_metadata = str(decoded_user.metadata)

            response = client.get("/protected")
            self.assertEqual(200, client.post("/logout").status_code)
            expired_response = client.get("/protected")

        self.assertEqual(200, response.status_code)
        self.assertEqual({"ok": True}, response.json())
        self.assertEqual(
            ["oauth-access-secret", None],
            observed_tokens,
        )
        self.assertNotIn("oauth-access-secret", response.text)
        self.assertNotIn("oauth-refresh-secret", response.text)
        self.assertNotIn("oauth-access-secret", serialized_metadata)
        self.assertNotIn("oauth-refresh-secret", serialized_metadata)
        self.assertNotIn("access_token", decoded_user.metadata)
        self.assertNotIn("refresh_token", decoded_user.metadata)
        self.assertEqual({"ok": True}, expired_response.json())
        self.assertIsNone(current_user_metadata())

    def test_oauth_credential_store_is_bounded_pruned_and_redacted(self):
        async def exercise_store():
            store = OAuthCredentialStore(max_credentials=2)
            expired = await store.replace(
                previous_session_id=None,
                principal_id=PRINCIPAL_ID,
                access_token="expired-access-secret",
                refresh_token="expired-refresh-secret",
                ttl_seconds=1,
            )
            active = await store.replace(
                previous_session_id=None,
                principal_id=PRINCIPAL_ID,
                access_token="active-access-secret",
                refresh_token="active-refresh-secret",
                ttl_seconds=3600,
            )
            replacement = await store.replace(
                previous_session_id=expired.session_id,
                principal_id=PRINCIPAL_ID,
                access_token="replacement-access-secret",
                refresh_token="replacement-refresh-secret",
                ttl_seconds=3600,
            )

            self.assertEqual(2, await store.count())
            self.assertIsNone(
                await store.get(
                    expired.session_id,
                    principal_id=PRINCIPAL_ID,
                )
            )
            self.assertIsNotNone(
                await store.get(
                    active.session_id,
                    principal_id=PRINCIPAL_ID,
                )
            )
            self.assertNotIn("active-access-secret", repr(active))
            self.assertNotIn("active-refresh-secret", repr(active))
            self.assertNotIn("replacement-access-secret", repr(replacement))

        import asyncio

        asyncio.run(exercise_store())


if __name__ == "__main__":
    unittest.main()
