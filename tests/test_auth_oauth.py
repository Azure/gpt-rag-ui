import importlib
import json
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from chainlit.auth import create_jwt, decode_jwt
from chainlit.config import config as chainlit_config
from chainlit.user import User

from auth_session import (
    OAUTH_SESSION_ID_KEY,
    OAUTH_SESSION_SOURCE,
    get_oauth_credential_store,
)


TENANT_ID = "11111111-2222-3333-4444-555555555555"
OBJECT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
PRINCIPAL_ID = f"{TENANT_ID}:{OBJECT_ID}"
CLIENT_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"


class OAuthCallbackTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.previous_oauth_callback = chainlit_config.code.oauth_callback
        self.previous_logout_callback = chainlit_config.code.on_logout
        self.store = get_oauth_credential_store()
        self.store.clear_for_testing()
        self.addCleanup(self.store.clear_for_testing)
        self.addCleanup(self._restore_callbacks)

    def _restore_callbacks(self):
        chainlit_config.code.oauth_callback = self.previous_oauth_callback
        chainlit_config.code.on_logout = self.previous_logout_callback

    async def test_callback_keeps_tokens_out_of_user_and_chainlit_cookie(self):
        environment = {
            "CHAINLIT_AUTH_SECRET": "test-secret-with-adequate-length",
            "OAUTH_AZURE_AD_CLIENT_ID": CLIENT_ID,
            "OAUTH_AZURE_AD_CLIENT_SECRET": "client-secret",
            "OAUTH_AZURE_AD_TENANT_ID": TENANT_ID,
            "OAUTH_AZURE_AD_SCOPES": (
                f"api://{CLIENT_ID}/user_impersonation,"
                "openid,profile,offline_access"
            ),
        }
        config_client = Mock()
        config_client.get.return_value = None
        config_client.get_value.side_effect = (
            lambda name, *args, **kwargs: environment.get(name)
        )
        dependencies_stub = SimpleNamespace(
            get_config=lambda: config_client,
        )
        with (
            patch.dict(os.environ, environment),
            patch.dict(sys.modules, {"dependencies": dependencies_stub}),
        ):
            auth_oauth = importlib.import_module("auth_oauth")
            token_result = {
                "access_token": "oauth-access-secret",
                "refresh_token": "oauth-refresh-secret",
                "id_token_claims": {
                    "tid": TENANT_ID,
                    "oid": OBJECT_ID,
                    "name": "Test User",
                    "preferred_username": "user@example.com",
                },
            }
            confidential_client = Mock()
            confidential_client.acquire_token_by_refresh_token.return_value = (
                token_result
            )

            with self.assertLogs(
                "gpt_rag_ui.auth_oauth",
                level="DEBUG",
            ) as captured_logs:
                with (
                    patch.object(
                        auth_oauth,
                        "get_env_var",
                        side_effect=lambda name, *args, **kwargs: environment.get(
                            name
                        ),
                    ),
                    patch.object(
                        auth_oauth,
                        "is_user_authorized",
                        return_value=True,
                    ),
                    patch.object(
                        auth_oauth.msal,
                        "ConfidentialClientApplication",
                        return_value=confidential_client,
                    ),
                ):
                    user = await auth_oauth.oauth_callback(
                        "azure-ad",
                        "provider-token",
                        {},
                        User(
                            identifier="provider-user",
                            metadata={
                                "refresh_token": "provider-refresh-token"
                            },
                        ),
                    )

            self.assertIsNotNone(user)
            self.assertEqual(PRINCIPAL_ID, user.identifier)
            self.assertEqual(OAUTH_SESSION_SOURCE, user.metadata["auth_source"])
            session_id = user.metadata[OAUTH_SESSION_ID_KEY]
            credential = await self.store.get(
                session_id,
                principal_id=PRINCIPAL_ID,
            )
            self.assertEqual("oauth-access-secret", credential.access_token)
            self.assertEqual("oauth-refresh-secret", credential.refresh_token)

            chainlit_token = create_jwt(user)
            cookie_user = decode_jwt(chainlit_token)
            serialized_user = json.dumps(cookie_user.to_dict())
            logged_output = "\n".join(captured_logs.output)
            for forbidden in (
                "oauth-access-secret",
                "oauth-refresh-secret",
                "provider-token",
                "provider-refresh-token",
                "access_token",
                "refresh_token",
            ):
                self.assertNotIn(forbidden, chainlit_token)
                self.assertNotIn(forbidden, serialized_user)
                if forbidden.endswith("-secret") or forbidden.endswith("-token"):
                    self.assertNotIn(forbidden, logged_output)


if __name__ == "__main__":
    unittest.main()
