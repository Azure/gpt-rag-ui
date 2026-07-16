import json
import os
import unittest
from unittest.mock import patch

from chainlit.auth import authenticate_user, create_jwt
from chainlit.user import User

import datalayer
from datalayer import OrchestratorDataLayer


TENANT_ID = "11111111-2222-3333-4444-555555555555"
OBJECT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
PRINCIPAL_ID = f"{TENANT_ID}:{OBJECT_ID}"


def user_with_metadata(**metadata) -> User:
    return User(
        identifier=PRINCIPAL_ID,
        display_name="Test User",
        metadata={
            "authorized": True,
            "tenant_id": TENANT_ID,
            "object_id": OBJECT_ID,
            "principal_id": PRINCIPAL_ID,
            "client_principal_id": OBJECT_ID,
            "client_principal_name": "user@example.com",
            **metadata,
        },
    )


class DataLayerUserCacheTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        datalayer._users.clear()
        self.addCleanup(datalayer._users.clear)
        self.layer = OrchestratorDataLayer()

    async def test_oauth_first_then_copilot_never_reuses_auth_state(self):
        oauth = await self.layer.create_user(
            user_with_metadata(
                auth_source="oauth",
                access_token="oauth-access-secret",
                refresh_token="oauth-refresh-secret",
            )
        )
        copilot = await self.layer.create_user(
            user_with_metadata(
                auth_source="copilot_session",
                copilot_session_id="opaque-session",
            )
        )
        cached = await self.layer.get_user(PRINCIPAL_ID)

        self.assertEqual(oauth.metadata, copilot.metadata)
        self.assertEqual(copilot.metadata, cached.metadata)
        serialized = json.dumps(cached.to_dict())
        for forbidden in (
            "oauth-access-secret",
            "oauth-refresh-secret",
            "opaque-session",
            "access_token",
            "refresh_token",
            "auth_source",
            "copilot_session_id",
        ):
            self.assertNotIn(forbidden, serialized)

    async def test_cached_profile_contains_only_canonical_safe_fields(self):
        persisted = await self.layer.create_user(
            user_with_metadata(
                access_token="access-secret",
                refresh_token="refresh-secret",
                access_token_expires_at=123,
                copilot_session_id="session-secret",
                unexpected="not-safe",
            )
        )

        self.assertEqual(
            {
                "authorized",
                "tenant_id",
                "object_id",
                "principal_id",
                "client_principal_id",
                "client_principal_name",
                "client_group_names",
                "user_name",
            },
            set(persisted.metadata),
        )

    async def test_chainlit_user_serialization_returns_only_safe_profile(self):
        session_user = user_with_metadata(
            auth_source="oauth_session",
            oauth_session_id="opaque-oauth-session",
            access_token="must-never-be-serialized",
            refresh_token="must-never-be-serialized",
        )
        with (
            patch.dict(
                os.environ,
                {"CHAINLIT_AUTH_SECRET": "test-secret-with-adequate-length"},
            ),
            patch(
                "chainlit.auth.get_data_layer",
                return_value=self.layer,
            ),
        ):
            current_user = await authenticate_user(create_jwt(session_user))

        serialized = json.dumps(current_user.to_dict())
        for forbidden in (
            "opaque-oauth-session",
            "must-never-be-serialized",
            "access_token",
            "refresh_token",
            "auth_source",
            "oauth_session_id",
        ):
            self.assertNotIn(forbidden, serialized)

    async def test_user_cache_is_lru_bounded(self):
        with patch.object(datalayer, "_MAX_CACHED_USERS", 2):
            object_ids = (
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
                "00000000-0000-0000-0000-000000000003",
            )
            for object_id in object_ids:
                principal_id = f"{TENANT_ID}:{object_id}"
                await self.layer.create_user(
                    User(
                        identifier=principal_id,
                        metadata={
                            "tenant_id": TENANT_ID,
                            "object_id": object_id,
                            "principal_id": principal_id,
                        },
                    )
                )

        self.assertEqual(2, len(datalayer._users))
        self.assertNotIn(f"{TENANT_ID}:{object_ids[0]}", datalayer._users)


if __name__ == "__main__":
    unittest.main()
