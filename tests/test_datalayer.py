import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from chainlit.user import User

import datalayer


class CopilotUserCacheTests(unittest.IsolatedAsyncioTestCase):
    async def test_copilot_principals_are_not_retained_in_user_cache(self):
        principal_id = (
            "00000000-0000-0000-0000-000000000000:"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
        metadata = {
            "auth_source": "copilot_session",
            "copilot_auth_mode": "anonymous",
            "copilot_session_id": "s" * 43,
            "principal_id": principal_id,
            "tenant_id": "00000000-0000-0000-0000-000000000000",
            "object_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        }
        request_session = SimpleNamespace(
            principal_id=principal_id,
            display_name="Anonymous Copilot user",
            user_metadata=lambda: metadata,
        )
        layer = datalayer.OrchestratorDataLayer()
        datalayer._users.clear()
        self.addCleanup(datalayer._users.clear)

        with (
            patch(
                "datalayer.get_request_copilot_session",
                return_value=request_session,
            ),
            patch(
                "datalayer.is_copilot_session_active",
                new=AsyncMock(return_value=True),
            ),
        ):
            persisted = await layer.get_user(principal_id)
            recreated = await layer.create_user(
                User(
                    identifier=principal_id,
                    display_name="Anonymous Copilot user",
                    metadata=metadata,
                )
            )

        self.assertEqual(principal_id, persisted.identifier)
        self.assertEqual(principal_id, recreated.identifier)
        self.assertEqual({}, datalayer._users)


if __name__ == "__main__":
    unittest.main()
