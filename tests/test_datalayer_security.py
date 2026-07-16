import unittest
from unittest.mock import AsyncMock, patch

import datalayer


class DataLayerSecurityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.layer = datalayer.OrchestratorDataLayer()
        self.principal = (
            "11111111-2222-3333-4444-555555555555:"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
        self.metadata = {
            "principal_id": self.principal,
            "tenant_id": "11111111-2222-3333-4444-555555555555",
            "object_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "authorized": True,
            "auth_source": "copilot_session",
            "copilot_session_id": "session-1",
        }

    async def test_list_threads_binds_owner_to_canonical_tid_oid(self):
        with (
            patch(
                "datalayer._get_session_metadata",
                return_value=self.metadata,
            ),
            patch(
                "datalayer.is_copilot_session_active",
                AsyncMock(return_value=True),
            ),
            patch(
                "datalayer.resolve_access_token",
                AsyncMock(return_value="token"),
            ),
            patch(
                "datalayer.call_orchestrator_list_conversations",
                AsyncMock(
                    return_value={
                        "conversations": [
                            {"id": "thread", "name": "Thread"}
                        ],
                        "has_more": False,
                    }
                ),
            ),
        ):
            result = await self.layer.list_threads(
                pagination=type(
                    "Pagination",
                    (),
                    {"first": 20, "cursor": None},
                )(),
                filters=object(),
            )

        self.assertEqual(self.principal, result.data[0]["userId"])
        self.assertEqual(
            self.principal,
            result.data[0]["userIdentifier"],
        )

    async def test_get_thread_rejects_other_principal(self):
        with (
            patch(
                "datalayer._get_session_metadata",
                return_value=self.metadata,
            ),
            patch(
                "datalayer.is_copilot_session_active",
                AsyncMock(return_value=True),
            ),
            patch(
                "datalayer.get_owned_conversation",
                AsyncMock(return_value=None),
            ),
        ):
            self.assertIsNone(await self.layer.get_thread("thread"))

    async def test_update_and_delete_require_owned_thread(self):
        with (
            patch(
                "datalayer._get_session_metadata",
                return_value=self.metadata,
            ),
            patch(
                "datalayer.is_copilot_session_active",
                AsyncMock(return_value=True),
            ),
            patch(
                "datalayer.get_owned_conversation",
                AsyncMock(return_value=None),
            ),
            patch(
                "datalayer.call_orchestrator_update_conversation",
                AsyncMock(),
            ) as update,
            patch(
                "datalayer.call_orchestrator_delete_conversation",
                AsyncMock(),
            ) as delete,
        ):
            await self.layer.update_thread("thread", name="new name")
            self.assertFalse(await self.layer.delete_thread("thread"))

        update.assert_not_awaited()
        delete.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
