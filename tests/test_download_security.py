import unittest
from unittest.mock import AsyncMock, patch

from conversation_security import conversation_belongs_to, get_owned_conversation
from download_security import DownloadTokenManager, is_download_target_allowed


PRINCIPAL = (
    "11111111-2222-3333-4444-555555555555:"
    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)
METADATA = {
    "principal_id": PRINCIPAL,
    "tenant_id": "11111111-2222-3333-4444-555555555555",
    "object_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "access_token": "token",
}


class DownloadSecurityTests(unittest.IsolatedAsyncioTestCase):
    def test_grant_is_absolute_signed_and_principal_bound(self):
        manager = DownloadTokenManager(
            secret="secret",
            public_url="https://chat.example.com",
        )
        url = manager.issue(
            principal_id=PRINCIPAL,
            conversation_id="conversation",
            container="documents",
            blob_name="folder/file.pdf",
        )
        grant = manager.verify(url.rsplit("/", 1)[-1])
        self.assertTrue(url.startswith("https://chat.example.com/api/download/"))
        self.assertEqual(PRINCIPAL, grant.principal_id)
        self.assertEqual("folder/file.pdf", grant.blob_name)
        self.assertIsNone(manager.verify("tampered"))

    def test_rejects_path_traversal(self):
        manager = DownloadTokenManager(secret="secret", public_url="https://chat")
        with self.assertRaises(ValueError):
            manager.issue(
                principal_id=PRINCIPAL,
                conversation_id="conversation",
                container="documents",
                blob_name="../secret.pdf",
            )

    def test_download_target_policy_is_default_deny_and_conversation_bound(self):
        self.assertTrue(
            is_download_target_allowed(
                conversation_id="mine",
                container="conversation-documents",
                blob_name="conversations/mine/file.pdf",
                conversation_container="conversation-documents",
                shared_containers=set(),
            )
        )
        self.assertFalse(
            is_download_target_allowed(
                conversation_id="mine",
                container="conversation-documents",
                blob_name="conversations/other/file.pdf",
                conversation_container="conversation-documents",
                shared_containers=set(),
            )
        )
        self.assertFalse(
            is_download_target_allowed(
                conversation_id="mine",
                container="documents",
                blob_name="private.pdf",
                conversation_container="conversation-documents",
                shared_containers=set(),
            )
        )
        self.assertTrue(
            is_download_target_allowed(
                conversation_id="mine",
                container="documents",
                blob_name="shared.pdf",
                conversation_container="conversation-documents",
                shared_containers={"documents"},
            )
        )

    def test_conversation_identity_requires_matching_tenant_and_object(self):
        self.assertTrue(
            conversation_belongs_to(
                {
                    "principal_id": METADATA["object_id"],
                    "tenant_id": METADATA["tenant_id"],
                },
                METADATA,
            )
        )
        self.assertTrue(
            conversation_belongs_to(
                {"principal_id": METADATA["object_id"]},
                METADATA,
            )
        )
        self.assertFalse(
            conversation_belongs_to(
                {"principal_id": "different-object"},
                METADATA,
            )
        )
        self.assertFalse(
            conversation_belongs_to(
                {
                    "principal_id": METADATA["object_id"],
                    "tenant_id": "different-tenant",
                },
                METADATA,
            )
        )
        self.assertFalse(conversation_belongs_to({}, METADATA))

    def test_declared_session_principal_must_match_tid_and_oid(self):
        mismatched_metadata = {
            **METADATA,
            "principal_id": "different-tenant:different-object",
        }
        self.assertFalse(
            conversation_belongs_to(
                {"principal_id": METADATA["object_id"]},
                mismatched_metadata,
            )
        )

    async def test_owned_conversation_fails_closed(self):
        with (
            patch(
                "conversation_security.resolve_access_token",
                AsyncMock(return_value="token"),
            ),
            patch(
                "conversation_security.call_orchestrator_get_conversation",
                AsyncMock(return_value={"principal_id": "different-object"}),
            ),
        ):
            self.assertIsNone(
                await get_owned_conversation("conversation", METADATA)
            )


if __name__ == "__main__":
    unittest.main()
