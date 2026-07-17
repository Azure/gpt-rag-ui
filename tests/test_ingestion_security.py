import unittest
from unittest.mock import patch

from ingestion_client import _build_ingest_documents_payload


class IngestionSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_ingestion_acl_uses_validated_bare_object_id(self):
        object_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        with patch(
            "ingestion_client._read_file_bytes",
            return_value=b"hello",
        ):
            payload = await _build_ingest_documents_payload(
                "thread",
                "question",
                [{"path": "upload.txt", "name": "upload.txt"}],
                {
                    "principal_id": (
                        "11111111-2222-3333-4444-555555555555:"
                        f"{object_id}"
                    ),
                    "object_id": object_id,
                    "client_principal_id": (
                        "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
                    ),
                },
            )

        self.assertEqual([object_id], payload["securityUserIds"])
        self.assertNotIn(":", payload["securityUserIds"][0])

    async def test_ingestion_omits_malformed_object_id(self):
        with patch(
            "ingestion_client._read_file_bytes",
            return_value=b"hello",
        ):
            payload = await _build_ingest_documents_payload(
                "thread",
                "question",
                [{"path": "upload.txt", "name": "upload.txt"}],
                {
                    "object_id": "tenant:object",
                    "client_principal_id": (
                        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                    ),
                },
            )

        self.assertNotIn("securityUserIds", payload)


if __name__ == "__main__":
    unittest.main()
