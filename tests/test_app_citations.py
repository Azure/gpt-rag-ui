import os
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("CHAINLIT_AUTH_SECRET", "test-secret")

with (
    patch("telemetry.Telemetry.configure_monitoring"),
    patch("telemetry.Telemetry.get_tracer", return_value=Mock()),
):
    import app


class AppCitationTests(unittest.TestCase):
    def test_oauth_configuration_detects_environment_only_settings(self):
        oauth_environment = {
            "OAUTH_AZURE_AD_CLIENT_ID": " client-id ",
            "OAUTH_AZURE_AD_CLIENT_SECRET": " client-secret ",
            "OAUTH_AZURE_AD_TENANT_ID": " tenant-id ",
        }
        with (
            patch.dict(os.environ, oauth_environment, clear=True),
            patch.object(app, "config") as config,
        ):
            config.get.return_value = ""
            self.assertTrue(app._oauth_is_configured())

    def test_copilot_citation_is_absolute_signed_and_principal_bound(self):
        manager = Mock(public_url="https://chat.example.com")
        manager.issue.return_value = (
            "https://chat.example.com/api/download/grant-1"
        )
        with (
            patch.object(app, "COPILOT_ENABLED", True),
            patch.object(app, "DOCUMENTS_CONTAINER", "documents"),
            patch.object(app, "CONVERSATION_DOCUMENTS_CONTAINER", ""),
            patch.object(app, "SHARED_DOWNLOAD_CONTAINERS", {"documents"}),
            patch("app.get_download_tokens", return_value=manager),
        ):
            citation = app.resolve_reference_href(
                "documents/folder/file.pdf",
                conversation_id="thread-1",
                principal_id="tenant:object",
            )

        self.assertEqual(
            "https://chat.example.com/api/download/grant-1",
            citation,
        )
        manager.issue.assert_called_once_with(
            principal_id="tenant:object",
            conversation_id="thread-1",
            container="documents",
            blob_name="folder/file.pdf",
        )

    def test_copilot_citation_requires_conversation_and_principal(self):
        with patch.object(app, "COPILOT_ENABLED", True):
            self.assertIsNone(
                app.resolve_reference_href(
                    "documents/file.pdf",
                    conversation_id="",
                    principal_id="tenant:object",
                )
            )
            self.assertIsNone(
                app.resolve_reference_href(
                    "documents/file.pdf",
                    conversation_id="thread-1",
                    principal_id="",
                )
            )

    def test_standalone_citations_keep_legacy_sas_path(self):
        legacy = Mock(
            return_value=(
                "https://storage.blob.core.windows.net/"
                "documents/file.pdf?sig=token"
            )
        )
        with (
            patch.object(app, "COPILOT_ENABLED", False),
            patch("app._resolve_legacy_reference_href", legacy),
        ):
            citation = app.resolve_reference_href("documents/file.pdf")

        self.assertEqual(
            (
                "https://storage.blob.core.windows.net/"
                "documents/file.pdf?sig=token"
            ),
            citation,
        )
        legacy.assert_called_once_with("documents/file.pdf")


if __name__ == "__main__":
    unittest.main()
