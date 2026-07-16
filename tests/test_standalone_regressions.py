import os
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

import main
import telemetry
from embed_auth import COPILOT_SESSION_COOKIE, CopilotSession
from embed_config import EmbedSettings


with patch.object(telemetry.Telemetry, "configure_monitoring"):
    import app as chainlit_app


class FakeConfig:
    def __init__(self, values=None, *, connected=True):
        self.values = values or {}
        self.connected = connected

    def get(self, key, default=None, type=str):
        value = self.values.get(key, default)
        if value is None or type is None:
            return value
        return type(value)


class StandaloneAuthRegressionTests(unittest.TestCase):
    def evaluate(self, *, azure: bool, enabled: bool):
        with (
            patch.object(main.os, "environ", {}),
            patch.object(
                main,
                "_is_running_in_azure_host",
                return_value=azure,
            ),
        ):
            return main._evaluate_auth_state(
                FakeConfig(),
                EmbedSettings(enabled=enabled),
            )

    def test_disabled_or_unset_copilot_preserves_anonymous_without_oauth(self):
        for azure in (False, True):
            with self.subTest(azure=azure):
                state = self.evaluate(azure=azure, enabled=False)
                self.assertFalse(state.oauth_configured)
                self.assertTrue(state.allow_anonymous)
                self.assertTrue(state.default_allow_anonymous)

    def test_enabled_copilot_keeps_stricter_default_scoped_to_embed(self):
        azure_state = self.evaluate(azure=True, enabled=True)
        local_state = self.evaluate(azure=False, enabled=True)

        self.assertFalse(azure_state.allow_anonymous)
        self.assertFalse(local_state.allow_anonymous)

    def test_local_and_azure_build_use_chainlit_when_copilot_is_unset(self):
        for azure in (False, True):
            with self.subTest(azure=azure):
                expected_app = object()
                config = FakeConfig()
                with (
                    patch.object(main.os, "environ", {}),
                    patch.object(main, "get_config", return_value=config),
                    patch.object(main, "_startup_banner"),
                    patch.object(main, "_configure_chainlit_prereqs"),
                    patch.object(
                        main,
                        "load_embed_settings",
                        return_value=EmbedSettings(),
                    ),
                    patch.object(
                        main,
                        "_is_running_in_azure_host",
                        return_value=azure,
                    ),
                    patch.object(
                        main,
                        "_create_chainlit_app",
                        return_value=expected_app,
                    ) as create_chainlit,
                    patch.object(
                        main,
                        "_create_auth_required_app",
                    ) as auth_required,
                ):
                    result = main.build_app()

                self.assertIs(expected_app, result)
                create_chainlit.assert_called_once()
                auth_required.assert_not_called()


class StandaloneDownloadRegressionTests(unittest.TestCase):
    def test_legacy_download_route_streams_without_copilot_configuration(self):
        download = Mock(return_value=b"legacy-bytes")
        download_app = main._create_legacy_download_app(
            download_from_blob=download,
            documents_container="documents",
            images_container="images",
        )
        host = FastAPI()
        host.mount("/api/download", download_app)

        with TestClient(host) as client:
            response = client.get("/api/download/documents/folder/file.pdf")

        self.assertEqual(200, response.status_code)
        self.assertEqual(b"legacy-bytes", response.content)
        self.assertEqual(
            'attachment; filename="file.pdf"',
            response.headers["content-disposition"],
        )
        download.assert_called_once_with("documents/folder/file.pdf")

    def test_legacy_download_route_is_unavailable_to_copilot_session(self):
        download = Mock(return_value=b"must-not-leak")
        download_app = main._create_legacy_download_app(
            download_from_blob=download,
            documents_container="documents",
            images_container="images",
            copilot_sessions=object(),
        )
        host = FastAPI()
        host.mount("/api/download", download_app)

        with (
            patch(
                "embed_auth.current_copilot_session",
                return_value=SimpleNamespace(session_id="opaque"),
            ),
            TestClient(host) as client,
        ):
            response = client.get("/api/download/documents/private.pdf")

        self.assertEqual(404, response.status_code)
        download.assert_not_called()

    def test_legacy_download_rejects_active_copilot_cookie_without_referer(self):
        class FakeCopilotSessions:
            async def get(self, session_id):
                return object() if session_id == "opaque-session" else None

        download = Mock(return_value=b"must-not-download")
        download_app = main._create_legacy_download_app(
            download_from_blob=download,
            documents_container="documents",
            images_container="images",
            copilot_sessions=FakeCopilotSessions(),
        )
        host = FastAPI()
        host.mount("/api/download", download_app)

        with TestClient(host) as client:
            response = client.get(
                "/api/download/documents/private.pdf",
                headers={
                    "Cookie": (
                        f"{COPILOT_SESSION_COOKIE}=opaque-session"
                    )
                },
            )

        self.assertEqual(404, response.status_code)
        download.assert_not_called()

    def test_enabled_instance_rejects_unauthenticated_legacy_download(self):
        download = Mock(return_value=b"must-not-download")
        download_app = main._create_legacy_download_app(
            download_from_blob=download,
            documents_container="documents",
            images_container="images",
            copilot_sessions=object(),
        )
        host = FastAPI()
        host.mount("/api/download", download_app)

        with TestClient(host) as client:
            response = client.get("/api/download/documents/private.pdf")

        self.assertEqual(404, response.status_code)
        download.assert_not_called()

    def test_active_standalone_oauth_session_keeps_legacy_download(self):
        class FakeCopilotSessions:
            async def get(self, session_id):
                return object() if session_id == "opaque-session" else None

        download = Mock(return_value=b"standalone-bytes")
        download_app = main._create_legacy_download_app(
            download_from_blob=download,
            documents_container="documents",
            images_container="images",
            copilot_sessions=FakeCopilotSessions(),
        )
        host = FastAPI()
        host.mount("/api/download", download_app)

        with (
            patch(
                "auth_session.current_oauth_credential",
                new=AsyncMock(return_value=object()),
            ),
            TestClient(host) as client,
        ):
            response = client.get(
                "/api/download/documents/standalone.pdf",
                headers={
                    "Cookie": (
                        f"{COPILOT_SESSION_COOKIE}=opaque-session"
                    )
                },
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(b"standalone-bytes", response.content)


class CitationRegressionTests(unittest.TestCase):
    def setUp(self):
        self.container_patch = patch.multiple(
            chainlit_app,
            STORAGE_ACCOUNT_NAME="storage",
            DOCUMENTS_CONTAINER="documents",
            IMAGES_CONTAINER="images",
            CONVERSATION_DOCUMENTS_CONTAINER="conversation-documents",
            SHARED_DOWNLOAD_CONTAINERS={"documents"},
        )
        self.container_patch.start()
        self.addCleanup(self.container_patch.stop)

    def test_disabled_copilot_preserves_legacy_sas_citation_bytes(self):
        with (
            patch.object(chainlit_app, "COPILOT_ENABLED", False),
            patch(
                "app.generate_blob_sas_url",
                return_value="https://storage/documents/file.pdf?sig=legacy",
            ),
            patch("app.get_download_tokens") as download_tokens,
        ):
            rendered = chainlit_app.replace_source_reference_links(
                "See [source](file.pdf)."
            )

        self.assertEqual(
            "See [source](https://storage/documents/file.pdf?sig=legacy).",
            rendered,
        )
        download_tokens.assert_not_called()

    def test_enabled_instance_keeps_legacy_citations_for_standalone_session(self):
        with (
            patch.object(chainlit_app, "COPILOT_ENABLED", True),
            patch("app.current_copilot_session", return_value=None),
            patch(
                "app.generate_blob_sas_url",
                return_value="https://storage/documents/file.pdf?sig=legacy",
            ),
        ):
            href = chainlit_app.resolve_reference_href(
                "file.pdf",
                conversation_id="conversation",
                principal_id="principal",
            )

        self.assertEqual(
            "https://storage/documents/file.pdf?sig=legacy",
            href,
        )

    def test_copilot_session_uses_absolute_authenticated_grant(self):
        manager = Mock()
        manager.issue.return_value = (
            "https://chat.example.com/api/download/signed-grant"
        )
        session = CopilotSession(
            session_id="opaque",
            principal_id="principal",
            tenant_id="tenant",
            object_id="object",
            access_token="entra-secret",
            chainlit_token="chainlit-secret",
            expires_at=9999999999,
        )
        with (
            patch.object(chainlit_app, "COPILOT_ENABLED", True),
            patch("app.current_copilot_session", return_value=session),
            patch("app.is_download_target_allowed", return_value=True),
            patch("app.get_download_tokens", return_value=manager),
        ):
            href = chainlit_app.resolve_reference_href(
                "file.pdf",
                conversation_id="conversation",
                principal_id="principal",
            )

        self.assertEqual(
            "https://chat.example.com/api/download/signed-grant",
            href,
        )
        manager.issue.assert_called_once_with(
            principal_id="principal",
            conversation_id="conversation",
            container="documents",
            blob_name="file.pdf",
        )

    def test_missing_legacy_citation_is_removed_as_before(self):
        with (
            patch.object(chainlit_app, "COPILOT_ENABLED", False),
            patch(
                "app.generate_blob_sas_url",
                side_effect=FileNotFoundError,
            ),
        ):
            rendered = chainlit_app.replace_source_reference_links(
                "See [source](missing.pdf)."
            )

        self.assertEqual("See .", rendered)


if __name__ == "__main__":
    unittest.main()
