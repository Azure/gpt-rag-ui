import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import dependencies


class FakeConfig:
    def __init__(self, values=None):
        self.values = values or {}

    def get(self, key, default=None, type=str):
        value = self.values.get(key, default)
        return type(value) if value is not None and type is not None else value


dependencies.__dict__["__config"] = FakeConfig()

import main  # noqa: E402
from embed_config import EmbedConfigError, EmbedSettings  # noqa: E402


STRONG_SECRET = "a-secure-test-secret-with-at-least-32-bytes"


class MainPolicyTests(unittest.TestCase):
    def test_copilot_requires_persistent_chainlit_auth_secret(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                EmbedConfigError,
                "persistent CHAINLIT_AUTH_SECRET",
            ):
                main._configure_chainlit_prereqs(
                    FakeConfig(),
                    require_persistent_auth_secret=True,
                )

            self.assertNotIn("CHAINLIT_AUTH_SECRET", os.environ)

    def test_copilot_accepts_environment_chainlit_auth_secret(self):
        with patch.dict(
            os.environ,
            {"CHAINLIT_AUTH_SECRET": f"  {STRONG_SECRET}  "},
            clear=True,
        ):
            main._configure_chainlit_prereqs(
                FakeConfig(),
                require_persistent_auth_secret=True,
            )

            self.assertEqual(
                STRONG_SECRET,
                os.environ["CHAINLIT_AUTH_SECRET"],
            )

    def test_copilot_loads_chainlit_auth_secret_from_app_configuration(self):
        config = FakeConfig(
            {"CHAINLIT_AUTH_SECRET": STRONG_SECRET}
        )
        with patch.dict(os.environ, {}, clear=True):
            main._configure_chainlit_prereqs(
                config,
                require_persistent_auth_secret=True,
            )

            self.assertEqual(
                STRONG_SECRET,
                os.environ["CHAINLIT_AUTH_SECRET"],
            )

    def test_copilot_rejects_whitespace_or_short_auth_secrets(self):
        for value in ("   ", "too-short"):
            with self.subTest(value=value):
                with patch.dict(
                    os.environ,
                    {"CHAINLIT_AUTH_SECRET": value},
                    clear=True,
                ):
                    with self.assertRaises(EmbedConfigError):
                        main._configure_chainlit_prereqs(
                            FakeConfig(),
                            require_persistent_auth_secret=True,
                        )
                    self.assertNotIn("CHAINLIT_AUTH_SECRET", os.environ)

    def test_whitespace_chainlit_url_falls_back_to_app_configuration(self):
        config = FakeConfig(
            {
                "CHAINLIT_AUTH_SECRET": STRONG_SECRET,
                "CHAINLIT_URL": " https://chat.example.com/ ",
            }
        )
        with patch.dict(
            os.environ,
            {"CHAINLIT_URL": "   "},
            clear=True,
        ):
            main._configure_chainlit_prereqs(
                config,
                require_persistent_auth_secret=True,
            )
            self.assertEqual(
                "https://chat.example.com",
                os.environ["CHAINLIT_URL"],
            )

    def test_whitespace_oauth_environment_values_use_normalized_config(self):
        config = FakeConfig(
            {
                "CHAINLIT_AUTH_SECRET": STRONG_SECRET,
                "OAUTH_AZURE_AD_CLIENT_ID": " config-client ",
                "OAUTH_AZURE_AD_TENANT_ID": " config-tenant ",
                "OAUTH_AZURE_AD_CLIENT_SECRET": " config-secret ",
                "OAUTH_AZURE_AD_SCOPES": " api://scope/.default ",
                "OAUTH_AZURE_AD_ENABLE_SINGLE_TENANT": " false ",
            }
        )
        with (
            patch.dict(
                os.environ,
                {
                    "OAUTH_AZURE_AD_CLIENT_ID": " ",
                    "OAUTH_AZURE_AD_TENANT_ID": " ",
                    "OAUTH_AZURE_AD_CLIENT_SECRET": " ",
                    "OAUTH_AZURE_AD_SCOPES": " ",
                    "OAUTH_AZURE_AD_ENABLE_SINGLE_TENANT": " ",
                },
                clear=True,
            ),
            patch("main._is_running_in_azure_host", return_value=True),
        ):
            auth_state = main._evaluate_auth_state(config)
            main._configure_auth_environment(config, auth_state)

            self.assertEqual(
                "config-client",
                os.environ["OAUTH_AZURE_AD_CLIENT_ID"],
            )
            self.assertEqual(
                "config-tenant",
                os.environ["OAUTH_AZURE_AD_TENANT_ID"],
            )
            self.assertEqual(
                "config-secret",
                os.environ["OAUTH_AZURE_AD_CLIENT_SECRET"],
            )
            self.assertEqual(
                "api://scope/.default",
                os.environ["OAUTH_AZURE_AD_SCOPES"],
            )
            self.assertEqual(
                "false",
                os.environ["OAUTH_AZURE_AD_ENABLE_SINGLE_TENANT"],
            )

    def test_standalone_keeps_temporary_secret_fallback(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("main.secrets.token_urlsafe", return_value="temporary-secret"),
            self.assertLogs("gpt_rag_ui.main", level="WARNING") as logs,
        ):
            main._configure_chainlit_prereqs(FakeConfig())

            self.assertEqual(
                "temporary-secret",
                os.environ["CHAINLIT_AUTH_SECRET"],
            )
            self.assertTrue(
                any("using a temporary secret" in message for message in logs.output)
            )

    def test_embed_environment_sets_mode_without_changing_route_paths(self):
        settings = EmbedSettings(
            enabled=True,
            auth_mode="anonymous",
            ui_origin="https://chat.example.com",
            allowed_origins=("https://portal.example.com",),
        )
        with patch.dict(os.environ, {}, clear=True):
            main._configure_embed_environment(settings)

            self.assertEqual(
                "https://chat.example.com",
                os.environ["CHAINLIT_PUBLIC_URL"],
            )
            self.assertEqual(
                "anonymous",
                os.environ["CHAINLIT_COPILOT_AUTH_MODE_EFFECTIVE"],
            )
            self.assertNotIn("CHAINLIT_ROOT_PATH", os.environ)

    def test_entra_copilot_upload_validation_is_session_scoped(self):
        original_validate = Mock(side_effect=ValueError("File upload is not enabled"))
        validate_mime_type = Mock()
        validate_file_size = Mock()
        server = SimpleNamespace(
            validate_file_upload=original_validate,
            validate_file_mime_type=validate_mime_type,
            validate_file_size=validate_file_size,
        )
        file = object()

        with patch(
            "embed_auth.get_request_copilot_session",
            return_value=SimpleNamespace(auth_mode="entra"),
        ):
            main._configure_copilot_upload_validation(server)
            server.validate_file_upload(file)

        original_validate.assert_not_called()
        validate_mime_type.assert_called_once_with(file, None)
        validate_file_size.assert_called_once_with(file, None)

        with patch(
            "embed_auth.get_request_copilot_session",
            return_value=None,
        ):
            main._configure_copilot_upload_validation(server)
            with self.assertRaisesRegex(ValueError, "not enabled"):
                server.validate_file_upload(file)


if __name__ == "__main__":
    unittest.main()
