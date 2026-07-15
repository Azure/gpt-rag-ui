import os
import unittest
from unittest.mock import patch

import dependencies


class FakeConfig:
    def __init__(self, values=None):
        self.values = values or {}

    def get(self, key, default=None, type=str):
        value = self.values.get(key, default)
        return type(value) if value is not None and type is not None else value


dependencies.__dict__["__config"] = FakeConfig()

import main  # noqa: E402
from embed_config import EmbedConfigError  # noqa: E402


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
            {"CHAINLIT_AUTH_SECRET": "persistent-environment-secret"},
            clear=True,
        ):
            main._configure_chainlit_prereqs(
                FakeConfig(),
                require_persistent_auth_secret=True,
            )

            self.assertEqual(
                "persistent-environment-secret",
                os.environ["CHAINLIT_AUTH_SECRET"],
            )

    def test_copilot_loads_chainlit_auth_secret_from_app_configuration(self):
        config = FakeConfig(
            {"CHAINLIT_AUTH_SECRET": "persistent-config-secret"}
        )
        with patch.dict(os.environ, {}, clear=True):
            main._configure_chainlit_prereqs(
                config,
                require_persistent_auth_secret=True,
            )

            self.assertEqual(
                "persistent-config-secret",
                os.environ["CHAINLIT_AUTH_SECRET"],
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


if __name__ == "__main__":
    unittest.main()
