"""Tests for app.py's administrative-panel settings wiring (issue #611,
ADR-0004): ``PANEL_SETTINGS`` is loaded, safe-by-default, only wires the
owner-index writer when the panel's user-facing surfaces are active, and
never affects the classic (``CHAT_BACKEND=orchestrator``) code path."""

import importlib
import os
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("CHAINLIT_AUTH_SECRET", "test-secret")

_HOSTED_AGENT_ENV = {
    "CHAT_BACKEND": "hosted_agent",
    "HOSTED_AGENT_BASE_URL": "https://agent.example.com/protocol",
    "HOSTED_AGENT_RESOURCE_SCOPE": "api://hosted-agent/.default",
    "OAUTH_AZURE_AD_CLIENT_ID": "client-id",
    "OAUTH_AZURE_AD_CLIENT_SECRET": "client-secret",
    "OAUTH_AZURE_AD_TENANT_ID": "tenant-id",
}

_CONTINUITY_ENV = {
    **_HOSTED_AGENT_ENV,
    "HOSTED_CONTINUITY_ENABLED": "true",
    "HOSTED_CONVERSATION_OWNER_BINDING": "capability",
    "HOSTED_CONVERSATION_CAPABILITY_KEY": "k" * 32,
    "HOSTED_CONVERSATION_CAPABILITY_KEY_ID": "key-1",
    "HOSTED_CONVERSATION_STORE_BASE_URL": "https://agent.example.com/openai/v1",
    "HOSTED_CONVERSATION_STORE_RESOURCE_SCOPE": "api://hosted-agent/.default",
}

_PANEL_ENV = {
    **_CONTINUITY_ENV,
    "DEPLOY_ADMINISTRATIVE_PANEL": "true",
    "PANEL_HISTORY_ENABLED": "true",
    "PANEL_CONVERSATIONS_TOKEN_AUDIENCE": "api://panel/.default",
    "DATABASE_ACCOUNT_NAME": "gptragdb",
    "DATABASE_NAME": "gptrag",
}


def _reload_app_with_env(env: dict[str, str]):
    with (
        patch.dict(os.environ, env, clear=False),
        patch("telemetry.Telemetry.configure_monitoring"),
        patch("telemetry.Telemetry.get_tracer", return_value=Mock()),
    ):
        import app

        return importlib.reload(app)


class PanelAppWiringTests(unittest.TestCase):
    def tearDown(self):
        _reload_app_with_env({"CHAT_BACKEND": "orchestrator"})

    def test_panel_settings_disabled_by_default_for_hosted_agent_backend(self):
        app = _reload_app_with_env(_HOSTED_AGENT_ENV)
        self.assertFalse(app.PANEL_SETTINGS.user_surfaces_active)

    def test_orchestrator_backend_gets_inert_panel_settings(self):
        """Classic regression: CHAT_BACKEND=orchestrator must never load or
        require any panel configuration, and PANEL_SETTINGS must stay the
        fully-inert default."""
        app = _reload_app_with_env({"CHAT_BACKEND": "orchestrator"})
        self.assertEqual(app.CHAT_BACKEND, "orchestrator")
        self.assertFalse(app.PANEL_SETTINGS.deploy_administrative_panel)
        self.assertFalse(app.PANEL_SETTINGS.history_enabled)
        self.assertFalse(app.PANEL_SETTINGS.user_surfaces_active)

    def test_continuity_enabled_without_panel_env_keeps_panel_inert(self):
        app = _reload_app_with_env(_CONTINUITY_ENV)
        self.assertTrue(app.HOSTED_CONTINUITY_ENABLED)
        self.assertFalse(app.PANEL_SETTINGS.user_surfaces_active)

    def test_full_panel_env_activates_user_surfaces(self):
        app = _reload_app_with_env(_PANEL_ENV)
        self.assertTrue(app.PANEL_SETTINGS.user_surfaces_active)
        self.assertEqual(app.PANEL_SETTINGS.database_account_name, "gptragdb")

    def test_coordinator_receives_owner_index_writer_only_when_panel_active(self):
        app = _reload_app_with_env(_PANEL_ENV)
        coordinator = app._get_hosted_continuity_coordinator()
        self.assertIsNotNone(coordinator._on_conversation_created)

    def test_coordinator_has_no_writer_when_panel_inactive(self):
        app = _reload_app_with_env(_CONTINUITY_ENV)
        coordinator = app._get_hosted_continuity_coordinator()
        self.assertIsNone(coordinator._on_conversation_created)

    def test_invalid_panel_config_fails_fast_at_import(self):
        """Fail-closed at startup (not first request) when the panel is
        half-configured, mirroring the continuity settings' own posture."""
        bad_env = {
            **_PANEL_ENV,
        }
        del bad_env["PANEL_CONVERSATIONS_TOKEN_AUDIENCE"]
        with self.assertRaises(Exception):
            _reload_app_with_env(bad_env)


if __name__ == "__main__":
    unittest.main()
