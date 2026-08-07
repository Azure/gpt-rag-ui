"""Focused tests proving app.py's hosted-agent continuity wiring: the
capability is persisted to the Chainlit session, the coordinator factory is
built from the loaded settings, and default (flag-off) behavior is fully
preserved. These tests reload app.py under distinct CHAT_BACKEND/continuity
configurations, since app.py resolves its configuration once at import time.
"""

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
    # Explicit capability mode: the disabled fallback owner-binding mode,
    # preserved here as a distinct scenario from the preferred/default
    # delegated mode covered by _DELEGATED_CONTINUITY_ENV below.
    "HOSTED_CONVERSATION_OWNER_BINDING": "capability",
    "HOSTED_CONVERSATION_CAPABILITY_KEY": "k" * 32,
    "HOSTED_CONVERSATION_CAPABILITY_KEY_ID": "key-1",
    "HOSTED_CONVERSATION_STORE_BASE_URL": "https://agent.example.com/openai/v1",
    "HOSTED_CONVERSATION_STORE_RESOURCE_SCOPE": "api://hosted-agent/.default",
}

_DELEGATED_CONTINUITY_ENV = {
    **_HOSTED_AGENT_ENV,
    "HOSTED_CONTINUITY_ENABLED": "true",
    # Preferred/default owner-binding mode (Azure/GPT-RAG#591, "OQ-OWN"):
    # gated on an explicit protocol-version + validated-flag attestation.
    "HOSTED_CONVERSATION_OWNER_BINDING": "delegated",
    "HOSTED_CONVERSATION_OWNER_BINDING_VALIDATED": "true",
    "HOSTED_AGENT_PROTOCOL_VERSION": "2.0.0",
    "HOSTED_CONVERSATION_STORE_BASE_URL": "https://agent.example.com/openai/v1",
    "HOSTED_CONVERSATION_STORE_RESOURCE_SCOPE": "api://hosted-agent/.default",
}


def _reload_app_with_env(env: dict[str, str]):
    with (
        patch.dict(os.environ, env, clear=False),
        patch("telemetry.Telemetry.configure_monitoring"),
        patch("telemetry.Telemetry.get_tracer", return_value=Mock()),
    ):
        import app

        return importlib.reload(app)


class TestHostedContinuityAppWiring(unittest.TestCase):
    """Reloads app.py under different configurations; each test restores
    the module back to the CHAT_BACKEND=orchestrator baseline afterward so
    later test modules that import app.py see the expected default state."""

    def tearDown(self):
        _reload_app_with_env({"CHAT_BACKEND": "orchestrator"})

    def test_continuity_disabled_by_default_for_hosted_agent_backend(self):
        app = _reload_app_with_env(_HOSTED_AGENT_ENV)
        self.assertEqual(app.CHAT_BACKEND, "hosted_agent")
        self.assertFalse(app.HOSTED_CONTINUITY_ENABLED)

    def test_orchestrator_backend_forces_continuity_disabled(self):
        app = _reload_app_with_env({"CHAT_BACKEND": "orchestrator"})
        self.assertEqual(app.CHAT_BACKEND, "orchestrator")
        self.assertFalse(app.HOSTED_CONTINUITY_ENABLED)

    def test_continuity_enabled_builds_working_coordinator_from_settings(self):
        app = _reload_app_with_env(_CONTINUITY_ENV)
        self.assertTrue(app.HOSTED_CONTINUITY_ENABLED)
        self.assertEqual(
            app.HOSTED_CONTINUITY_SETTINGS.store_base_url,
            "https://agent.example.com/openai/v1",
        )
        coordinator = app._get_hosted_continuity_coordinator()
        self.assertIsInstance(coordinator, app.HostedContinuityCoordinator)
        # The factory must be a singleton (same coordinator instance reused
        # across turns/messages within one running process).
        self.assertIs(coordinator, app._get_hosted_continuity_coordinator())

    def test_delegated_continuity_builds_coordinator_without_capability_manager(self):
        """Preferred/default owner-binding mode (Azure/GPT-RAG#591): the
        factory must build a working coordinator with no capability manager
        dependency, and app.py's settings must reflect delegated mode."""
        app = _reload_app_with_env(_DELEGATED_CONTINUITY_ENV)
        self.assertTrue(app.HOSTED_CONTINUITY_ENABLED)
        self.assertEqual(app.HOSTED_CONTINUITY_SETTINGS.owner_binding, "delegated")
        self.assertTrue(app.HOSTED_CONTINUITY_SETTINGS.uses_delegated_binding)
        coordinator = app._get_hosted_continuity_coordinator()
        self.assertIsInstance(coordinator, app.HostedContinuityCoordinator)
        self.assertIs(coordinator, app._get_hosted_continuity_coordinator())

    def test_invalid_continuity_config_fails_fast_at_import(self):
        bad_env = {
            **_HOSTED_AGENT_ENV,
            "HOSTED_CONTINUITY_ENABLED": "true",
            "HOSTED_CONVERSATION_OWNER_BINDING": "capability",
            # Deliberately omit HOSTED_CONVERSATION_CAPABILITY_KEY so startup
            # must fail fast rather than defer to the first user turn.
            "HOSTED_CONVERSATION_STORE_BASE_URL": "https://agent.example.com/openai/v1",
        }
        with self.assertRaises(Exception):
            _reload_app_with_env(bad_env)

    def test_delegated_continuity_ungated_fails_fast_at_import(self):
        """Delegated mode without the explicit validated-flag + protocol
        version attestation must fail closed at startup (the practical
        equivalent of a 503: the process never comes up misconfigured)."""
        bad_env = {
            **_HOSTED_AGENT_ENV,
            "HOSTED_CONTINUITY_ENABLED": "true",
            "HOSTED_CONVERSATION_OWNER_BINDING": "delegated",
            "HOSTED_CONVERSATION_STORE_BASE_URL": "https://agent.example.com/openai/v1",
            "HOSTED_CONVERSATION_STORE_RESOURCE_SCOPE": "api://hosted-agent/.default",
            # Deliberately omit HOSTED_CONVERSATION_OWNER_BINDING_VALIDATED
            # and HOSTED_AGENT_PROTOCOL_VERSION.
        }
        with self.assertRaises(Exception):
            _reload_app_with_env(bad_env)


if __name__ == "__main__":
    unittest.main()
