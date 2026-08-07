import os
import unittest
from unittest.mock import patch

from hosted_continuity_config import (
    HostedContinuityConfigError,
    load_hosted_continuity_settings,
)


class TestHostedContinuityConfig(unittest.TestCase):
    _VALID_VALUES = {
        "HOSTED_CONTINUITY_ENABLED": "true",
        "HOSTED_CONVERSATION_CAPABILITY_KEY": "a" * 32,
        "HOSTED_CONVERSATION_CAPABILITY_KEY_ID": "key-1",
        "HOSTED_CONVERSATION_STORE_BASE_URL": "https://agent.example.com/openai/v1",
        "HOSTED_CONVERSATION_STORE_RESOURCE_SCOPE": "api://hosted-agent/.default",
    }

    def _load(self, values: dict[str, str]):
        def get_value(key, default=None, _type=str):
            return values.get(key, default)

        config = type("Config", (), {"get": staticmethod(get_value)})()
        with patch.dict(os.environ, {}, clear=True):
            return load_hosted_continuity_settings(config)

    def test_disabled_by_default_and_ignores_other_settings(self):
        settings = self._load({})
        self.assertFalse(settings.enabled)
        self.assertEqual(settings.owner_binding, "capability")
        self.assertFalse(settings.uses_capability_binding)
        self.assertFalse(settings.uses_delegated_binding)

    def test_disabled_ignores_invalid_values_of_other_settings(self):
        # Preserves current behavior when the feature flag is false: no
        # other setting is even parsed, let alone validated.
        settings = self._load(
            {
                "HOSTED_CONTINUITY_ENABLED": "false",
                "HOSTED_HISTORY_MAX_ITEMS": "not-a-number",
                "HOSTED_CONVERSATION_OWNER_BINDING": "nonsense",
            }
        )
        self.assertFalse(settings.enabled)

    def test_enabled_with_valid_values_returns_capability_defaults(self):
        settings = self._load(dict(self._VALID_VALUES))
        self.assertTrue(settings.enabled)
        self.assertEqual(settings.owner_binding, "capability")
        self.assertTrue(settings.uses_capability_binding)
        self.assertFalse(settings.uses_delegated_binding)
        self.assertEqual(settings.capability_ttl_seconds, 900)
        self.assertEqual(settings.history_max_items, 40)
        self.assertEqual(settings.history_max_tokens, 8000)
        self.assertEqual(settings.history_truncation, "drop_oldest")
        self.assertEqual(
            settings.store_base_url, "https://agent.example.com/openai/v1"
        )
        self.assertEqual(settings.store_resource_scope, "api://hosted-agent/.default")

    def test_store_resource_scope_falls_back_to_hosted_agent_scope(self):
        values = dict(self._VALID_VALUES)
        del values["HOSTED_CONVERSATION_STORE_RESOURCE_SCOPE"]
        values["HOSTED_AGENT_RESOURCE_SCOPE"] = "api://hosted-agent-fallback/.default"
        settings = self._load(values)
        self.assertEqual(
            settings.store_resource_scope, "api://hosted-agent-fallback/.default"
        )

    def test_delegated_binding_is_inert_until_explicitly_validated(self):
        values = dict(self._VALID_VALUES)
        values["HOSTED_CONVERSATION_OWNER_BINDING"] = "delegated"
        with self.assertRaisesRegex(HostedContinuityConfigError, "inert"):
            self._load(values)

    def test_delegated_binding_activates_once_validated_flag_set(self):
        values = dict(self._VALID_VALUES)
        values["HOSTED_CONVERSATION_OWNER_BINDING"] = "delegated"
        values["HOSTED_CONVERSATION_OWNER_BINDING_VALIDATED"] = "true"
        settings = self._load(values)
        self.assertTrue(settings.uses_delegated_binding)
        self.assertFalse(settings.uses_capability_binding)

    def test_rejects_unknown_owner_binding(self):
        values = dict(self._VALID_VALUES)
        values["HOSTED_CONVERSATION_OWNER_BINDING"] = "trust-me"
        with self.assertRaisesRegex(
            HostedContinuityConfigError, "HOSTED_CONVERSATION_OWNER_BINDING"
        ):
            self._load(values)

    def test_capability_binding_requires_key(self):
        values = dict(self._VALID_VALUES)
        del values["HOSTED_CONVERSATION_CAPABILITY_KEY"]
        with self.assertRaisesRegex(
            HostedContinuityConfigError, "HOSTED_CONVERSATION_CAPABILITY_KEY"
        ):
            self._load(values)

    def test_capability_binding_requires_long_enough_key(self):
        values = dict(self._VALID_VALUES)
        values["HOSTED_CONVERSATION_CAPABILITY_KEY"] = "short"
        with self.assertRaisesRegex(
            HostedContinuityConfigError, "HOSTED_CONVERSATION_CAPABILITY_KEY"
        ):
            self._load(values)

    def test_capability_binding_requires_key_id(self):
        values = dict(self._VALID_VALUES)
        del values["HOSTED_CONVERSATION_CAPABILITY_KEY_ID"]
        with self.assertRaisesRegex(
            HostedContinuityConfigError, "HOSTED_CONVERSATION_CAPABILITY_KEY_ID"
        ):
            self._load(values)

    def test_rejects_out_of_bounds_ttl(self):
        values = dict(self._VALID_VALUES)
        values["HOSTED_CONVERSATION_CAPABILITY_TTL_SECONDS"] = "10"
        with self.assertRaisesRegex(
            HostedContinuityConfigError, "HOSTED_CONVERSATION_CAPABILITY_TTL_SECONDS"
        ):
            self._load(values)

    def test_rejects_out_of_bounds_max_items(self):
        values = dict(self._VALID_VALUES)
        values["HOSTED_HISTORY_MAX_ITEMS"] = "0"
        with self.assertRaisesRegex(
            HostedContinuityConfigError, "HOSTED_HISTORY_MAX_ITEMS"
        ):
            self._load(values)

    def test_rejects_out_of_bounds_max_tokens(self):
        values = dict(self._VALID_VALUES)
        values["HOSTED_HISTORY_MAX_TOKENS"] = "10"
        with self.assertRaisesRegex(
            HostedContinuityConfigError, "HOSTED_HISTORY_MAX_TOKENS"
        ):
            self._load(values)

    def test_rejects_unsupported_truncation_strategy(self):
        values = dict(self._VALID_VALUES)
        values["HOSTED_HISTORY_TRUNCATION"] = "drop_newest"
        with self.assertRaisesRegex(
            HostedContinuityConfigError, "HOSTED_HISTORY_TRUNCATION"
        ):
            self._load(values)

    def test_requires_store_base_url(self):
        values = dict(self._VALID_VALUES)
        del values["HOSTED_CONVERSATION_STORE_BASE_URL"]
        with self.assertRaisesRegex(
            HostedContinuityConfigError, "HOSTED_CONVERSATION_STORE_BASE_URL"
        ):
            self._load(values)

    def test_rejects_non_https_store_base_url(self):
        values = dict(self._VALID_VALUES)
        values["HOSTED_CONVERSATION_STORE_BASE_URL"] = "http://agent.example.com"
        with self.assertRaisesRegex(
            HostedContinuityConfigError, "HTTPS"
        ):
            self._load(values)

    def test_allows_local_http_store_base_url(self):
        values = dict(self._VALID_VALUES)
        values["HOSTED_CONVERSATION_STORE_BASE_URL"] = "http://localhost:8000"
        settings = self._load(values)
        self.assertEqual(settings.store_base_url, "http://localhost:8000")

    def test_rejects_arm_store_resource_scope(self):
        values = dict(self._VALID_VALUES)
        values["HOSTED_CONVERSATION_STORE_RESOURCE_SCOPE"] = (
            "https://management.azure.com/.default"
        )
        with self.assertRaisesRegex(HostedContinuityConfigError, "not Azure ARM"):
            self._load(values)

    def test_requires_explicit_default_scope_suffix(self):
        values = dict(self._VALID_VALUES)
        values["HOSTED_CONVERSATION_STORE_RESOURCE_SCOPE"] = "api://hosted-agent"
        with self.assertRaisesRegex(HostedContinuityConfigError, "/.default"):
            self._load(values)


if __name__ == "__main__":
    unittest.main()
