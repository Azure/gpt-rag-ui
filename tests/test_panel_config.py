import unittest

from panel_config import PanelConfigError, PanelSettings, load_panel_settings


class _FakeAppConfig:
    def __init__(self, values: dict[str, str] | None = None):
        self._values = values or {}

    def get(self, key, default="", cast=str):
        return self._values.get(key, default)


class PanelSettingsDefaultsTests(unittest.TestCase):
    def test_defaults_are_fully_disabled(self):
        settings = PanelSettings()
        self.assertFalse(settings.deploy_administrative_panel)
        self.assertFalse(settings.history_enabled)
        self.assertFalse(settings.owner_binding_validated)
        self.assertEqual(settings.enumeration_mode, "owner_index")
        self.assertFalse(settings.user_surfaces_active)
        self.assertFalse(settings.uses_delegated_enumeration)

    def test_load_returns_disabled_settings_with_no_environment(self):
        settings = load_panel_settings(_FakeAppConfig(), environ={})
        self.assertFalse(settings.user_surfaces_active)

    def test_deploy_flag_alone_does_not_activate_user_surfaces(self):
        settings = load_panel_settings(
            _FakeAppConfig(),
            environ={"DEPLOY_ADMINISTRATIVE_PANEL": "true"},
        )
        self.assertTrue(settings.deploy_administrative_panel)
        self.assertFalse(settings.history_enabled)
        self.assertFalse(settings.user_surfaces_active)

    def test_history_flag_alone_does_not_activate_user_surfaces(self):
        settings = load_panel_settings(
            _FakeAppConfig(),
            environ={"PANEL_HISTORY_ENABLED": "true"},
        )
        self.assertFalse(settings.deploy_administrative_panel)
        self.assertFalse(settings.user_surfaces_active)


_FULL_ENV = {
    "DEPLOY_ADMINISTRATIVE_PANEL": "true",
    "PANEL_HISTORY_ENABLED": "true",
    "PANEL_CONVERSATIONS_TOKEN_AUDIENCE": "api://panel/.default",
    "OAUTH_AZURE_AD_TENANT_ID": "11111111-1111-1111-1111-111111111111",
    "DATABASE_ACCOUNT_NAME": "gptragdb",
    "DATABASE_NAME": "gptrag",
}


class PanelSettingsActiveTests(unittest.TestCase):
    def test_both_gates_true_with_full_config_activates_owner_index_default(self):
        settings = load_panel_settings(_FakeAppConfig(), environ=_FULL_ENV)
        self.assertTrue(settings.user_surfaces_active)
        self.assertEqual(settings.enumeration_mode, "owner_index")
        self.assertFalse(settings.uses_delegated_enumeration)
        self.assertEqual(settings.token_audience, "api://panel/.default")
        self.assertEqual(
            settings.tenant_id, "11111111-1111-1111-1111-111111111111"
        )
        self.assertEqual(settings.database_account_name, "gptragdb")
        self.assertEqual(settings.database_name, "gptrag")

    def test_missing_token_audience_fails_closed(self):
        env = {**_FULL_ENV}
        del env["PANEL_CONVERSATIONS_TOKEN_AUDIENCE"]
        with self.assertRaises(PanelConfigError):
            load_panel_settings(_FakeAppConfig(), environ=env)

    def test_missing_tenant_fails_closed(self):
        env = {**_FULL_ENV}
        del env["OAUTH_AZURE_AD_TENANT_ID"]
        with self.assertRaises(PanelConfigError):
            load_panel_settings(_FakeAppConfig(), environ=env)

    def test_missing_database_config_fails_closed(self):
        env = {**_FULL_ENV}
        del env["DATABASE_ACCOUNT_NAME"]
        with self.assertRaises(PanelConfigError):
            load_panel_settings(_FakeAppConfig(), environ=env)

    def test_dedicated_tenant_key_overrides_oauth_tenant(self):
        env = {
            **_FULL_ENV,
            "PANEL_CONVERSATIONS_TENANT_ID": "22222222-2222-2222-2222-222222222222",
        }
        settings = load_panel_settings(_FakeAppConfig(), environ=env)
        self.assertEqual(
            settings.tenant_id, "22222222-2222-2222-2222-222222222222"
        )

    def test_delegated_enumeration_requires_its_own_gate(self):
        env = {
            **_FULL_ENV,
            "PANEL_CONVERSATION_ENUMERATION_MODE": "delegated",
        }
        with self.assertRaises(PanelConfigError):
            load_panel_settings(_FakeAppConfig(), environ=env)

    def test_delegated_enumeration_active_once_own_gate_is_set(self):
        env = {
            **_FULL_ENV,
            "PANEL_CONVERSATION_ENUMERATION_MODE": "delegated",
            "PANEL_HISTORY_OWNER_BINDING_VALIDATED": "true",
        }
        settings = load_panel_settings(_FakeAppConfig(), environ=env)
        self.assertTrue(settings.uses_delegated_enumeration)

    def test_owner_binding_validated_alone_never_disables_owner_index(self):
        """An unmet/absent gate never produces an error; owner_index stays
        the active mechanism (ADR-0004: the panel deploy gate is
        independent of the owner-binding evidence gate)."""
        settings = load_panel_settings(_FakeAppConfig(), environ=_FULL_ENV)
        self.assertTrue(settings.user_surfaces_active)
        self.assertEqual(settings.enumeration_mode, "owner_index")

    def test_invalid_enumeration_mode_rejected(self):
        env = {**_FULL_ENV, "PANEL_CONVERSATION_ENUMERATION_MODE": "bogus"}
        with self.assertRaises(PanelConfigError):
            load_panel_settings(_FakeAppConfig(), environ=env)

    def test_container_names_default_when_unset(self):
        settings = load_panel_settings(_FakeAppConfig(), environ=_FULL_ENV)
        self.assertEqual(
            settings.owner_index_container, "panel-conversation-owner-index"
        )
        self.assertEqual(settings.feedback_container, "panel-feedback")

    def test_container_names_overridable(self):
        env = {
            **_FULL_ENV,
            "PANEL_OWNER_INDEX_DATABASE_CONTAINER": "custom-owner-index",
            "PANEL_FEEDBACK_DATABASE_CONTAINER": "custom-feedback",
        }
        settings = load_panel_settings(_FakeAppConfig(), environ=env)
        self.assertEqual(settings.owner_index_container, "custom-owner-index")
        self.assertEqual(settings.feedback_container, "custom-feedback")


if __name__ == "__main__":
    unittest.main()
