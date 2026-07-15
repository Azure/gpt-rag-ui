import unittest
from types import SimpleNamespace

from embed_config import (
    configure_chainlit_allowed_origins,
    EmbedConfigError,
    EmbedSettings,
    load_embed_settings,
)


class FakeConfig:
    def __init__(self, values=None):
        self.values = values or {}

    def get(self, key, default=None, type=str):
        value = self.values.get(key, default)
        return type(value) if value is not None and type is not None else value


class EmbedConfigTests(unittest.TestCase):
    def test_disabled_by_default_ignores_other_settings(self):
        settings = load_embed_settings(
            FakeConfig(
                {
                    "CHAINLIT_ALLOWED_ORIGINS": "*",
                    "CHAINLIT_COPILOT_AUTH_MODE": "invalid",
                }
            ),
            {},
        )

        self.assertEqual(EmbedSettings(), settings)

    def test_enabled_anonymous_mode_normalizes_explicit_origins(self):
        settings = load_embed_settings(
            FakeConfig(),
            {
                "CHAINLIT_COPILOT_ENABLED": "true",
                "CHAINLIT_ALLOWED_ORIGINS": (
                    "https://PORTAL.example.com/, http://localhost:3000, "
                    "https://portal.example.com"
                ),
            },
        )

        self.assertTrue(settings.enabled)
        self.assertEqual("anonymous", settings.auth_mode)
        self.assertEqual(
            ("https://portal.example.com", "http://localhost:3000"),
            settings.allowed_origins,
        )
        self.assertEqual("lax", settings.cookie_samesite)

    def test_enabled_entra_mode_requires_tenant_and_audience(self):
        with self.assertRaisesRegex(
            EmbedConfigError, "CHAINLIT_COPILOT_ENTRA_TENANT_ID"
        ):
            load_embed_settings(
                FakeConfig(),
                {
                    "CHAINLIT_COPILOT_ENABLED": "true",
                    "CHAINLIT_ALLOWED_ORIGINS": "https://portal.example.com",
                    "CHAINLIT_COPILOT_AUTH_MODE": "entra",
                },
            )

    def test_enabled_entra_mode_loads_secure_settings(self):
        settings = load_embed_settings(
            FakeConfig(),
            {
                "CHAINLIT_COPILOT_ENABLED": "true",
                "CHAINLIT_ALLOWED_ORIGINS": "https://portal.example.com",
                "CHAINLIT_COPILOT_AUTH_MODE": "entra",
                "CHAINLIT_COOKIE_SAMESITE": "none",
                "CHAINLIT_COPILOT_ENTRA_TENANT_ID": (
                    "11111111-2222-3333-4444-555555555555"
                ),
                "CHAINLIT_COPILOT_ENTRA_AUDIENCE": (
                    "api://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                ),
            },
        )

        self.assertTrue(settings.uses_entra)
        self.assertEqual("none", settings.cookie_samesite)
        self.assertEqual("user_impersonation", settings.entra_required_scope)
        self.assertEqual(
            "https://login.microsoftonline.com/"
            "11111111-2222-3333-4444-555555555555/v2.0",
            settings.entra_issuer,
        )

    def test_rejects_malformed_required_scope(self):
        with self.assertRaisesRegex(
            EmbedConfigError, "CHAINLIT_COPILOT_ENTRA_REQUIRED_SCOPE"
        ):
            load_embed_settings(
                FakeConfig(),
                {
                    "CHAINLIT_COPILOT_ENABLED": "true",
                    "CHAINLIT_ALLOWED_ORIGINS": "https://portal.example.com",
                    "CHAINLIT_COPILOT_AUTH_MODE": "entra",
                    "CHAINLIT_COPILOT_ENTRA_TENANT_ID": (
                        "11111111-2222-3333-4444-555555555555"
                    ),
                    "CHAINLIT_COPILOT_ENTRA_AUDIENCE": "api://test",
                    "CHAINLIT_COPILOT_ENTRA_REQUIRED_SCOPE": "scope one",
                },
            )

    def test_rejects_malformed_enable_flag(self):
        with self.assertRaisesRegex(EmbedConfigError, "CHAINLIT_COPILOT_ENABLED"):
            load_embed_settings(
                FakeConfig(),
                {"CHAINLIT_COPILOT_ENABLED": "sometimes"},
            )

    def test_rejects_wildcards_and_non_local_http_origins(self):
        for origin in ("*", "https://*.example.com", "http://portal.example.com"):
            with self.subTest(origin=origin):
                with self.assertRaises(EmbedConfigError):
                    load_embed_settings(
                        FakeConfig(),
                        {
                            "CHAINLIT_COPILOT_ENABLED": "true",
                            "CHAINLIT_ALLOWED_ORIGINS": origin,
                        },
                    )

    def test_rejects_origin_paths_credentials_and_null_origin(self):
        for origin in (
            "https://portal.example.com/chat",
            "https://user:password@portal.example.com",
            "null",
        ):
            with self.subTest(origin=origin):
                with self.assertRaises(EmbedConfigError):
                    load_embed_settings(
                        FakeConfig(),
                        {
                            "CHAINLIT_COPILOT_ENABLED": "true",
                            "CHAINLIT_ALLOWED_ORIGINS": origin,
                        },
                    )

    def test_rejects_cross_site_cookie_on_http(self):
        with self.assertRaisesRegex(EmbedConfigError, "requires HTTPS"):
            load_embed_settings(
                FakeConfig(),
                {
                    "CHAINLIT_COPILOT_ENABLED": "true",
                    "CHAINLIT_ALLOWED_ORIGINS": "http://localhost:3000",
                    "CHAINLIT_COOKIE_SAMESITE": "none",
                },
            )

    def test_configure_leaves_standalone_origins_unchanged(self):
        chainlit_config = SimpleNamespace(
            project=SimpleNamespace(
                allow_origins=["https://standalone.example.com"]
            )
        )

        configure_chainlit_allowed_origins(EmbedSettings(), chainlit_config)

        self.assertEqual(
            ["https://standalone.example.com"],
            chainlit_config.project.allow_origins,
        )

    def test_configure_sets_explicit_origins_in_memory_when_enabled(self):
        chainlit_config = SimpleNamespace(
            project=SimpleNamespace(allow_origins=["*"])
        )
        enabled = EmbedSettings(
            enabled=True,
            allowed_origins=("https://portal.example.com",),
        )

        configure_chainlit_allowed_origins(enabled, chainlit_config)

        self.assertEqual(
            ["https://portal.example.com"],
            chainlit_config.project.allow_origins,
        )


if __name__ == "__main__":
    unittest.main()
