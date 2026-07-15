import unittest
from types import SimpleNamespace

from embed_config import (
    configure_chainlit_allowed_origins,
    EmbedConfigError,
    EmbedSettings,
    load_embed_settings,
)


TENANT_ID = "11111111-2222-3333-4444-555555555555"


class FakeConfig:
    def __init__(self, values=None):
        self.values = values or {}

    def get(self, key, default=None, type=str):
        value = self.values.get(key, default)
        return type(value) if value is not None and type is not None else value


def enabled_env(**overrides):
    values = {
        "CHAINLIT_COPILOT_ENABLED": "true",
        "CHAINLIT_URL": "https://chat.example.com",
        "CHAINLIT_ALLOWED_ORIGINS": "https://portal.example.com",
        "CHAINLIT_COPILOT_ENTRA_TENANT_ID": TENANT_ID,
        "CHAINLIT_COPILOT_ENTRA_AUDIENCE": "api://test",
    }
    values.update(overrides)
    return values


class EmbedConfigTests(unittest.TestCase):
    def test_disabled_by_default_ignores_other_settings(self):
        settings = load_embed_settings(
            FakeConfig({"CHAINLIT_ALLOWED_ORIGINS": "*"}),
            {},
        )
        self.assertEqual(EmbedSettings(), settings)

    def test_enabled_mode_requires_entra_and_normalizes_origins(self):
        settings = load_embed_settings(
            FakeConfig(),
            enabled_env(
                CHAINLIT_ALLOWED_ORIGINS=(
                    "https://PORTAL.example.com/, http://localhost:3000, "
                    "https://portal.example.com"
                )
            ),
        )
        self.assertTrue(settings.uses_entra)
        self.assertEqual(
            ("https://portal.example.com", "http://localhost:3000"),
            settings.allowed_origins,
        )
        self.assertEqual("https://chat.example.com", settings.ui_origin)
        self.assertEqual(
            (
                "https://chat.example.com",
                "https://portal.example.com",
                "http://localhost:3000",
            ),
            settings.runtime_allowed_origins,
        )

    def test_enabled_mode_requires_url_tenant_and_audience(self):
        for key in (
            "CHAINLIT_URL",
            "CHAINLIT_COPILOT_ENTRA_TENANT_ID",
            "CHAINLIT_COPILOT_ENTRA_AUDIENCE",
        ):
            with self.subTest(key=key):
                values = enabled_env()
                values.pop(key)
                with self.assertRaises(EmbedConfigError):
                    load_embed_settings(FakeConfig(), values)

    def test_tenant_id_is_normalized_for_exact_claim_matching(self):
        settings = load_embed_settings(
            FakeConfig(),
            enabled_env(
                CHAINLIT_COPILOT_ENTRA_TENANT_ID=TENANT_ID.upper(),
            ),
        )
        self.assertEqual(TENANT_ID.lower(), settings.entra_tenant_id)

    def test_rejects_unsafe_origins(self):
        for origin in (
            "*",
            "null",
            "https://*.example.com",
            "http://portal.example.com",
            "https://portal.example.com/chat",
            "******portal.example.com",
        ):
            with self.subTest(origin=origin):
                with self.assertRaises(EmbedConfigError):
                    load_embed_settings(
                        FakeConfig(),
                        enabled_env(CHAINLIT_ALLOWED_ORIGINS=origin),
                    )

    def test_rejects_cross_site_cookie_on_http(self):
        with self.assertRaisesRegex(EmbedConfigError, "requires HTTPS"):
            load_embed_settings(
                FakeConfig(),
                enabled_env(
                    CHAINLIT_ALLOWED_ORIGINS="http://localhost:3000",
                    CHAINLIT_COOKIE_SAMESITE="none",
                ),
            )

    def test_rejects_unbounded_session_settings(self):
        for key, value in (
            ("CHAINLIT_COPILOT_SESSION_TTL_SECONDS", "59"),
            ("CHAINLIT_COPILOT_MAX_SESSIONS", "10001"),
            ("CHAINLIT_COPILOT_MAX_SESSIONS", "many"),
        ):
            with self.subTest(key=key):
                with self.assertRaises(EmbedConfigError):
                    load_embed_settings(FakeConfig(), enabled_env(**{key: value}))

    def test_configure_leaves_standalone_origins_unchanged(self):
        chainlit_config = SimpleNamespace(
            project=SimpleNamespace(allow_origins=["https://standalone.example.com"])
        )
        configure_chainlit_allowed_origins(EmbedSettings(), chainlit_config)
        self.assertEqual(
            ["https://standalone.example.com"],
            chainlit_config.project.allow_origins,
        )

    def test_configure_uses_exact_portal_and_ui_origins(self):
        chainlit_config = SimpleNamespace(
            project=SimpleNamespace(allow_origins=["*"])
        )
        enabled = EmbedSettings(
            enabled=True,
            ui_origin="https://chat.example.com",
            allowed_origins=("https://portal.example.com",),
        )
        configure_chainlit_allowed_origins(enabled, chainlit_config)
        self.assertEqual(
            ["https://chat.example.com", "https://portal.example.com"],
            chainlit_config.project.allow_origins,
        )


if __name__ == "__main__":
    unittest.main()
