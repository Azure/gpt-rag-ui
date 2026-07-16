import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import dependencies
import httpx
import jwt
from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import Response


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

    def test_embed_environment_separates_origin_and_public_root_path(self):
        settings = EmbedSettings(
            enabled=True,
            auth_mode="anonymous",
            ui_origin="https://portal.example.com",
            root_path="/gpt-rag",
            allowed_origins=("https://portal.example.com",),
        )
        with patch.dict(os.environ, {}, clear=True):
            main._configure_embed_environment(settings)

            self.assertEqual(
                "https://portal.example.com/gpt-rag",
                os.environ["CHAINLIT_PUBLIC_URL"],
            )
            self.assertEqual("/gpt-rag", os.environ["CHAINLIT_ROOT_PATH"])
            self.assertEqual(
                settings.chainlit_auth_cookie_name,
                os.environ["CHAINLIT_AUTH_COOKIE_NAME"],
            )
            self.assertEqual(
                "anonymous",
                os.environ["CHAINLIT_COPILOT_AUTH_MODE_EFFECTIVE"],
            )

    def test_chainlit_auth_cookies_are_scoped_to_public_root_path(self):
        from chainlit.auth import cookie as chainlit_cookie

        def set_auth_cookie(_request, response, token):
            response.set_cookie("access_token", token, httponly=True)

        def set_oauth_state_cookie(response, token):
            response.set_cookie("oauth_state", token, httponly=True)

        def clear_oauth_state_cookie(response):
            response.delete_cookie("oauth_state")

        def clear_auth_cookie(request, response):
            for name in request.cookies:
                if name.startswith("access_token"):
                    response.delete_cookie(name)

        server = SimpleNamespace(
            set_auth_cookie=set_auth_cookie,
            clear_auth_cookie=clear_auth_cookie,
            set_oauth_state_cookie=set_oauth_state_cookie,
            clear_oauth_state_cookie=clear_oauth_state_cookie,
        )
        with (
            patch.object(chainlit_cookie, "set_auth_cookie"),
            patch.object(chainlit_cookie, "clear_auth_cookie"),
            patch.object(chainlit_cookie, "set_oauth_state_cookie"),
            patch.object(chainlit_cookie, "clear_oauth_state_cookie"),
            patch.object(chainlit_cookie, "_cookie_path"),
            patch.object(chainlit_cookie, "_auth_cookie_name"),
            patch.object(chainlit_cookie, "_state_cookie_name"),
        ):
            main._scope_chainlit_cookies(server, "/gpt-rag")
            auth_response = Response()
            state_response = Response()
            clear_response = Response()
            server.set_auth_cookie(None, auth_response, "token")
            server.set_oauth_state_cookie(state_response, "state")
            server.clear_oauth_state_cookie(clear_response)

        for response in (
            auth_response,
            state_response,
            clear_response,
        ):
            self.assertIn("Path=/gpt-rag", response.headers["set-cookie"])

    def test_chainlit_cookie_scope_expires_signed_legacy_root_cookie(self):
        from chainlit.auth import cookie as chainlit_cookie

        settings = EmbedSettings(root_path="/gpt-rag")
        cookie_name = settings.chainlit_auth_cookie_name

        def set_auth_cookie(_request, response, token):
            response.set_cookie(cookie_name, token, httponly=True)

        def clear_auth_cookie(request, response):
            for name in request.cookies:
                if name.startswith(cookie_name):
                    response.delete_cookie(name)

        server = SimpleNamespace(
            set_auth_cookie=set_auth_cookie,
            clear_auth_cookie=clear_auth_cookie,
            set_oauth_state_cookie=lambda response, token: None,
            clear_oauth_state_cookie=lambda response: None,
        )
        legacy_token = jwt.encode(
            {
                "identifier": "legacy-user",
                "metadata": {},
                "exp": 1,
            },
            STRONG_SECRET,
            algorithm="HS256",
        )
        request = Request(
            {
                "type": "http",
                "headers": [
                    (
                        b"cookie",
                        f"{cookie_name}={legacy_token}".encode("ascii"),
                    )
                ],
            }
        )

        with (
            patch.dict(
                os.environ,
                {"CHAINLIT_AUTH_SECRET": STRONG_SECRET},
                clear=False,
            ),
            patch.object(chainlit_cookie, "set_auth_cookie"),
            patch.object(chainlit_cookie, "clear_auth_cookie"),
            patch.object(chainlit_cookie, "set_oauth_state_cookie"),
            patch.object(chainlit_cookie, "clear_oauth_state_cookie"),
            patch.object(chainlit_cookie, "_cookie_path"),
            patch.object(chainlit_cookie, "_auth_cookie_name"),
            patch.object(chainlit_cookie, "_state_cookie_name"),
        ):
            main._scope_chainlit_cookies(
                server,
                "/gpt-rag",
                cookie_name,
            )
            response = Response()
            server.set_auth_cookie(request, response, "new-token")

        headers = response.headers.getlist("set-cookie")
        self.assertTrue(
            any(
                f"{cookie_name}=new-token" in header
                and "Path=/gpt-rag" in header
                for header in headers
            )
        )
        self.assertTrue(
            any(
                f"{cookie_name}=\"\"" in header
                and "Path=/" in header
                and "Max-Age=0" in header
                for header in headers
            )
        )

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


class PublicRootPathSmokeTests(unittest.IsolatedAsyncioTestCase):
    async def test_public_contract_is_available_only_beneath_root_path(self):
        host_app = FastAPI()

        async def endpoint():
            return {"ok": True}

        routes = (
            ("GET", "/copilot/index.js"),
            ("POST", "/copilot/auth/bootstrap"),
            ("POST", "/copilot/auth/logout"),
            ("GET", "/project/settings"),
            ("GET", "/ws/socket.io"),
            ("GET", "/assets/app.js"),
            ("GET", "/public/logo.svg"),
            ("GET", "/api/download/grant"),
            ("GET", "/version-footer"),
        )
        for method, path in routes:
            host_app.add_api_route(path, endpoint, methods=[method])

        public_app = main._mount_public_root(
            host_app,
            EmbedSettings(
                enabled=True,
                auth_mode="anonymous",
                ui_origin="https://portal.example.com",
                root_path="/gpt-rag",
                allowed_origins=("https://portal.example.com",),
            ),
        )
        transport = httpx.ASGITransport(app=public_app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://portal.example.com",
        ) as client:
            for method, path in routes:
                with self.subTest(path=path):
                    response = await client.request(
                        method,
                        f"/gpt-rag{path}",
                        params={"transport": "polling"}
                        if path == "/ws/socket.io"
                        else None,
                    )
                    self.assertEqual(200, response.status_code)

                    missing_prefix = await client.request(method, path)
                    self.assertEqual(404, missing_prefix.status_code)

            ambiguous_prefix = await client.get(
                "/gpt-rag-other/copilot/index.js"
            )
            self.assertEqual(404, ambiguous_prefix.status_code)
            encoded_boundary = await client.get(
                "/gpt-rag%2Fcopilot/index.js"
            )
            self.assertEqual(404, encoded_boundary.status_code)
            encoded_root = await client.get(
                "/gpt%2Drag/copilot/index.js"
            )
            self.assertEqual(404, encoded_root.status_code)
            self.assertEqual(404, (await client.get("/docs")).status_code)


if __name__ == "__main__":
    unittest.main()
