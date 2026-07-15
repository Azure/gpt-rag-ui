import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import urlsplit

import httpx
from azure.core.exceptions import ResourceNotFoundError
from chainlit.user import User
from fastapi import FastAPI

from conversation_security import conversation_belongs_to, get_owned_conversation
from download_security import (
    DownloadTokenManager,
    is_download_target_allowed,
    register_secure_download_route,
)
from embed_auth import COPILOT_SESSION_COOKIE
from embed_config import EmbedSettings
from embed_security import CopilotRequestMiddleware


PRINCIPAL = (
    "11111111-2222-3333-4444-555555555555:"
    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)
SESSION_ID = "s" * 43
METADATA = {
    "principal_id": PRINCIPAL,
    "tenant_id": "11111111-2222-3333-4444-555555555555",
    "object_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "access_token": "token",
}


class DownloadSecurityTests(unittest.IsolatedAsyncioTestCase):
    def test_grant_is_absolute_signed_and_principal_bound(self):
        manager = DownloadTokenManager(
            secret="secret",
            public_url="https://chat.example.com",
        )
        url = manager.issue(
            principal_id=PRINCIPAL,
            conversation_id="conversation",
            container="documents",
            blob_name="folder/file.pdf",
        )
        grant = manager.verify(url.rsplit("/", 1)[-1])
        self.assertTrue(url.startswith("https://chat.example.com/api/download/"))
        self.assertEqual(PRINCIPAL, grant.principal_id)
        self.assertEqual("folder/file.pdf", grant.blob_name)
        self.assertIsNone(manager.verify("tampered"))

    def test_rejects_path_traversal(self):
        manager = DownloadTokenManager(secret="secret", public_url="https://chat")
        with self.assertRaises(ValueError):
            manager.issue(
                principal_id=PRINCIPAL,
                conversation_id="conversation",
                container="documents",
                blob_name="../secret.pdf",
            )

    def test_download_target_policy_is_default_deny_and_conversation_bound(self):
        self.assertTrue(
            is_download_target_allowed(
                conversation_id="mine",
                container="conversation-documents",
                blob_name="conversations/mine/file.pdf",
                conversation_container="conversation-documents",
                shared_containers=set(),
            )
        )
        self.assertFalse(
            is_download_target_allowed(
                conversation_id="mine",
                container="conversation-documents",
                blob_name="conversations/other/file.pdf",
                conversation_container="conversation-documents",
                shared_containers=set(),
            )
        )
        self.assertFalse(
            is_download_target_allowed(
                conversation_id="mine",
                container="documents",
                blob_name="private.pdf",
                conversation_container="conversation-documents",
                shared_containers=set(),
            )
        )
        self.assertTrue(
            is_download_target_allowed(
                conversation_id="mine",
                container="documents",
                blob_name="shared.pdf",
                conversation_container="conversation-documents",
                shared_containers={"documents"},
            )
        )

    def test_conversation_identity_requires_matching_tenant_and_object(self):
        self.assertTrue(
            conversation_belongs_to(
                {
                    "principal_id": METADATA["object_id"],
                    "tenant_id": METADATA["tenant_id"],
                },
                METADATA,
            )
        )
        self.assertTrue(
            conversation_belongs_to(
                {"principal_id": METADATA["object_id"]},
                METADATA,
            )
        )
        self.assertFalse(
            conversation_belongs_to(
                {"principal_id": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"},
                METADATA,
            )
        )
        self.assertFalse(
            conversation_belongs_to(
                {
                    "principal_id": METADATA["object_id"],
                    "tenant_id": "99999999-8888-7777-6666-555555555555",
                },
                METADATA,
            )
        )
        self.assertFalse(conversation_belongs_to({}, METADATA))

    def test_declared_session_principal_must_match_tid_and_oid(self):
        mismatched_metadata = {
            **METADATA,
            "principal_id": (
                "99999999-8888-7777-6666-555555555555:"
                "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
            ),
        }
        self.assertFalse(
            conversation_belongs_to(
                {"principal_id": METADATA["object_id"]},
                mismatched_metadata,
            )
        )

    async def test_owned_conversation_fails_closed(self):
        with (
            patch(
                "conversation_security.resolve_access_token",
                AsyncMock(return_value="token"),
            ),
            patch(
                "conversation_security.call_orchestrator_get_conversation",
                AsyncMock(
                    return_value={
                        "principal_id": (
                            "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
                        )
                    }
                ),
            ),
        ):
            self.assertIsNone(
                await get_owned_conversation("conversation", METADATA)
            )

    async def test_secure_download_route_authorizes_exact_portal_origin(self):
        manager = DownloadTokenManager(
            secret="secret",
            public_url="https://chat.example.com",
        )
        url = manager.issue(
            principal_id=PRINCIPAL,
            conversation_id="conversation",
            container="conversation-documents",
            blob_name="conversations/conversation/file.pdf",
        )
        grant_token = urlsplit(url).path.rsplit("/", 1)[-1]
        session = SimpleNamespace(
            principal_id=PRINCIPAL,
            chainlit_token="internal-chainlit-token",
            user_metadata=lambda: {
                **METADATA,
                "auth_source": "copilot_session",
                "copilot_session_id": SESSION_ID,
            },
        )

        class Sessions:
            async def get(self, session_id):
                return session if session_id == SESSION_ID else None

        app = FastAPI()
        resolver = AsyncMock(return_value={"id": "conversation"})
        downloader = Mock(return_value=b"pdf-data")
        register_secure_download_route(
            app,
            manager=manager,
            download_blob=downloader,
            allowed_containers={"conversation-documents"},
            conversation_container="conversation-documents",
            shared_containers=set(),
            conversation_resolver=resolver,
        )
        app.add_middleware(
            CopilotRequestMiddleware,
            settings=EmbedSettings(
                enabled=True,
                ui_origin="https://chat.example.com",
                allowed_origins=("https://portal.example.com",),
            ),
            sessions=Sessions(),
        )
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://chat.example.com",
            cookies={COPILOT_SESSION_COOKIE: SESSION_ID},
        ) as client:
            response = await client.get(
                f"/api/download/{grant_token}",
                headers={"Origin": "https://portal.example.com"},
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(b"pdf-data", response.content)
        self.assertEqual("private, no-store", response.headers["cache-control"])
        self.assertIn("file.pdf", response.headers["content-disposition"])
        resolver.assert_awaited_once_with(
            "conversation",
            session.user_metadata(),
        )
        downloader.assert_called_once_with(
            "conversation-documents/conversations/conversation/file.pdf"
        )

    async def test_secure_download_route_fails_closed(self):
        manager = DownloadTokenManager(
            secret="secret",
            public_url="https://chat.example.com",
        )
        valid_url = manager.issue(
            principal_id=PRINCIPAL,
            conversation_id="conversation",
            container="documents",
            blob_name="file.pdf",
        )
        token = urlsplit(valid_url).path.rsplit("/", 1)[-1]
        session = SimpleNamespace(
            principal_id=PRINCIPAL,
            chainlit_token="internal-chainlit-token",
            user_metadata=lambda: METADATA,
        )

        class Sessions:
            async def get(self, session_id):
                return session if session_id == SESSION_ID else None

        async def request(
            *,
            grant_token=token,
            resolver_result=None,
            download_result=b"data",
            authenticated=True,
            shared_containers=None,
        ):
            app = FastAPI()
            resolver = AsyncMock(return_value=resolver_result)
            downloader = Mock()
            if isinstance(download_result, Exception):
                downloader.side_effect = download_result
            else:
                downloader.return_value = download_result
            register_secure_download_route(
                app,
                manager=manager,
                download_blob=downloader,
                allowed_containers={"documents"},
                conversation_container="conversation-documents",
                shared_containers=(
                    {"documents"}
                    if shared_containers is None
                    else shared_containers
                ),
                conversation_resolver=resolver,
            )
            app.add_middleware(
                CopilotRequestMiddleware,
                settings=EmbedSettings(
                    enabled=True,
                    ui_origin="https://chat.example.com",
                    allowed_origins=("https://portal.example.com",),
                ),
                sessions=Sessions(),
            )
            cookies = (
                {COPILOT_SESSION_COOKIE: SESSION_ID}
                if authenticated
                else {}
            )
            transport = httpx.ASGITransport(
                app=app,
                raise_app_exceptions=False,
            )
            async with httpx.AsyncClient(
                transport=transport,
                base_url="https://chat.example.com",
                cookies=cookies,
            ) as client:
                response = await client.get(
                    f"/api/download/{grant_token}",
                    headers={"Origin": "https://portal.example.com"},
                )
            return response

        self.assertEqual(
            401,
            (await request(authenticated=False)).status_code,
        )
        self.assertEqual(
            404,
            (
                await request(
                    grant_token="tampered",
                    resolver_result={"id": "conversation"},
                )
            ).status_code,
        )
        self.assertEqual(
            404,
            (await request(resolver_result=None)).status_code,
        )
        self.assertEqual(
            404,
            (
                await request(
                    resolver_result={"id": "conversation"},
                    shared_containers=set(),
                )
            ).status_code,
        )
        self.assertEqual(
            404,
            (
                await request(
                    resolver_result={"id": "conversation"},
                    download_result=ResourceNotFoundError("missing"),
                )
            ).status_code,
        )
        backend_failure = await request(
            resolver_result={"id": "conversation"},
            download_result=RuntimeError("backend-secret"),
        )
        self.assertEqual(500, backend_failure.status_code)
        self.assertNotIn("backend-secret", backend_failure.text)

    async def test_download_accepts_standalone_chainlit_session(self):
        manager = DownloadTokenManager(
            secret="secret",
            public_url="https://chat.example.com",
        )
        url = manager.issue(
            principal_id=PRINCIPAL,
            conversation_id="conversation",
            container="documents",
            blob_name="file.pdf",
        )
        token = urlsplit(url).path.rsplit("/", 1)[-1]

        app = FastAPI()
        register_secure_download_route(
            app,
            manager=manager,
            download_blob=Mock(return_value=b"data"),
            allowed_containers={"documents"},
            conversation_container="conversation-documents",
            shared_containers={"documents"},
            conversation_resolver=AsyncMock(return_value={"id": "conversation"}),
        )
        oauth_user = User(
            identifier=PRINCIPAL,
            metadata={
                **METADATA,
                "auth_source": "oauth",
                "authorized": True,
            },
        )
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        with (
            patch(
                "download_security.get_token_from_cookies",
                return_value="chainlit-token",
            ),
            patch(
                "download_security.authenticate_user",
                AsyncMock(return_value=oauth_user),
            ),
        ):
            async with httpx.AsyncClient(
                transport=transport,
                base_url="https://chat.example.com",
            ) as client:
                response = await client.get(f"/api/download/{token}")
        self.assertEqual(200, response.status_code)


if __name__ == "__main__":
    unittest.main()
