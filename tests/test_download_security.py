import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, call, Mock, patch
from urllib.parse import urlsplit

import httpx
from azure.core.exceptions import ResourceNotFoundError
from chainlit.user import User
from fastapi import FastAPI
from itsdangerous import URLSafeTimedSerializer

from conversation_security import conversation_belongs_to, get_owned_conversation
from download_security import (
    DownloadStream,
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
OTHER_PRINCIPAL = (
    "99999999-8888-7777-6666-555555555555:"
    "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
)
SESSION_ID = "s" * 43
CONVERSATION_ID = "12345678-1234-4abc-8def-1234567890ab"
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
            conversation_id=CONVERSATION_ID,
            container="documents",
            blob_name="folder/file.pdf",
        )
        grant = manager.verify(url.rsplit("/", 1)[-1])
        self.assertTrue(url.startswith("https://chat.example.com/api/download/"))
        self.assertEqual(PRINCIPAL, grant.principal_id)
        self.assertEqual("folder/file.pdf", grant.blob_name)
        self.assertIsNone(manager.verify("tampered"))

    def test_grant_rejects_legacy_sha1_signature(self):
        manager = DownloadTokenManager(
            secret="secret",
            public_url="https://chat.example.com",
        )
        legacy_token = URLSafeTimedSerializer(
            "secret",
            salt="gpt-rag-download-v1",
            signer_kwargs={"digest_method": hashlib.sha1},
        ).dumps(
            {
                "v": 1,
                "p": PRINCIPAL,
                "c": CONVERSATION_ID,
                "n": "documents",
                "b": "folder/file.pdf",
            }
        )

        self.assertIsNone(manager.verify(legacy_token))

    def test_grant_uses_canonical_public_root_path(self):
        manager = DownloadTokenManager(
            secret="secret",
            public_url="https://portal.example.com/gpt-rag",
        )
        url = manager.issue(
            principal_id=PRINCIPAL,
            conversation_id=CONVERSATION_ID,
            container="documents",
            blob_name="folder/file.pdf",
        )
        self.assertTrue(
            url.startswith(
                "https://portal.example.com/gpt-rag/api/download/"
            )
        )

        for public_url in (
            "https://portal.example.com/gpt-rag/",
            "https://portal.example.com/gpt-rag/../admin",
            "https://portal.example.com/gpt%2Frag",
            "https://portal.example.com/gpt-rag?mode=embed",
        ):
            with self.subTest(public_url=public_url):
                with self.assertRaises(ValueError):
                    DownloadTokenManager(
                        secret="secret",
                        public_url=public_url,
                    )

    def test_rejects_path_traversal(self):
        manager = DownloadTokenManager(secret="secret", public_url="https://chat")
        with self.assertRaises(ValueError):
            manager.issue(
                principal_id=PRINCIPAL,
                conversation_id=CONVERSATION_ID,
                container="documents",
                blob_name="../secret.pdf",
            )
        with self.assertRaises(ValueError):
            manager.issue(
                principal_id=PRINCIPAL,
                conversation_id="../conversations/other",
                container="documents",
                blob_name="file.pdf",
            )
        with self.assertRaises(ValueError):
            manager.issue(
                principal_id=PRINCIPAL,
                conversation_id=CONVERSATION_ID,
                container="conversation-documents",
                blob_name="conversations/mine/%2e%2e/victim/file.pdf",
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
                await get_owned_conversation(CONVERSATION_ID, METADATA)
            )

    async def test_secure_download_route_authorizes_top_level_navigation(self):
        manager = DownloadTokenManager(
            secret="secret",
            public_url="https://chat.example.com",
        )
        url = manager.issue(
            principal_id=PRINCIPAL,
            conversation_id=CONVERSATION_ID,
            container="conversation-documents",
            blob_name=f"conversations/{CONVERSATION_ID}/file.pdf",
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
        resolver = AsyncMock(return_value={"id": CONVERSATION_ID})
        downloader = Mock(
            side_effect=lambda _path: DownloadStream(
                chunks=iter((b"pdf-", b"data")),
                size=8,
            )
        )
        register_secure_download_route(
            app,
            manager=manager,
            download_blob=downloader,
            allowed_containers={"conversation-documents"},
            conversation_container="conversation-documents",
            shared_containers=set(),
            sessions=Sessions(),
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
            )
            wrong_origin = await client.get(
                f"/api/download/{grant_token}",
                headers={"Origin": "https://attacker.example.com"},
            )
            same_origin = await client.get(
                f"/api/download/{grant_token}",
                headers={"Origin": "https://chat.example.com"},
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(403, wrong_origin.status_code)
        self.assertEqual(200, same_origin.status_code)
        self.assertEqual(b"pdf-data", response.content)
        self.assertEqual("8", response.headers["content-length"])
        self.assertEqual("private, no-store", response.headers["cache-control"])
        self.assertIn("file.pdf", response.headers["content-disposition"])
        self.assertEqual(
            [
                call(CONVERSATION_ID, session.user_metadata()),
                call(CONVERSATION_ID, session.user_metadata()),
            ],
            resolver.await_args_list,
        )
        expected_path = (
            "conversation-documents/conversations/"
            f"{CONVERSATION_ID}/file.pdf"
        )
        self.assertEqual(
            [call(expected_path), call(expected_path)],
            downloader.call_args_list,
        )

    async def test_secure_download_route_fails_closed(self):
        manager = DownloadTokenManager(
            secret="secret",
            public_url="https://chat.example.com",
        )
        valid_url = manager.issue(
            principal_id=PRINCIPAL,
            conversation_id=CONVERSATION_ID,
            container="documents",
            blob_name="file.pdf",
        )
        token = urlsplit(valid_url).path.rsplit("/", 1)[-1]
        other_url = manager.issue(
            principal_id=OTHER_PRINCIPAL,
            conversation_id=CONVERSATION_ID,
            container="documents",
            blob_name="file.pdf",
        )
        other_token = urlsplit(other_url).path.rsplit("/", 1)[-1]
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
            cookie_header=None,
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
                sessions=Sessions(),
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
                if authenticated and cookie_header is None
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
                    headers={
                        "Origin": "https://portal.example.com",
                        **(
                            {"Cookie": cookie_header}
                            if cookie_header is not None
                            else {}
                        ),
                    },
                )
            return response

        self.assertEqual(
            401,
            (await request(authenticated=False)).status_code,
        )
        self.assertEqual(
            401,
            (
                await request(
                    cookie_header=(
                        f"{COPILOT_SESSION_COOKIE}={'a' * 43}; "
                        f"{COPILOT_SESSION_COOKIE}={'b' * 43}"
                    )
                )
            ).status_code,
        )
        self.assertEqual(
            404,
            (
                await request(
                    grant_token="tampered",
                    resolver_result={"id": CONVERSATION_ID},
                )
            ).status_code,
        )
        self.assertEqual(
            404,
            (
                await request(
                    grant_token=other_token,
                    resolver_result={"id": CONVERSATION_ID},
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
                    resolver_result={"id": CONVERSATION_ID},
                    shared_containers=set(),
                )
            ).status_code,
        )
        self.assertEqual(
            404,
            (
                await request(
                    resolver_result={"id": CONVERSATION_ID},
                    download_result=ResourceNotFoundError("missing"),
                )
            ).status_code,
        )
        backend_failure = await request(
            resolver_result={"id": CONVERSATION_ID},
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
            conversation_id=CONVERSATION_ID,
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
            sessions=SimpleNamespace(
                get=AsyncMock(return_value=None),
            ),
            conversation_resolver=AsyncMock(
                return_value={"id": CONVERSATION_ID}
            ),
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

    async def test_grant_principal_selects_standalone_cookie_over_other_opaque_cookie(
        self,
    ):
        manager = DownloadTokenManager(
            secret="secret",
            public_url="https://chat.example.com",
        )
        url = manager.issue(
            principal_id=PRINCIPAL,
            conversation_id=CONVERSATION_ID,
            container="documents",
            blob_name="file.pdf",
        )
        token = urlsplit(url).path.rsplit("/", 1)[-1]
        stale_session = SimpleNamespace(
            session_id=SESSION_ID,
            principal_id=OTHER_PRINCIPAL,
            chainlit_token="opaque-chainlit-token",
            auth_mode="entra",
            user_metadata=lambda: {},
        )
        sessions = SimpleNamespace(
            get=AsyncMock(return_value=stale_session),
        )
        app = FastAPI()
        register_secure_download_route(
            app,
            manager=manager,
            download_blob=Mock(return_value=b"data"),
            allowed_containers={"documents"},
            conversation_container="conversation-documents",
            shared_containers={"documents"},
            sessions=sessions,
            conversation_resolver=AsyncMock(
                return_value={"id": CONVERSATION_ID}
            ),
        )
        app.add_middleware(
            CopilotRequestMiddleware,
            settings=EmbedSettings(
                enabled=True,
                auth_mode="entra",
                ui_origin="https://chat.example.com",
                allowed_origins=("https://portal.example.com",),
            ),
            sessions=sessions,
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
                cookies={COPILOT_SESSION_COOKIE: SESSION_ID},
            ) as client:
                response = await client.get(f"/api/download/{token}")

        self.assertEqual(200, response.status_code)
        self.assertEqual(
            [call(SESSION_ID), call(SESSION_ID)],
            sessions.get.await_args_list,
        )

    async def test_bound_copilot_session_is_rechecked_before_download(self):
        manager = DownloadTokenManager(
            secret="secret",
            public_url="https://chat.example.com",
        )
        url = manager.issue(
            principal_id=PRINCIPAL,
            conversation_id=CONVERSATION_ID,
            container="documents",
            blob_name="file.pdf",
        )
        token = urlsplit(url).path.rsplit("/", 1)[-1]
        session = SimpleNamespace(
            session_id=SESSION_ID,
            principal_id=PRINCIPAL,
            chainlit_token="internal-chainlit-token",
            user_metadata=lambda: METADATA,
        )

        class RevokedDuringRequestSessions:
            def __init__(self):
                self.calls = 0

            async def get(self, session_id):
                self.calls += 1
                return session if self.calls == 1 else None

        sessions = RevokedDuringRequestSessions()
        downloader = Mock(return_value=b"data")
        app = FastAPI()
        register_secure_download_route(
            app,
            manager=manager,
            download_blob=downloader,
            allowed_containers={"documents"},
            conversation_container="conversation-documents",
            shared_containers={"documents"},
            sessions=sessions,
            conversation_resolver=AsyncMock(
                return_value={"id": CONVERSATION_ID}
            ),
        )
        app.add_middleware(
            CopilotRequestMiddleware,
            settings=EmbedSettings(
                enabled=True,
                ui_origin="https://chat.example.com",
                allowed_origins=("https://portal.example.com",),
            ),
            sessions=sessions,
        )
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://chat.example.com",
            cookies={COPILOT_SESSION_COOKIE: SESSION_ID},
        ) as client:
            response = await client.get(
                f"/api/download/{token}",
                headers={"Origin": "https://portal.example.com"},
            )

        self.assertEqual(401, response.status_code)
        self.assertEqual(2, sessions.calls)
        downloader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
