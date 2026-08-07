"""Security and behavior tests for the panel's user-facing FastAPI routes
(issue #611, ADR-0004): two-user isolation, forged/guessed-id handling,
identical 404s, app-only rejection, cursor tamper/expiry/cross-user, no
content ever reaching the panel Cosmos fakes, no store read before the
owner gate, delete partial-failure reporting, downstream-error mapping,
and the fail-closed gate matrix.
"""

import json
import os
import time
import unittest
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from jwt.algorithms import RSAAlgorithm
from starlette.testclient import TestClient

os.environ.setdefault("CHAINLIT_AUTH_SECRET", "test-secret-for-panel-routes-tests!!")

from entra_token import EntraTokenValidator
from hosted_conversation_store import (
    ConversationItem,
    ConversationStoreAccessDeniedError,
    ConversationStoreError,
)
from panel_config import PanelSettings
import panel_routes

TENANT_ID = "11111111-2222-3333-4444-555555555555"
AUDIENCE = "api://panel/.default"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
OID_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
OID_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


class FakeConversationStore:
    """In-memory stand-in for ``ConversationStoreClient`` used only by
    these route tests -- reused, never duplicated, as the single store the
    panel routes and (in production) the continuity coordinator share."""

    def __init__(self):
        self.conversations: dict[str, list[ConversationItem]] = {}
        self.owners: dict[str, str] = {}
        self.fail_list_for: set[str] = set()
        self.fail_delete_for: set[str] = set()
        self.list_calls: list[str] = []
        self.delete_calls: list[str] = []

    def seed(self, conversation_id: str, oid: str, items: list[tuple[str, str]]):
        self.conversations[conversation_id] = [
            ConversationItem(item_id=f"item-{i}", role=role, content=content)
            for i, (role, content) in enumerate(items)
        ]
        self.owners[conversation_id] = oid

    async def list_items_ascending(
        self, *, oid, conversation_id, limit, user_access_token=""
    ):
        self.list_calls.append(conversation_id)
        if conversation_id in self.fail_list_for:
            raise ConversationStoreError("simulated read failure")
        owner = self.owners.get(conversation_id)
        if owner is None or owner != oid:
            raise ConversationStoreAccessDeniedError("denied")
        return list(self.conversations[conversation_id])[:limit]

    async def delete_conversation(
        self, *, oid, conversation_id, user_access_token=""
    ):
        self.delete_calls.append(conversation_id)
        if conversation_id in self.fail_delete_for:
            raise ConversationStoreError("simulated delete failure")
        self.conversations.pop(conversation_id, None)
        self.owners.pop(conversation_id, None)


class FakePanelCosmosClient:
    """In-memory stand-in for ``PanelCosmosClient``; also lets tests assert
    every stored document's key set to prove no content ever lands here."""

    def __init__(self, settings: PanelSettings):
        self.settings = settings
        self._data: dict[str, dict[tuple[str, str], dict]] = {
            settings.owner_index_container: {},
            settings.feedback_container: {},
        }
        self.fail_query = False
        self.fail_delete_owner_index = False
        self.fail_delete_feedback_ids: set[str] = set()
        self.read_calls: list[tuple[str, str, str]] = []

    def seed_owner_index(self, conversation_id: str, oid: str, title: str = ""):
        self._data[self.settings.owner_index_container][(conversation_id, oid)] = {
            "id": conversation_id,
            "principal_id": oid,
            "title": title,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }

    def all_documents(self) -> list[dict]:
        docs = []
        for container in self._data.values():
            docs.extend(container.values())
        return docs

    async def read_item(self, container_name, item_id, partition_key):
        self.read_calls.append((container_name, item_id, partition_key))
        return self._data[container_name].get((item_id, partition_key))

    async def upsert_item(self, container_name, body):
        key = (body["id"], body["principal_id"])
        self._data[container_name][key] = dict(body)
        return dict(body)

    async def delete_item(self, container_name, item_id, partition_key):
        if (
            container_name == self.settings.owner_index_container
            and self.fail_delete_owner_index
        ):
            from panel_cosmos import PanelStoreError

            raise PanelStoreError("simulated owner-index delete failure")
        if item_id in self.fail_delete_feedback_ids:
            from panel_cosmos import PanelStoreError

            raise PanelStoreError("simulated feedback delete failure")
        self._data[container_name].pop((item_id, partition_key), None)

    async def query_items(self, container_name, *, query, parameters, partition_key):
        if self.fail_query:
            from panel_cosmos import PanelStoreError

            raise PanelStoreError("simulated query failure")
        params = {p["name"]: p["value"] for p in parameters}
        rows = [
            dict(value)
            for (item_id, pk), value in self._data[container_name].items()
            if pk == partition_key
        ]
        if "@conversation_id" in params:
            rows = [
                row
                for row in rows
                if row.get("conversation_id") == params["@conversation_id"]
            ]
        if container_name == self.settings.owner_index_container:
            rows.sort(key=lambda row: row.get("updated_at") or "", reverse=True)
            skip = params.get("@skip", 0)
            limit = params.get("@limit", len(rows))
            rows = rows[skip : skip + limit]
        return rows


def _panel_settings() -> PanelSettings:
    return PanelSettings(
        deploy_administrative_panel=True,
        history_enabled=True,
        owner_binding_validated=False,
        enumeration_mode="owner_index",
        token_audience=AUDIENCE,
        tenant_id=TENANT_ID,
        database_account_name="acct",
        database_name="db",
        owner_index_container="owner-index",
        feedback_container="feedback",
        cursor_ttl_seconds=60,
    )


class _Harness:
    """Builds a FastAPI app with the panel routes mounted against fakes."""

    def __init__(
        self,
        *,
        settings: PanelSettings | None = None,
        continuity_active: bool = True,
    ):
        self.settings = settings if settings is not None else _panel_settings()
        self.store = FakeConversationStore()
        self.cosmos = FakePanelCosmosClient(self.settings)

        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_jwk = json.loads(RSAAlgorithm.to_jwk(self.private_key.public_key()))
        public_jwk.update({"kid": "test-key", "use": "sig", "alg": "RS256"})
        jwks = {"keys": [public_jwk]}

        async def load_jwks():
            return jwks

        self.validator = EntraTokenValidator(
            tenant_id=self.settings.tenant_id or TENANT_ID,
            audience=self.settings.token_audience or AUDIENCE,
            clock_skew_seconds=0,
            jwks_loader=load_jwks,
        )

        self.app = FastAPI()
        self._patches = [
            patch("panel_routes.get_panel_cosmos_client", return_value=self.cosmos),
            patch("panel_routes.EntraTokenValidator", return_value=self.validator),
        ]
        for p in self._patches:
            p.start()
        panel_routes.register_panel_routes(
            self.app,
            config=object(),
            settings=self.settings,
            continuity_active=lambda: continuity_active,
            get_conversation_store=lambda: self.store,
        )
        self.client = TestClient(self.app)

    def close(self):
        for p in self._patches:
            p.stop()

    def token(self, oid: str, **overrides) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": self.settings.token_audience or AUDIENCE,
            "tid": self.settings.tenant_id or TENANT_ID,
            "oid": oid,
            "scp": "user_impersonation",
            "ver": "2.0",
            "iat": now,
            "nbf": now - 1,
            "exp": now + 300,
        }
        claims.update(overrides)
        return jwt.encode(
            claims, self.private_key, algorithm="RS256", headers={"kid": "test-key"}
        )

    def auth(self, oid: str, **overrides) -> dict:
        return {"Authorization": f"Bearer {self.token(oid, **overrides)}"}


class GateMatrixTests(unittest.TestCase):
    def test_disabled_panel_returns_503_on_every_endpoint(self):
        harness = _Harness(settings=PanelSettings())
        try:
            client = harness.client
            headers = harness.auth(OID_A)
            self.assertEqual(
                client.get("/panel/conversations", headers=headers).status_code, 503
            )
            self.assertEqual(
                client.get(
                    "/panel/conversations/conv-1/messages", headers=headers
                ).status_code,
                503,
            )
            self.assertEqual(
                client.post(
                    "/panel/conversations/conv-1/feedback",
                    headers=headers,
                    json={"feedback_id": "fb-1", "message_ref": "m-1"},
                ).status_code,
                503,
            )
            self.assertEqual(
                client.get(
                    "/panel/conversations/conv-1/feedback", headers=headers
                ).status_code,
                503,
            )
            self.assertEqual(
                client.delete(
                    "/panel/conversations/conv-1", headers=headers
                ).status_code,
                503,
            )
        finally:
            harness.close()

    def test_deploy_flag_alone_still_returns_503(self):
        settings = PanelSettings(deploy_administrative_panel=True, history_enabled=False)
        harness = _Harness(settings=settings)
        try:
            response = harness.client.get("/panel/conversations")
            self.assertEqual(response.status_code, 503)
        finally:
            harness.close()

    def test_panel_enabled_but_continuity_inactive_returns_503(self):
        harness = _Harness(continuity_active=False)
        try:
            headers = harness.auth(OID_A)
            response = harness.client.get("/panel/conversations", headers=headers)
            self.assertEqual(response.status_code, 503)
        finally:
            harness.close()

    def test_fully_active_returns_200_for_empty_list(self):
        harness = _Harness()
        try:
            headers = harness.auth(OID_A)
            response = harness.client.get("/panel/conversations", headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["items"], [])
        finally:
            harness.close()


class AuthenticationMatrixTests(unittest.TestCase):
    def test_missing_bearer_is_401(self):
        harness = _Harness()
        try:
            response = harness.client.get("/panel/conversations")
            self.assertEqual(response.status_code, 401)
        finally:
            harness.close()

    def test_wrong_audience_is_401(self):
        harness = _Harness()
        try:
            headers = harness.auth(OID_A, aud="api://something-else")
            response = harness.client.get("/panel/conversations", headers=headers)
            self.assertEqual(response.status_code, 401)
        finally:
            harness.close()

    def test_app_only_token_is_403(self):
        harness = _Harness()
        try:
            headers = harness.auth(OID_A, scp=None)
            response = harness.client.get("/panel/conversations", headers=headers)
            self.assertEqual(response.status_code, 403)
        finally:
            harness.close()

    def test_idtyp_app_is_403(self):
        harness = _Harness()
        try:
            headers = harness.auth(OID_A, idtyp="app")
            response = harness.client.get("/panel/conversations", headers=headers)
            self.assertEqual(response.status_code, 403)
        finally:
            harness.close()


class TwoUserIsolationTests(unittest.TestCase):
    def setUp(self):
        self.harness = _Harness()
        self.harness.store.seed("conv-a", OID_A, [("user", "hi"), ("assistant", "hello")])
        self.harness.cosmos.seed_owner_index("conv-a", OID_A, title="A's chat")
        self.addCleanup(self.harness.close)

    def test_list_only_returns_the_callers_own_conversations(self):
        response = self.harness.client.get(
            "/panel/conversations", headers=self.harness.auth(OID_A)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual([item["id"] for item in response.json()["items"]], ["conv-a"])

        response_b = self.harness.client.get(
            "/panel/conversations", headers=self.harness.auth(OID_B)
        )
        self.assertEqual(response_b.status_code, 200)
        self.assertEqual(response_b.json()["items"], [])

    def test_owner_can_read_messages(self):
        response = self.harness.client.get(
            "/panel/conversations/conv-a/messages",
            headers=self.harness.auth(OID_A),
        )
        self.assertEqual(response.status_code, 200)
        roles = [item["role"] for item in response.json()["items"]]
        self.assertEqual(roles, ["user", "assistant"])

    def test_non_owner_gets_identical_404_as_missing_conversation(self):
        forged_response = self.harness.client.get(
            "/panel/conversations/conv-a/messages",
            headers=self.harness.auth(OID_B),
        )
        missing_response = self.harness.client.get(
            "/panel/conversations/does-not-exist/messages",
            headers=self.harness.auth(OID_B),
        )
        self.assertEqual(forged_response.status_code, 404)
        self.assertEqual(missing_response.status_code, 404)
        self.assertEqual(forged_response.json(), missing_response.json())

    def test_guessed_conversation_id_is_404_not_owner_disclosure(self):
        response = self.harness.client.get(
            "/panel/conversations/some-guessed-conversation-id/messages",
            headers=self.harness.auth(OID_A),
        )
        self.assertEqual(response.status_code, 404)

    def test_non_owner_cannot_delete(self):
        response = self.harness.client.delete(
            "/panel/conversations/conv-a", headers=self.harness.auth(OID_B)
        )
        self.assertEqual(response.status_code, 404)
        # The system of record must never even be touched for a non-owner.
        self.assertEqual(self.harness.store.delete_calls, [])

    def test_non_owner_cannot_read_or_write_feedback(self):
        get_response = self.harness.client.get(
            "/panel/conversations/conv-a/feedback", headers=self.harness.auth(OID_B)
        )
        post_response = self.harness.client.post(
            "/panel/conversations/conv-a/feedback",
            headers=self.harness.auth(OID_B),
            json={"feedback_id": "fb-1", "message_ref": "m-1"},
        )
        self.assertEqual(get_response.status_code, 404)
        self.assertEqual(post_response.status_code, 404)

    def test_no_store_read_before_owner_gate(self):
        """A non-owner/forged request must never reach the
        managed-Conversations store at all."""
        self.harness.client.get(
            "/panel/conversations/conv-a/messages",
            headers=self.harness.auth(OID_B),
        )
        self.assertEqual(self.harness.store.list_calls, [])


class CursorSigningSecretUnavailableTests(unittest.TestCase):
    """A missing/empty CHAINLIT_AUTH_SECRET at request time is a server
    misconfiguration, not a caller input problem -- it must map to an
    explicit 502, never an unhandled 500."""

    def test_missing_signing_secret_is_502_not_500(self):
        harness = _Harness()
        try:
            with patch.dict(os.environ, {"CHAINLIT_AUTH_SECRET": ""}, clear=False):
                response = harness.client.get(
                    "/panel/conversations", headers=harness.auth(OID_A)
                )
            self.assertEqual(response.status_code, 502)
        finally:
            harness.close()


class CursorSecurityTests(unittest.TestCase):
    def setUp(self):
        self.harness = _Harness()
        for i in range(3):
            self.harness.cosmos.seed_owner_index(f"conv-{i}", OID_A)
        self.addCleanup(self.harness.close)

    def test_tampered_cursor_is_422(self):
        response = self.harness.client.get(
            "/panel/conversations",
            headers=self.harness.auth(OID_A),
            params={"cursor": "not-a-real-cursor"},
        )
        self.assertEqual(response.status_code, 422)

    def test_expired_cursor_is_422(self):
        from panel_cursor import PanelCursorManager

        short_ttl_settings = PanelSettings(
            **{**_panel_settings().__dict__, "cursor_ttl_seconds": 1}
        )
        harness = _Harness(settings=short_ttl_settings)
        try:
            for i in range(3):
                harness.cosmos.seed_owner_index(f"conv-{i}", OID_A)
            manager = PanelCursorManager(
                secret=os.environ["CHAINLIT_AUTH_SECRET"], ttl_seconds=1
            )
            # Deterministically mint a cursor whose embedded timestamp is
            # far in the past, instead of relying on a real sleep (which is
            # flaky under load): the itsdangerous TimestampSigner used
            # internally calls time.time() once at mint time.
            with patch(
                "itsdangerous.timed.time.time",
                return_value=time.time() - 1000,
            ):
                token = manager.mint(oid=OID_A, skip=1)
            response = harness.client.get(
                "/panel/conversations",
                headers=harness.auth(OID_A),
                params={"cursor": token},
            )
            self.assertEqual(response.status_code, 422)
        finally:
            harness.close()

    def test_cursor_minted_for_another_user_is_rejected(self):
        from panel_cursor import PanelCursorManager

        manager = PanelCursorManager(
            secret=os.environ["CHAINLIT_AUTH_SECRET"], ttl_seconds=60
        )
        token = manager.mint(oid=OID_B, skip=1)
        response = self.harness.client.get(
            "/panel/conversations",
            headers=self.harness.auth(OID_A),
            params={"cursor": token},
        )
        self.assertEqual(response.status_code, 422)

    def test_valid_cursor_pages_results(self):
        first = self.harness.client.get(
            "/panel/conversations",
            headers=self.harness.auth(OID_A),
            params={"limit": 2},
        )
        self.assertEqual(first.status_code, 200)
        body = first.json()
        self.assertEqual(len(body["items"]), 2)
        self.assertIsNotNone(body["next_cursor"])

        second = self.harness.client.get(
            "/panel/conversations",
            headers=self.harness.auth(OID_A),
            params={"limit": 2, "cursor": body["next_cursor"]},
        )
        self.assertEqual(second.status_code, 200)
        self.assertEqual(len(second.json()["items"]), 1)
        self.assertIsNone(second.json()["next_cursor"])


class FeedbackContentTests(unittest.TestCase):
    def setUp(self):
        self.harness = _Harness()
        self.harness.store.seed("conv-a", OID_A, [("user", "hi")])
        self.harness.cosmos.seed_owner_index("conv-a", OID_A)
        self.addCleanup(self.harness.close)

    def test_create_and_read_own_feedback(self):
        create = self.harness.client.post(
            "/panel/conversations/conv-a/feedback",
            headers=self.harness.auth(OID_A),
            json={
                "feedback_id": "fb-1",
                "message_ref": "m-1",
                "rating": 1,
                "category": "helpful",
                "comment": "Nice answer",
            },
        )
        self.assertEqual(create.status_code, 200)

        listing = self.harness.client.get(
            "/panel/conversations/conv-a/feedback",
            headers=self.harness.auth(OID_A),
        )
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(len(listing.json()["items"]), 1)

    def test_malformed_feedback_body_is_422(self):
        response = self.harness.client.post(
            "/panel/conversations/conv-a/feedback",
            headers=self.harness.auth(OID_A),
            json={
                "feedback_id": "fb-1",
                "message_ref": "m-1",
                "rating": 999,
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_extra_field_in_feedback_body_is_422(self):
        response = self.harness.client.post(
            "/panel/conversations/conv-a/feedback",
            headers=self.harness.auth(OID_A),
            json={
                "feedback_id": "fb-1",
                "message_ref": "m-1",
                "unexpected_field": "not allowed",
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_repeated_feedback_id_is_idempotent(self):
        for _ in range(2):
            response = self.harness.client.post(
                "/panel/conversations/conv-a/feedback",
                headers=self.harness.auth(OID_A),
                json={"feedback_id": "fb-1", "message_ref": "m-1", "rating": 1},
            )
            self.assertEqual(response.status_code, 200)
        listing = self.harness.client.get(
            "/panel/conversations/conv-a/feedback",
            headers=self.harness.auth(OID_A),
        )
        self.assertEqual(len(listing.json()["items"]), 1)

    def test_no_message_content_ever_stored_in_panel_cosmos(self):
        self.harness.client.post(
            "/panel/conversations/conv-a/feedback",
            headers=self.harness.auth(OID_A),
            json={
                "feedback_id": "fb-1",
                "message_ref": "m-1",
                "rating": 1,
                "comment": "the assistant said the secret document text",
            },
        )
        for doc in self.harness.cosmos.all_documents():
            self.assertNotIn("content", doc)
            self.assertNotIn("messages", doc)
            self.assertNotIn("citations", doc)


class DownstreamErrorTests(unittest.TestCase):
    def setUp(self):
        self.harness = _Harness()
        self.harness.store.seed("conv-a", OID_A, [("user", "hi")])
        self.harness.cosmos.seed_owner_index("conv-a", OID_A)
        self.addCleanup(self.harness.close)

    def test_messages_store_failure_is_502(self):
        self.harness.store.fail_list_for.add("conv-a")
        response = self.harness.client.get(
            "/panel/conversations/conv-a/messages", headers=self.harness.auth(OID_A)
        )
        self.assertEqual(response.status_code, 502)

    def test_cosmos_query_failure_on_list_is_502(self):
        self.harness.cosmos.fail_query = True
        response = self.harness.client.get(
            "/panel/conversations", headers=self.harness.auth(OID_A)
        )
        self.assertEqual(response.status_code, 502)

    def test_delete_store_failure_is_502_and_metadata_untouched(self):
        self.harness.store.fail_delete_for.add("conv-a")
        response = self.harness.client.delete(
            "/panel/conversations/conv-a", headers=self.harness.auth(OID_A)
        )
        self.assertEqual(response.status_code, 502)
        # Metadata must remain intact -- no partial cleanup on a SoR failure.
        row = self.harness.cosmos._data[self.harness.settings.owner_index_container].get(
            ("conv-a", OID_A)
        )
        self.assertIsNotNone(row)


class DeletePartialFailureTests(unittest.TestCase):
    def setUp(self):
        self.harness = _Harness()
        self.harness.store.seed("conv-a", OID_A, [("user", "hi")])
        self.harness.cosmos.seed_owner_index("conv-a", OID_A)
        self.addCleanup(self.harness.close)

    def test_full_success_reports_deleted(self):
        response = self.harness.client.delete(
            "/panel/conversations/conv-a", headers=self.harness.auth(OID_A)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "deleted")

    def test_owner_index_cleanup_failure_reports_partial_not_success(self):
        self.harness.cosmos.fail_delete_owner_index = True
        response = self.harness.client.delete(
            "/panel/conversations/conv-a", headers=self.harness.auth(OID_A)
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "partial")
        self.assertTrue(body["detail"])
        # The system of record delete must still have happened.
        self.assertEqual(self.harness.store.delete_calls, ["conv-a"])


if __name__ == "__main__":
    unittest.main()
