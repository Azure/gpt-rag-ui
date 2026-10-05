import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from gpt_rag_ui.clients import orchestrator_client as oc


class ServiceTokenTests(unittest.TestCase):
    def setUp(self):
        oc._service_token_cache.update(token=None, expires_on=0, scope=None)
        self.cred = Mock()
        self.cred.get_token.return_value = SimpleNamespace(token="tok", expires_on=time.time() + 3600)
        self._orig = oc._service_credential
        oc._service_credential = self.cred

    def tearDown(self):
        oc._service_credential = self._orig
        oc._service_token_cache.update(token=None, expires_on=0, scope=None)

    def _aud(self, value):
        return patch.object(oc, "_get_config_value", side_effect=lambda k, default=None: value if k == "ORCHESTRATOR_AUTH_AUDIENCE" else default)

    def test_no_audience_returns_none(self):
        with self._aud(""):
            self.assertIsNone(oc._get_service_token())
        self.cred.get_token.assert_not_called()

    def test_scope_appends_default(self):
        with self._aud("api://abc"):
            self.assertEqual(oc._service_token_scope(), "api://abc/.default")

    def test_token_is_cached(self):
        with self._aud("abc"):
            self.assertEqual(oc._get_service_token(), "tok")
            self.assertEqual(oc._get_service_token(), "tok")
        self.cred.get_token.assert_called_once_with("abc/.default")

    def test_credential_error_returns_none(self):
        self.cred.get_token.side_effect = RuntimeError("boom")
        with self._aud("abc"):
            self.assertIsNone(oc._get_service_token())

    def test_apply_adds_header(self):
        headers = {}
        with self._aud("abc"):
            oc._apply_service_token(headers)
        self.assertEqual(headers[oc.SERVICE_AUTH_HEADER], "Bearer " + "tok")

    def test_apply_noop_without_audience(self):
        headers = {}
        with self._aud(""):
            oc._apply_service_token(headers)
        self.assertNotIn(oc.SERVICE_AUTH_HEADER, headers)


if __name__ == "__main__":
    unittest.main()
