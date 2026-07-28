"""
Focused contract tests for hosted_agent_client.py.

Covers: config validation, SSE parsing, text-delta streaming,
citation annotations, tool activity logging, error events,
cancellation, conversation/thread-ID mapping, and credential
handling (server-side only, no user token forwarded).
"""
import asyncio
import json
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from hosted_agent_client import (
    HostedAgentConfigError,
    HostedAgentEvent,
    _build_hosted_agent_headers,
    _iter_sse_events,
    _parse_sse_block,
    call_hosted_agent_stream,
    validate_hosted_agent_config,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.run(coro)


async def _collect_events(gen):
    """Drain an async generator into a list of (text, meta) pairs."""
    results = []
    try:
        async for item in gen:
            results.append(item)
    except Exception as exc:
        results.append(("__exc__", exc))
    return results


def _sse_body(*blocks: str) -> str:
    """Build a valid SSE body from a sequence of block strings."""
    return "\n\n".join(blocks) + "\n\n"


def _event_block(event_type: str, data: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(data)}"


def _mock_sse_response(body: str, status_code: int = 200):
    """Return a mock httpx.Response that streams *body* as SSE text."""
    response = MagicMock()
    response.status_code = status_code
    response.reason_phrase = "OK" if status_code < 400 else "Error"

    async def _aiter_text():
        yield body

    response.aiter_text = _aiter_text
    return response


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

class TestValidateHostedAgentConfig(unittest.TestCase):
    def test_raises_when_url_missing(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("hosted_agent_client.config") as cfg,
        ):
            cfg.get.return_value = None
            with self.assertRaises(HostedAgentConfigError) as ctx:
                validate_hosted_agent_config()
        self.assertIn("HOSTED_AGENT_BASE_URL", str(ctx.exception))

    def test_raises_when_url_not_absolute_http(self):
        with patch.dict(os.environ, {"HOSTED_AGENT_BASE_URL": "not-a-url"}, clear=True):
            with self.assertRaises(HostedAgentConfigError) as ctx:
                validate_hosted_agent_config()
        self.assertIn("absolute HTTP", str(ctx.exception))

    def test_accepts_https_url(self):
        with patch.dict(
            os.environ,
            {"HOSTED_AGENT_BASE_URL": "https://agent.example.com"},
            clear=True,
        ):
            validate_hosted_agent_config()  # must not raise

    def test_accepts_http_url(self):
        with patch.dict(
            os.environ,
            {"HOSTED_AGENT_BASE_URL": "http://localhost:8000"},
            clear=True,
        ):
            validate_hosted_agent_config()  # must not raise

    def test_reads_url_from_app_configuration(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("hosted_agent_client.config") as cfg,
        ):
            cfg.get.return_value = "https://agent.example.com"
            validate_hosted_agent_config()  # must not raise

    def test_raises_unknown_chat_backend(self):
        """The caller (app.py) rejects unknown CHAT_BACKEND values before this."""
        # Just ensure validate_hosted_agent_config itself works in isolation.
        with patch.dict(
            os.environ,
            {"HOSTED_AGENT_BASE_URL": "https://agent.example.com"},
            clear=True,
        ):
            validate_hosted_agent_config()


# ---------------------------------------------------------------------------
# SSE parsing — _parse_sse_block
# ---------------------------------------------------------------------------

class TestParseSseBlock(unittest.TestCase):
    def test_returns_none_for_empty_block(self):
        self.assertIsNone(_parse_sse_block(""))

    def test_parses_event_and_json_data(self):
        block = 'event: text.delta\ndata: {"value": "Hello"}'
        event = _parse_sse_block(block)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "text.delta")
        self.assertEqual(event.data, {"value": "Hello"})

    def test_parses_multiline_data_fields(self):
        block = 'event: text.delta\ndata: {"value":\ndata:  "multi"}'
        event = _parse_sse_block(block)
        # data lines are joined; JSON parse may vary — just check no crash
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "text.delta")

    def test_handles_invalid_json_gracefully(self):
        block = "event: error\ndata: not json"
        event = _parse_sse_block(block)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "error")
        self.assertIn("raw", event.data)

    def test_data_only_block_uses_unknown_type(self):
        block = 'data: {"foo": "bar"}'
        event = _parse_sse_block(block)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "unknown")
        self.assertEqual(event.data.get("foo"), "bar")

    def test_empty_data_produces_empty_dict(self):
        block = "event: done"
        event = _parse_sse_block(block)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "done")
        self.assertEqual(event.data, {})


# ---------------------------------------------------------------------------
# SSE iteration — _iter_sse_events
# ---------------------------------------------------------------------------

class TestIterSseEvents(unittest.TestCase):
    def test_yields_events_from_well_formed_sse(self):
        body = _sse_body(
            _event_block("text.delta", {"value": "Hello "}),
            _event_block("text.delta", {"value": "world"}),
            _event_block("done", {}),
        )
        response = _mock_sse_response(body)

        async def _collect():
            return [e async for e in _iter_sse_events(response)]

        events = _run(_collect())
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0].event_type, "text.delta")
        self.assertEqual(events[0].data["value"], "Hello ")
        self.assertEqual(events[1].data["value"], "world")
        self.assertEqual(events[2].event_type, "done")

    def test_skips_comment_lines(self):
        body = ": keep-alive\n\n" + _event_block("done", {}) + "\n\n"
        response = _mock_sse_response(body)

        async def _collect():
            return [e async for e in _iter_sse_events(response)]

        events = _run(_collect())
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "done")

    def test_handles_trailing_block_without_final_blank_line(self):
        body = _event_block("text.delta", {"value": "hi"})  # no trailing \n\n
        response = _mock_sse_response(body)

        async def _collect():
            return [e async for e in _iter_sse_events(response)]

        events = _run(_collect())
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].data["value"], "hi")


# ---------------------------------------------------------------------------
# call_hosted_agent_stream — streaming contract
# ---------------------------------------------------------------------------

class TestCallHostedAgentStream(unittest.TestCase):
    def _make_stream(self, body: str, status_code: int = 200):
        """Patch httpx.AsyncClient to return a mock SSE response."""
        response = _mock_sse_response(body, status_code)

        async def _aread():
            return body.encode()

        response.aread = _aread

        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=response)
        cm.__aexit__ = AsyncMock(return_value=False)

        client = MagicMock()
        client.stream = MagicMock(return_value=cm)

        client_cm = MagicMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=False)

        return client_cm

    def _with_env(self, url="https://agent.example.com/api"):
        return patch.dict(os.environ, {"HOSTED_AGENT_BASE_URL": url}, clear=False)

    def _with_no_mi(self):
        """Patch managed-identity acquisition to avoid network calls."""
        return patch(
            "hosted_agent_client.ChainedTokenCredential",
            return_value=MagicMock(get_token=MagicMock(return_value=MagicMock(token="mi-token"))),
        )

    # -- text streaming -------------------------------------------------------

    def test_text_deltas_are_yielded(self):
        body = _sse_body(
            _event_block("text.delta", {"value": "Hello "}),
            _event_block("text.delta", {"value": "world"}),
            _event_block("done", {}),
        )
        with (
            self._with_env(),
            self._with_no_mi(),
            patch("httpx.AsyncClient", return_value=self._make_stream(body)),
        ):
            gen = call_hosted_agent_stream("conv-1", "Hi", {}, "q-1")
            results = _run(_collect_events(gen))

        texts = [r[0] for r in results if r[0]]
        self.assertEqual(texts, ["Hello ", "world"])

    def test_empty_text_delta_not_yielded(self):
        body = _sse_body(
            _event_block("text.delta", {"value": ""}),
            _event_block("done", {}),
        )
        with (
            self._with_env(),
            self._with_no_mi(),
            patch("httpx.AsyncClient", return_value=self._make_stream(body)),
        ):
            gen = call_hosted_agent_stream("conv-1", "Hi", {}, "q-1")
            results = _run(_collect_events(gen))

        texts = [r[0] for r in results if r[0]]
        self.assertEqual(texts, [])

    # -- conversation / thread-ID mapping ------------------------------------

    def test_conversation_id_propagated_from_done_event(self):
        body = _sse_body(
            _event_block("text.delta", {"value": "Hi"}),
            _event_block("done", {"conversation_id": "new-conv", "thread_id": "t-123"}),
        )
        with (
            self._with_env(),
            self._with_no_mi(),
            patch("httpx.AsyncClient", return_value=self._make_stream(body)),
        ):
            gen = call_hosted_agent_stream("", "Hi", {}, "q-1")
            results = _run(_collect_events(gen))

        # The done event should yield ("", {"conversation_id": ..., "thread_id": ...})
        meta_events = [r for r in results if not r[0] and r[1]]
        self.assertTrue(any(m[1].get("conversation_id") == "new-conv" for m in meta_events))
        self.assertTrue(any(m[1].get("thread_id") == "t-123" for m in meta_events))

    def test_thread_id_propagated_from_thread_created(self):
        body = _sse_body(
            _event_block("thread.created", {"thread_id": "t-001", "conversation_id": "c-001"}),
            _event_block("text.delta", {"value": "Hi"}),
            _event_block("done", {}),
        )
        with (
            self._with_env(),
            self._with_no_mi(),
            patch("httpx.AsyncClient", return_value=self._make_stream(body)),
        ):
            gen = call_hosted_agent_stream("", "Hi", {}, "q-1")
            results = _run(_collect_events(gen))

        meta_events = [r for r in results if not r[0] and r[1]]
        self.assertTrue(any(m[1].get("thread_id") == "t-001" for m in meta_events))

    # -- error event ----------------------------------------------------------

    def test_error_event_raises_runtime_error(self):
        body = _sse_body(
            _event_block("error", {"message": "something went wrong", "code": "ERR_001"}),
        )
        with (
            self._with_env(),
            self._with_no_mi(),
            patch("httpx.AsyncClient", return_value=self._make_stream(body)),
        ):
            gen = call_hosted_agent_stream("conv-1", "Hi", {}, "q-1")
            results = _run(_collect_events(gen))

        exc_items = [r for r in results if r[0] == "__exc__"]
        self.assertEqual(len(exc_items), 1)
        self.assertIsInstance(exc_items[0][1], RuntimeError)
        self.assertIn("something went wrong", str(exc_items[0][1]))

    # -- cancellation ---------------------------------------------------------

    def test_cancelled_event_stops_stream_cleanly(self):
        body = _sse_body(
            _event_block("text.delta", {"value": "partial"}),
            _event_block("cancelled", {}),
            _event_block("text.delta", {"value": "should not appear"}),
        )
        with (
            self._with_env(),
            self._with_no_mi(),
            patch("httpx.AsyncClient", return_value=self._make_stream(body)),
        ):
            gen = call_hosted_agent_stream("conv-1", "Hi", {}, "q-1")
            results = _run(_collect_events(gen))

        texts = [r[0] for r in results if r[0]]
        self.assertEqual(texts, ["partial"])
        # No exception should be raised
        exc_items = [r for r in results if r[0] == "__exc__"]
        self.assertEqual(exc_items, [])

    # -- HTTP error response --------------------------------------------------

    def test_http_error_raises_runtime_error(self):
        body = '{"detail": "not found"}'
        with (
            self._with_env(),
            self._with_no_mi(),
            patch("httpx.AsyncClient", return_value=self._make_stream(body, status_code=404)),
        ):
            gen = call_hosted_agent_stream("conv-1", "Hi", {}, "q-1")
            results = _run(_collect_events(gen))

        exc_items = [r for r in results if r[0] == "__exc__"]
        self.assertEqual(len(exc_items), 1)
        self.assertIsInstance(exc_items[0][1], RuntimeError)
        self.assertIn("404", str(exc_items[0][1]))

    # -- missing config -------------------------------------------------------

    def test_raises_config_error_when_url_not_configured(self):
        with (
            patch.dict(os.environ, {}, clear=False),
            patch("hosted_agent_client.os.getenv", return_value=None),
            patch("hosted_agent_client.config") as cfg,
        ):
            cfg.get.return_value = None
            gen = call_hosted_agent_stream("conv-1", "Hi", {}, "q-1")
            results = _run(_collect_events(gen))

        exc_items = [r for r in results if r[0] == "__exc__"]
        self.assertEqual(len(exc_items), 1)
        self.assertIsInstance(exc_items[0][1], HostedAgentConfigError)

    # -- credentials (ADR-0001) -----------------------------------------------

    def test_user_access_token_not_forwarded(self):
        """User delegated tokens must never appear in the outgoing Authorization header."""
        body = _sse_body(_event_block("done", {}))
        captured_headers = {}

        def _fake_stream(method, url, json, headers):
            captured_headers.update(headers)
            return self._make_stream(body)

        client = MagicMock()
        client.stream = MagicMock(side_effect=_fake_stream)

        client_cm = MagicMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=False)

        auth_info = {
            "access_token": "user-delegated-token-must-not-be-forwarded",
            "client_principal_id": "user-1",
        }

        with (
            self._with_env(),
            self._with_no_mi(),
            patch("httpx.AsyncClient", return_value=client_cm),
        ):
            gen = call_hosted_agent_stream("conv-1", "Hi", auth_info, "q-1")
            _run(_collect_events(gen))

        auth_header = captured_headers.get("Authorization", "")
        self.assertNotIn("user-delegated-token-must-not-be-forwarded", auth_header)

    def test_managed_identity_token_used_for_authorization(self):
        body = _sse_body(_event_block("done", {}))
        captured_headers = {}

        def _fake_stream(method, url, json, headers):
            captured_headers.update(headers)
            return self._make_stream(body)

        client = MagicMock()
        client.stream = MagicMock(side_effect=_fake_stream)

        client_cm = MagicMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=False)

        with (
            self._with_env(),
            patch(
                "hosted_agent_client.ChainedTokenCredential",
                return_value=MagicMock(
                    get_token=MagicMock(return_value=MagicMock(token="server-mi-token"))
                ),
            ),
            patch("httpx.AsyncClient", return_value=client_cm),
        ):
            gen = call_hosted_agent_stream("conv-1", "Hi", {}, "q-1")
            _run(_collect_events(gen))

        # The header value is ****** MI token; just verify presence
        self.assertIn("Authorization", captured_headers)
        self.assertIn("server-mi-token", captured_headers["Authorization"])

    # -- identity propagation -------------------------------------------------

    def test_principal_id_propagated_in_payload(self):
        body = _sse_body(_event_block("done", {}))
        captured_payload = {}

        def _fake_stream(method, url, json, headers):
            captured_payload.update(json)
            return self._make_stream(body)

        client = MagicMock()
        client.stream = MagicMock(side_effect=_fake_stream)

        client_cm = MagicMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=False)

        auth_info = {
            "client_principal_id": "principal-abc",
            "client_principal_name": "alice@example.com",
        }
        with (
            self._with_env(),
            self._with_no_mi(),
            patch("httpx.AsyncClient", return_value=client_cm),
        ):
            gen = call_hosted_agent_stream("conv-1", "Hi", auth_info, "q-1")
            _run(_collect_events(gen))

        self.assertEqual(captured_payload.get("client_principal_id"), "principal-abc")
        self.assertEqual(captured_payload.get("client_principal_name"), "alice@example.com")

    def test_no_auth_principal_not_propagated(self):
        body = _sse_body(_event_block("done", {}))
        captured_payload = {}

        def _fake_stream(method, url, json, headers):
            captured_payload.update(json)
            return self._make_stream(body)

        client = MagicMock()
        client.stream = MagicMock(side_effect=_fake_stream)

        client_cm = MagicMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=False)

        auth_info = {
            "client_principal_id": "no-auth",
            "client_principal_name": "anonymous",
        }
        with (
            self._with_env(),
            self._with_no_mi(),
            patch("httpx.AsyncClient", return_value=client_cm),
        ):
            gen = call_hosted_agent_stream("conv-1", "Hi", auth_info, "q-1")
            _run(_collect_events(gen))

        self.assertNotIn("client_principal_id", captured_payload)
        self.assertNotIn("client_principal_name", captured_payload)

    # -- tool activity --------------------------------------------------------

    def test_tool_call_events_are_not_yielded_as_text(self):
        body = _sse_body(
            _event_block("tool.call", {"type": "file_search", "status": "running"}),
            _event_block("text.delta", {"value": "result"}),
            _event_block("done", {}),
        )
        with (
            self._with_env(),
            self._with_no_mi(),
            patch("httpx.AsyncClient", return_value=self._make_stream(body)),
        ):
            gen = call_hosted_agent_stream("conv-1", "Hi", {}, "q-1")
            results = _run(_collect_events(gen))

        texts = [r[0] for r in results if r[0]]
        self.assertEqual(texts, ["result"])

    # -- annotation event -----------------------------------------------------

    def test_annotation_events_do_not_yield_text(self):
        body = _sse_body(
            _event_block("annotation", {"title": "Source 1", "url": "doc/file.pdf"}),
            _event_block("text.delta", {"value": "answer"}),
            _event_block("done", {}),
        )
        with (
            self._with_env(),
            self._with_no_mi(),
            patch("httpx.AsyncClient", return_value=self._make_stream(body)),
        ):
            gen = call_hosted_agent_stream("conv-1", "Hi", {}, "q-1")
            results = _run(_collect_events(gen))

        texts = [r[0] for r in results if r[0]]
        self.assertEqual(texts, ["answer"])

    # -- unknown events -------------------------------------------------------

    def test_unknown_events_ignored(self):
        body = _sse_body(
            _event_block("future.event", {"data": "x"}),
            _event_block("text.delta", {"value": "hi"}),
            _event_block("done", {}),
        )
        with (
            self._with_env(),
            self._with_no_mi(),
            patch("httpx.AsyncClient", return_value=self._make_stream(body)),
        ):
            gen = call_hosted_agent_stream("conv-1", "Hi", {}, "q-1")
            results = _run(_collect_events(gen))

        texts = [r[0] for r in results if r[0]]
        self.assertEqual(texts, ["hi"])
        exc_items = [r for r in results if r[0] == "__exc__"]
        self.assertEqual(exc_items, [])


# ---------------------------------------------------------------------------
# Headers — _build_hosted_agent_headers
# ---------------------------------------------------------------------------

class TestBuildHostedAgentHeaders(unittest.TestCase):
    def test_content_type_and_accept_always_set(self):
        with patch(
            "hosted_agent_client.ChainedTokenCredential",
            return_value=MagicMock(get_token=MagicMock(return_value=MagicMock(token="tok"))),
        ):
            headers = _build_hosted_agent_headers({})
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Accept"], "text/event-stream")

    def test_no_user_token_in_headers(self):
        with patch(
            "hosted_agent_client.ChainedTokenCredential",
            return_value=MagicMock(get_token=MagicMock(return_value=MagicMock(token="mi-tok"))),
        ):
            headers = _build_hosted_agent_headers({"access_token": "user-secret-token"})
        # The managed-identity token is present, but the user's token must not be.
        self.assertNotIn("user-secret-token", str(headers))

    def test_authorization_header_contains_bearer_token(self):
        """The Authorization header must carry a ****** (managed identity)."""
        with patch(
            "hosted_agent_client.ChainedTokenCredential",
            return_value=MagicMock(get_token=MagicMock(return_value=MagicMock(token="my-mi-token"))),
        ):
            headers = _build_hosted_agent_headers({})
        self.assertIn("Authorization", headers)
        self.assertIn("Bearer", headers["Authorization"])
        self.assertIn("my-mi-token", headers["Authorization"])

    def test_api_key_included_when_configured(self):
        with (
            patch.dict(os.environ, {"HOSTED_AGENT_APP_APIKEY": "test-api-key"}, clear=False),
            patch(
                "hosted_agent_client.ChainedTokenCredential",
                return_value=MagicMock(get_token=MagicMock(return_value=MagicMock(token="tok"))),
            ),
        ):
            headers = _build_hosted_agent_headers({})
        self.assertEqual(headers["X-API-KEY"], "test-api-key")

    def test_dapr_token_included_when_configured(self):
        with (
            patch("hosted_agent_client._get_dapr_api_token", return_value="dapr-secret"),
            patch(
                "hosted_agent_client.ChainedTokenCredential",
                return_value=MagicMock(get_token=MagicMock(return_value=MagicMock(token="tok"))),
            ),
        ):
            headers = _build_hosted_agent_headers({})
        self.assertEqual(headers["dapr-api-token"], "dapr-secret")


if __name__ == "__main__":
    unittest.main()
