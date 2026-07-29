"""
Contract tests for hosted_agent_client.py.

All SSE frames use the actual ``/invocations`` Responses contract from the
hosted orchestrator (``response.created``, ``response.output_text.delta``,
``response.output_text.annotation.added``,
``response.function_call_arguments.delta/.done``,
``response.completed``, ``response.cancelled``, ``error``).

Coverage:
- Config validation (URL, required scope)
- SSE parsing (_parse_sse_block / _iter_sse_events)
- InvocationRequest shape (messages, conversation_id, metadata)
- Two-turn conversation continuity via managed conversation_id
- Text delta streaming
- Citation annotation events
- Tool-call delta / done activity
- Successful completion (response.completed)
- Cancellation (response.cancelled)
- Error event (error)
- HTTP error response
- Auth fail-fast: missing scope raises before sending request
- Auth fail-fast: token acquisition failure raises before sending request
- Managed-identity token used in Authorization header (not user token)
- User access token never forwarded
- No automatic fallback to classic orchestrator path
"""
import asyncio
import json
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from hosted_agent_client import (
    HostedAgentConfigError,
    HostedAgentEvent,
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


async def _collect(gen):
    """Drain an async generator into a list of (text, meta) pairs.

    Exceptions are captured as ``("__exc__", <exception>)`` tuples so callers
    can assert on error cases without the test runner swallowing the exception.
    """
    results = []
    try:
        async for item in gen:
            results.append(item)
    except Exception as exc:
        results.append(("__exc__", exc))
    return results


def _sse(event_type: str, data: dict) -> str:
    """Build a single SSE block (without the trailing double newline)."""
    return f"event: {event_type}\ndata: {json.dumps(data)}"


def _sse_body(*blocks: str) -> str:
    """Join SSE blocks with the required blank-line separator."""
    return "\n\n".join(blocks) + "\n\n"


def _mock_response(body: str, status_code: int = 200):
    """Mock httpx.Response that streams *body* as SSE text."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.reason_phrase = "OK" if status_code < 400 else "Error"

    async def _aiter_text():
        yield body

    resp.aiter_text = _aiter_text

    async def _aread():
        return body.encode()

    resp.aread = _aread
    return resp


def _make_stream_cm(body: str, status_code: int = 200):
    """Build a mock httpx.AsyncClient context manager that yields *body*."""
    resp = _mock_response(body, status_code)

    stream_cm = MagicMock()
    stream_cm.__aenter__ = AsyncMock(return_value=resp)
    stream_cm.__aexit__ = AsyncMock(return_value=False)

    client = MagicMock()
    client.stream = MagicMock(return_value=stream_cm)

    client_cm = MagicMock()
    client_cm.__aenter__ = AsyncMock(return_value=client)
    client_cm.__aexit__ = AsyncMock(return_value=False)

    return client_cm


def _patch_env(url="https://agent.example.com"):
    return patch.dict(
        os.environ,
        {"HOSTED_AGENT_BASE_URL": url, "HOSTED_AGENT_RESOURCE_SCOPE": "api://agent/.default"},
        clear=False,
    )


def _patch_credential(token: str = "mi-token"):
    """Patch _get_credential so token acquisition succeeds without network."""
    mock_cred = MagicMock()
    mock_cred.get_token = MagicMock(return_value=MagicMock(token=token))
    return patch("hosted_agent_client._get_credential", return_value=mock_cred)


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


class TestValidateHostedAgentConfig(unittest.TestCase):
    def test_raises_when_url_missing(self):
        with (
            patch.dict(os.environ, {"HOSTED_AGENT_RESOURCE_SCOPE": "api://x/.default"}, clear=True),
            patch("hosted_agent_client.config") as cfg,
        ):
            cfg.get.return_value = None
            with self.assertRaises(HostedAgentConfigError) as ctx:
                validate_hosted_agent_config()
        self.assertIn("HOSTED_AGENT_BASE_URL", str(ctx.exception))

    def test_raises_when_url_not_absolute_http(self):
        with patch.dict(
            os.environ,
            {"HOSTED_AGENT_BASE_URL": "not-a-url", "HOSTED_AGENT_RESOURCE_SCOPE": "api://x/.default"},
            clear=True,
        ):
            with self.assertRaises(HostedAgentConfigError) as ctx:
                validate_hosted_agent_config()
        self.assertIn("absolute HTTP", str(ctx.exception))

    def test_raises_when_scope_missing(self):
        """Scope is required; ARM default is explicitly rejected."""
        with patch.dict(
            os.environ,
            {"HOSTED_AGENT_BASE_URL": "https://agent.example.com"},
            clear=True,
        ):
            with patch("hosted_agent_client.config") as cfg:
                cfg.get.return_value = None
                with self.assertRaises(HostedAgentConfigError) as ctx:
                    validate_hosted_agent_config()
        self.assertIn("HOSTED_AGENT_RESOURCE_SCOPE", str(ctx.exception))

    def test_accepts_https_url_with_scope(self):
        with patch.dict(
            os.environ,
            {
                "HOSTED_AGENT_BASE_URL": "https://agent.example.com",
                "HOSTED_AGENT_RESOURCE_SCOPE": "api://agent/.default",
            },
            clear=True,
        ):
            validate_hosted_agent_config()  # must not raise

    def test_accepts_http_url_with_scope(self):
        with patch.dict(
            os.environ,
            {
                "HOSTED_AGENT_BASE_URL": "http://localhost:8000",
                "HOSTED_AGENT_RESOURCE_SCOPE": "api://agent/.default",
            },
            clear=True,
        ):
            validate_hosted_agent_config()  # must not raise

    def test_reads_url_from_app_configuration(self):
        with (
            patch.dict(os.environ, {"HOSTED_AGENT_RESOURCE_SCOPE": "api://x/.default"}, clear=True),
            patch("hosted_agent_client.config") as cfg,
        ):
            cfg.get.return_value = "https://agent.example.com"
            validate_hosted_agent_config()  # must not raise


# ---------------------------------------------------------------------------
# SSE parsing — _parse_sse_block
# ---------------------------------------------------------------------------


class TestParseSseBlock(unittest.TestCase):
    def test_returns_none_for_empty_block(self):
        self.assertIsNone(_parse_sse_block(""))

    def test_parses_response_output_text_delta(self):
        block = 'event: response.output_text.delta\ndata: {"delta": "Hello"}'
        event = _parse_sse_block(block)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "response.output_text.delta")
        self.assertEqual(event.data, {"delta": "Hello"})

    def test_parses_response_created(self):
        block = 'event: response.created\ndata: {"conversation_id": "conv-1"}'
        event = _parse_sse_block(block)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "response.created")
        self.assertEqual(event.data.get("conversation_id"), "conv-1")

    def test_parses_response_completed(self):
        block = 'event: response.completed\ndata: {"conversation_id": "conv-1"}'
        event = _parse_sse_block(block)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "response.completed")

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

    def test_empty_data_produces_empty_dict(self):
        block = "event: response.completed"
        event = _parse_sse_block(block)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "response.completed")
        self.assertEqual(event.data, {})


# ---------------------------------------------------------------------------
# SSE iteration — _iter_sse_events
# ---------------------------------------------------------------------------


class TestIterSseEvents(unittest.TestCase):
    def test_yields_events_from_well_formed_sse(self):
        body = _sse_body(
            _sse("response.output_text.delta", {"delta": "Hello "}),
            _sse("response.output_text.delta", {"delta": "world"}),
            _sse("response.completed", {"conversation_id": "c1"}),
        )
        resp = _mock_response(body)

        async def _c():
            return [e async for e in _iter_sse_events(resp)]

        events = _run(_c())
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0].event_type, "response.output_text.delta")
        self.assertEqual(events[0].data["delta"], "Hello ")
        self.assertEqual(events[2].event_type, "response.completed")

    def test_skips_comment_lines(self):
        body = ": keep-alive\n\n" + _sse("response.completed", {}) + "\n\n"
        resp = _mock_response(body)

        async def _c():
            return [e async for e in _iter_sse_events(resp)]

        events = _run(_c())
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "response.completed")

    def test_handles_trailing_block_without_final_blank_line(self):
        body = _sse("response.output_text.delta", {"delta": "hi"})  # no trailing \n\n
        resp = _mock_response(body)

        async def _c():
            return [e async for e in _iter_sse_events(resp)]

        events = _run(_c())
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].data["delta"], "hi")


# ---------------------------------------------------------------------------
# InvocationRequest shape
# ---------------------------------------------------------------------------


class TestInvocationRequestShape(unittest.TestCase):
    """Verify that call_hosted_agent_stream sends the correct request body."""

    def _capture_payload_cm(self, body: str):
        """Build a client mock that captures the JSON payload sent."""
        captured = {}
        resp = _mock_response(body)

        stream_cm = MagicMock()
        stream_cm.__aenter__ = AsyncMock(return_value=resp)
        stream_cm.__aexit__ = AsyncMock(return_value=False)

        def _stream(method, url, json, headers):  # noqa: A002
            captured.update(json)
            return stream_cm

        client = MagicMock()
        client.stream = MagicMock(side_effect=_stream)

        client_cm = MagicMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=False)

        return client_cm, captured

    def test_messages_array_contains_user_turn(self):
        body = _sse_body(_sse("response.completed", {}))
        client_cm, captured = self._capture_payload_cm(body)
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=client_cm):
            _run(_collect(call_hosted_agent_stream("", "What is RAG?", {}, "q-1")))

        self.assertIn("messages", captured)
        self.assertEqual(len(captured["messages"]), 1)
        self.assertEqual(captured["messages"][0]["role"], "user")
        self.assertEqual(captured["messages"][0]["content"], "What is RAG?")

    def test_conversation_id_included_when_continuing(self):
        body = _sse_body(_sse("response.completed", {}))
        client_cm, captured = self._capture_payload_cm(body)
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=client_cm):
            _run(_collect(call_hosted_agent_stream("conv-abc", "follow-up", {}, "q-2")))

        self.assertEqual(captured.get("conversation_id"), "conv-abc")

    def test_conversation_id_absent_for_new_conversation(self):
        body = _sse_body(_sse("response.completed", {}))
        client_cm, captured = self._capture_payload_cm(body)
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=client_cm):
            _run(_collect(call_hosted_agent_stream("", "new question", {}, "q-3")))

        self.assertNotIn("conversation_id", captured)

    def test_metadata_contains_question_id(self):
        body = _sse_body(_sse("response.completed", {}))
        client_cm, captured = self._capture_payload_cm(body)
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=client_cm):
            _run(_collect(call_hosted_agent_stream("", "hi", {}, "q-xyz")))

        self.assertEqual(captured.get("metadata", {}).get("question_id"), "q-xyz")

    def test_no_legacy_fields_in_payload(self):
        """question, ask, thread_id, client_principal_* must not appear."""
        body = _sse_body(_sse("response.completed", {}))
        client_cm, captured = self._capture_payload_cm(body)
        auth_info = {"client_principal_id": "u1", "client_principal_name": "alice"}
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=client_cm):
            _run(_collect(call_hosted_agent_stream("", "hi", auth_info, "q-1")))

        for forbidden in ("question", "ask", "thread_id", "client_principal_id", "client_principal_name"):
            self.assertNotIn(forbidden, captured, f"'{forbidden}' must not appear in payload")

    def test_invocations_endpoint_used(self):
        """Endpoint must be /invocations, not /chat."""
        body = _sse_body(_sse("response.completed", {}))
        captured_urls = []

        resp = _mock_response(body)
        stream_cm = MagicMock()
        stream_cm.__aenter__ = AsyncMock(return_value=resp)
        stream_cm.__aexit__ = AsyncMock(return_value=False)

        def _stream(method, url, json, headers):  # noqa: A002
            captured_urls.append(url)
            return stream_cm

        client = MagicMock()
        client.stream = MagicMock(side_effect=_stream)
        client_cm = MagicMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=False)

        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=client_cm):
            _run(_collect(call_hosted_agent_stream("", "hi", {}, "q-1")))

        self.assertTrue(
            any("/invocations" in u for u in captured_urls),
            f"Expected /invocations in URL, got: {captured_urls}",
        )
        self.assertFalse(
            any("/chat" in u for u in captured_urls),
            "/chat must not be used",
        )


# ---------------------------------------------------------------------------
# Responses SSE contract — call_hosted_agent_stream
# ---------------------------------------------------------------------------


class TestResponsesSSEContract(unittest.TestCase):

    # -- response.created / conversation_id continuity -----------------------

    def test_response_created_yields_conversation_id(self):
        body = _sse_body(
            _sse("response.created", {"conversation_id": "srv-conv-1"}),
            _sse("response.output_text.delta", {"delta": "Hi"}),
            _sse("response.completed", {}),
        )
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=_make_stream_cm(body)):
            results = _run(_collect(call_hosted_agent_stream("", "hello", {}, "q-1")))

        meta_events = [r for r in results if not r[0] and r[1]]
        self.assertTrue(
            any(m[1].get("conversation_id") == "srv-conv-1" for m in meta_events),
            "response.created must yield conversation_id",
        )

    def test_two_turn_continuity(self):
        """Turn 1 establishes conversation_id; Turn 2 resends it."""
        body_t1 = _sse_body(
            _sse("response.created", {"conversation_id": "mgd-conv-99"}),
            _sse("response.output_text.delta", {"delta": "Turn 1 answer"}),
            _sse("response.completed", {"conversation_id": "mgd-conv-99"}),
        )
        captured_t2 = {}

        # ---- Turn 1 ----
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=_make_stream_cm(body_t1)):
            results_t1 = _run(_collect(call_hosted_agent_stream("", "turn 1", {}, "q-t1")))

        # Extract conversation_id surfaced by Turn 1.
        conv_id = None
        for text, meta in results_t1:
            if meta.get("conversation_id"):
                conv_id = meta["conversation_id"]

        self.assertEqual(conv_id, "mgd-conv-99")

        # ---- Turn 2 ----
        body_t2 = _sse_body(_sse("response.completed", {}))
        resp = _mock_response(body_t2)
        stream_cm = MagicMock()
        stream_cm.__aenter__ = AsyncMock(return_value=resp)
        stream_cm.__aexit__ = AsyncMock(return_value=False)

        def _stream(method, url, json, headers):  # noqa: A002
            captured_t2.update(json)
            return stream_cm

        client = MagicMock()
        client.stream = MagicMock(side_effect=_stream)
        client_cm = MagicMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=False)

        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=client_cm):
            _run(_collect(call_hosted_agent_stream(conv_id, "turn 2", {}, "q-t2")))

        self.assertEqual(captured_t2.get("conversation_id"), "mgd-conv-99")

    # -- text deltas ----------------------------------------------------------

    def test_text_deltas_are_yielded(self):
        body = _sse_body(
            _sse("response.output_text.delta", {"delta": "Hello "}),
            _sse("response.output_text.delta", {"delta": "world"}),
            _sse("response.completed", {}),
        )
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=_make_stream_cm(body)):
            results = _run(_collect(call_hosted_agent_stream("c1", "Hi", {}, "q-1")))

        texts = [r[0] for r in results if r[0]]
        self.assertEqual(texts, ["Hello ", "world"])

    def test_empty_delta_not_yielded(self):
        body = _sse_body(
            _sse("response.output_text.delta", {"delta": ""}),
            _sse("response.completed", {}),
        )
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=_make_stream_cm(body)):
            results = _run(_collect(call_hosted_agent_stream("c1", "Hi", {}, "q-1")))

        texts = [r[0] for r in results if r[0]]
        self.assertEqual(texts, [])

    # -- response.completed ---------------------------------------------------

    def test_response_completed_stops_stream(self):
        body = _sse_body(
            _sse("response.output_text.delta", {"delta": "answer"}),
            _sse("response.completed", {"conversation_id": "c-fin"}),
            _sse("response.output_text.delta", {"delta": "should not appear"}),
        )
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=_make_stream_cm(body)):
            results = _run(_collect(call_hosted_agent_stream("c-fin", "Hi", {}, "q-1")))

        texts = [r[0] for r in results if r[0]]
        self.assertEqual(texts, ["answer"])
        exc_items = [r for r in results if r[0] == "__exc__"]
        self.assertEqual(exc_items, [])

    def test_response_completed_yields_conversation_id(self):
        body = _sse_body(
            _sse("response.completed", {"conversation_id": "c-done"}),
        )
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=_make_stream_cm(body)):
            results = _run(_collect(call_hosted_agent_stream("c-done", "Hi", {}, "q-1")))

        meta_events = [r for r in results if not r[0] and r[1]]
        self.assertTrue(
            any(m[1].get("conversation_id") == "c-done" for m in meta_events),
        )

    # -- response.cancelled ---------------------------------------------------

    def test_response_cancelled_stops_stream_cleanly(self):
        body = _sse_body(
            _sse("response.output_text.delta", {"delta": "partial"}),
            _sse("response.cancelled", {}),
            _sse("response.output_text.delta", {"delta": "should not appear"}),
        )
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=_make_stream_cm(body)):
            results = _run(_collect(call_hosted_agent_stream("c1", "Hi", {}, "q-1")))

        texts = [r[0] for r in results if r[0]]
        self.assertEqual(texts, ["partial"])
        exc_items = [r for r in results if r[0] == "__exc__"]
        self.assertEqual(exc_items, [])

    # -- error event ----------------------------------------------------------

    def test_error_event_raises_runtime_error(self):
        body = _sse_body(
            _sse("error", {"message": "internal failure", "code": "ERR_500"}),
        )
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=_make_stream_cm(body)):
            results = _run(_collect(call_hosted_agent_stream("c1", "Hi", {}, "q-1")))

        exc_items = [r for r in results if r[0] == "__exc__"]
        self.assertEqual(len(exc_items), 1)
        self.assertIsInstance(exc_items[0][1], RuntimeError)
        self.assertIn("internal failure", str(exc_items[0][1]))

    # -- citation annotations -------------------------------------------------

    def test_annotation_events_do_not_yield_text(self):
        body = _sse_body(
            _sse("response.output_text.annotation.added", {"title": "Source 1", "url": "doc.pdf"}),
            _sse("response.output_text.delta", {"delta": "answer"}),
            _sse("response.completed", {}),
        )
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=_make_stream_cm(body)):
            results = _run(_collect(call_hosted_agent_stream("c1", "Hi", {}, "q-1")))

        texts = [r[0] for r in results if r[0]]
        self.assertEqual(texts, ["answer"])

    # -- tool call events -----------------------------------------------------

    def test_tool_call_events_do_not_yield_text(self):
        body = _sse_body(
            _sse("response.function_call_arguments.delta", {"name": "file_search"}),
            _sse("response.function_call_arguments.done", {"name": "file_search"}),
            _sse("response.output_text.delta", {"delta": "result"}),
            _sse("response.completed", {}),
        )
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=_make_stream_cm(body)):
            results = _run(_collect(call_hosted_agent_stream("c1", "Hi", {}, "q-1")))

        texts = [r[0] for r in results if r[0]]
        self.assertEqual(texts, ["result"])

    # -- unknown events -------------------------------------------------------

    def test_unknown_events_ignored(self):
        body = _sse_body(
            _sse("future.event.v2", {"data": "x"}),
            _sse("response.output_text.delta", {"delta": "hi"}),
            _sse("response.completed", {}),
        )
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=_make_stream_cm(body)):
            results = _run(_collect(call_hosted_agent_stream("c1", "Hi", {}, "q-1")))

        texts = [r[0] for r in results if r[0]]
        self.assertEqual(texts, ["hi"])
        exc_items = [r for r in results if r[0] == "__exc__"]
        self.assertEqual(exc_items, [])

    # -- HTTP error response --------------------------------------------------

    def test_http_error_raises_runtime_error(self):
        with _patch_env(), _patch_credential(), patch("httpx.AsyncClient", return_value=_make_stream_cm("{}", 404)):
            results = _run(_collect(call_hosted_agent_stream("c1", "Hi", {}, "q-1")))

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
            results = _run(_collect(call_hosted_agent_stream("c1", "Hi", {}, "q-1")))

        exc_items = [r for r in results if r[0] == "__exc__"]
        self.assertEqual(len(exc_items), 1)
        self.assertIsInstance(exc_items[0][1], HostedAgentConfigError)

    # -- no automatic fallback to orchestrator --------------------------------

    def test_config_error_is_not_swallowed(self):
        """HostedAgentConfigError must propagate; no silent fallback."""
        with (
            patch.dict(os.environ, {}, clear=False),
            patch("hosted_agent_client.os.getenv", return_value=None),
            patch("hosted_agent_client.config") as cfg,
        ):
            cfg.get.return_value = None
            results = _run(_collect(call_hosted_agent_stream("", "Hi", {}, "q-1")))

        exc_items = [r for r in results if r[0] == "__exc__"]
        self.assertGreater(len(exc_items), 0)
        # Must be a HostedAgentConfigError — not caught and silently retried
        self.assertIsInstance(exc_items[0][1], HostedAgentConfigError)


# ---------------------------------------------------------------------------
# Auth — fail-fast behaviour
# ---------------------------------------------------------------------------


class TestAuthFailFast(unittest.TestCase):

    def test_missing_scope_raises_before_sending_request(self):
        """No request must be sent when HOSTED_AGENT_RESOURCE_SCOPE is absent."""
        sent = []

        resp = _mock_response(_sse_body(_sse("response.completed", {})))
        stream_cm = MagicMock()
        stream_cm.__aenter__ = AsyncMock(return_value=resp)
        stream_cm.__aexit__ = AsyncMock(return_value=False)

        def _stream(method, url, json, headers):  # noqa: A002
            sent.append(url)
            return stream_cm

        client = MagicMock()
        client.stream = MagicMock(side_effect=_stream)
        client_cm = MagicMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=False)

        # Scope absent; URL present.
        with (
            patch.dict(
                os.environ,
                {"HOSTED_AGENT_BASE_URL": "https://agent.example.com"},
                clear=True,
            ),
            patch("hosted_agent_client.config") as cfg,
            patch("httpx.AsyncClient", return_value=client_cm),
        ):
            cfg.get.return_value = None  # scope not in App Configuration either
            results = _run(_collect(call_hosted_agent_stream("", "Hi", {}, "q-1")))

        self.assertEqual(sent, [], "No HTTP request should be sent when scope is missing")
        exc_items = [r for r in results if r[0] == "__exc__"]
        self.assertEqual(len(exc_items), 1)
        self.assertIsInstance(exc_items[0][1], HostedAgentConfigError)

    def test_token_acquisition_failure_raises_before_sending_request(self):
        """If the MI token cannot be acquired the request must not be sent."""
        sent = []

        resp = _mock_response(_sse_body(_sse("response.completed", {})))
        stream_cm = MagicMock()
        stream_cm.__aenter__ = AsyncMock(return_value=resp)
        stream_cm.__aexit__ = AsyncMock(return_value=False)

        def _stream(method, url, json, headers):  # noqa: A002
            sent.append(url)
            return stream_cm

        client = MagicMock()
        client.stream = MagicMock(side_effect=_stream)
        client_cm = MagicMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=False)

        failing_cred = MagicMock()
        failing_cred.get_token = MagicMock(side_effect=Exception("no identity"))

        with (
            _patch_env(),
            patch("hosted_agent_client._get_credential", return_value=failing_cred),
            patch("httpx.AsyncClient", return_value=client_cm),
        ):
            results = _run(_collect(call_hosted_agent_stream("", "Hi", {}, "q-1")))

        self.assertEqual(sent, [], "No HTTP request should be sent after auth failure")
        exc_items = [r for r in results if r[0] == "__exc__"]
        self.assertEqual(len(exc_items), 1)
        self.assertIsInstance(exc_items[0][1], HostedAgentConfigError)
        self.assertIn("no identity", str(exc_items[0][1]))

    def test_managed_identity_token_in_authorization_header(self):
        body = _sse_body(_sse("response.completed", {}))
        captured_headers = {}

        resp = _mock_response(body)
        stream_cm = MagicMock()
        stream_cm.__aenter__ = AsyncMock(return_value=resp)
        stream_cm.__aexit__ = AsyncMock(return_value=False)

        def _stream(method, url, json, headers):  # noqa: A002
            captured_headers.update(headers)
            return stream_cm

        client = MagicMock()
        client.stream = MagicMock(side_effect=_stream)
        client_cm = MagicMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=False)

        with (
            _patch_env(),
            _patch_credential("server-mi-token"),
            patch("httpx.AsyncClient", return_value=client_cm),
        ):
            _run(_collect(call_hosted_agent_stream("", "Hi", {}, "q-1")))

        self.assertIn("Authorization", captured_headers)
        self.assertIn("server-mi-token", captured_headers["Authorization"])

    def test_user_access_token_never_forwarded(self):
        body = _sse_body(_sse("response.completed", {}))
        captured_headers = {}

        resp = _mock_response(body)
        stream_cm = MagicMock()
        stream_cm.__aenter__ = AsyncMock(return_value=resp)
        stream_cm.__aexit__ = AsyncMock(return_value=False)

        def _stream(method, url, json, headers):  # noqa: A002
            captured_headers.update(headers)
            return stream_cm

        client = MagicMock()
        client.stream = MagicMock(side_effect=_stream)
        client_cm = MagicMock()
        client_cm.__aenter__ = AsyncMock(return_value=client)
        client_cm.__aexit__ = AsyncMock(return_value=False)

        auth_info = {
            "access_token": "user-delegated-token-must-not-be-forwarded",
            "client_principal_id": "user-1",
        }

        with (
            _patch_env(),
            _patch_credential(),
            patch("httpx.AsyncClient", return_value=client_cm),
        ):
            _run(_collect(call_hosted_agent_stream("", "Hi", auth_info, "q-1")))

        auth_header = captured_headers.get("Authorization", "")
        self.assertNotIn("user-delegated-token-must-not-be-forwarded", auth_header)
