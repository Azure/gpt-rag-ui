"""Execute retained application boundaries, including user-visible failure outcomes."""

import asyncio
from contextlib import ExitStack
import importlib
import os
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from gpt_rag_ui.auth.embed_auth import CopilotSessionStore
from gpt_rag_ui.telemetry.monitoring import Telemetry


class BoundaryFailureTests(unittest.IsolatedAsyncioTestCase):
    def chat(self):
        with patch.object(Telemetry, "configure_monitoring"), patch.dict(
            os.environ, {"CHAT_BACKEND": "orchestrator", "CHAINLIT_AUTH_SECRET": "test-secret"},
        ):
            return importlib.import_module("gpt_rag_ui.services.chat")

    async def test_chat_failure_boundaries_report_errors_and_close_generators(self):
        from gpt_rag_ui.clients.hosted_agent_client import HostedAgentAuthenticationError, HostedAgentCancelledError
        from gpt_rag_ui.services.hosted_continuity import ContinuityPersistenceError, ConversationNotFoundError
        chat = self.chat()
        for backend, continuity in (("orchestrator", False), ("hosted_agent", False), ("hosted_agent", True)):
            with self.subTest(backend=backend, continuity=continuity), ExitStack() as stack:
                closed = []

                async def failure(*args, **kwargs):
                    try:
                        raise RuntimeError("backend failure")
                        yield
                    finally:
                        closed.append(True)

                response = AsyncMock()
                response.content = ""
                fake_cl = SimpleNamespace(
                    Message=Mock(return_value=response),
                    user_session=SimpleNamespace(get=lambda key: None, set=Mock()),
                    chat_context=SimpleNamespace(to_openai=lambda: []),
                )
                patches = {
                    "cl": fake_cl, "tracer": MagicMock(), "CHAT_BACKEND": backend,
                    "HOSTED_CONTINUITY_ENABLED": continuity, "SHOW_STATISTICS": False,
                    "ENABLE_FEEDBACK": False,
                    "get_auth_info": AsyncMock(return_value={"authorized": True, "object_id": "test-oid"}),
                    "call_orchestrator_stream": failure, "call_hosted_agent_stream": failure,
                    "build_invocation_messages": Mock(return_value=[]),
                    "get_hosted_continuity_coordinator": Mock(return_value=SimpleNamespace(run_turn=failure)),
                    "HostedAgentAuthenticationError": HostedAgentAuthenticationError,
                    "HostedAgentCancelledError": HostedAgentCancelledError,
                    "ContinuityPersistenceError": ContinuityPersistenceError,
                    "ConversationNotFoundError": ConversationNotFoundError,
                }
                for name, value in patches.items():
                    stack.enter_context(patch.object(chat, name, value, create=True))
                with self.assertLogs(chat.logger, level="ERROR"):
                    await chat.handle_message(SimpleNamespace(id="failure-reference", content="question", elements=[]))
                self.assertIn("technical issue", response.content)
                self.assertIn("failure-reference", response.content)
                self.assertEqual([True], closed)
                response.update.assert_awaited_once()

    async def test_ingestion_failure_does_not_claim_processed_success(self):
        chat = self.chat()
        response = AsyncMock()
        response.content = ""
        fake_cl = SimpleNamespace(
            File=SimpleNamespace, Message=Mock(return_value=response),
            user_session=SimpleNamespace(get=lambda key: None, set=Mock()),
        )
        with (
            patch.object(chat, "cl", fake_cl), patch.object(chat, "tracer", MagicMock()),
            patch.object(chat, "CHAT_BACKEND", "orchestrator"),
            patch.object(chat, "SHOW_STATISTICS", False),
            patch.object(chat, "get_auth_info", AsyncMock(return_value={"authorized": True})),
            patch.object(chat, "ingest_files_session", AsyncMock(side_effect=RuntimeError("ingestion failure"))),
            self.assertLogs(chat.logger, level="ERROR"),
        ):
            await chat.handle_message(SimpleNamespace(
                id="upload-reference", content="",
                elements=[SimpleNamespace(mime="application/pdf", name="test.pdf", path="test.pdf", size=1)],
            ))
        self.assertIn("File ingestion failed", response.content)
        self.assertNotIn("processed successfully", response.content)
        self.assertNotIn("uploaded_docs", [call.args[0] for call in fake_cl.user_session.set.call_args_list])

    async def test_upload_bookkeeping_requires_confirmation_and_preserves_question_continuation(self):
        chat = self.chat()
        for outcome in (True, False, RuntimeError("private-ingestion")):
            with self.subTest(outcome=outcome), ExitStack() as stack:
                state = {"uploaded_docs": ["previous.pdf"]}
                response = AsyncMock()
                response.content = ""
                calls = []

                async def stream(*args, **kwargs):
                    calls.append((args, kwargs))
                    if False:
                        yield

                fake_cl = SimpleNamespace(
                    File=SimpleNamespace, Message=Mock(return_value=response),
                    user_session=SimpleNamespace(get=state.get, set=lambda key, value: state.__setitem__(key, value)),
                    chat_context=SimpleNamespace(to_openai=lambda: []),
                )
                ingestion = AsyncMock(
                    return_value=outcome if not isinstance(outcome, Exception) else None,
                    side_effect=outcome if isinstance(outcome, Exception) else None,
                )
                for name, value in {
                    "cl": fake_cl, "tracer": MagicMock(), "CHAT_BACKEND": "orchestrator",
                    "SHOW_STATISTICS": False, "ENABLE_FEEDBACK": False,
                    "get_auth_info": AsyncMock(return_value={"authorized": True}),
                    "ingest_files_session": ingestion, "call_orchestrator_stream": stream,
                }.items():
                    stack.enter_context(patch.object(chat, name, value))
                if isinstance(outcome, Exception):
                    stack.enter_context(self.assertLogs(chat.logger, level="ERROR"))
                await chat.handle_message(SimpleNamespace(
                    id="upload-reference", content="question",
                    elements=[SimpleNamespace(mime="application/pdf", name="new.pdf", path="new.pdf", size=1)],
                ))
                ingestion.assert_awaited_once()
                self.assertEqual(["previous.pdf", "new.pdf"] if outcome is True else ["previous.pdf"], state["uploaded_docs"])
                self.assertEqual(1, len(calls))  # Existing continuation; H6 remains pending.
                self.assertNotIn("private-ingestion", response.content)

    async def test_oauth_refresh_failure_clears_session_and_denies_request(self):
        chat = self.chat()
        user = SimpleNamespace(metadata={"auth_source": "oauth"})
        session = SimpleNamespace(get=lambda key: user, set=Mock())
        with (
            patch.object(chat, "cl", SimpleNamespace(user_session=session)),
            patch.object(chat, "auth_oauth", SimpleNamespace(
                ensure_fresh_user_access_token=AsyncMock(side_effect=RuntimeError("refresh failure")),
            ), create=True),
            self.assertLogs(chat.logger, level="WARNING"),
        ):
            result = await chat.get_auth_info()
        self.assertFalse(result["authorized"])
        self.assertEqual("session_expired", result["auth_error"])
        self.assertIsNone(result["access_token"])
        session.set.assert_called_once_with("user", None)

    async def test_feedback_boundary_emits_failure_toast_not_success(self):
        from gpt_rag_ui.api import feedback
        callbacks = {}

        def register(name):
            def decorator(callback):
                callbacks[name] = callback
                return callback
            return decorator

        toast = AsyncMock()
        with (
            patch.object(feedback, "cl", SimpleNamespace(
                action_callback=register, context=SimpleNamespace(emitter=SimpleNamespace(send_toast=toast)),
            )),
            patch.object(feedback, "call_orchestrator_for_feedback", AsyncMock(side_effect=RuntimeError("backend"))),
            patch.object(feedback, "FEEDBACK_RATING", False),
        ):
            feedback.register_feedback_handlers(
                lambda: {"authorized": True, "client_principal_id": "no-auth"},
                allow_standalone_anonymous=True,
            )
            with self.assertLogs(level="ERROR"):
                await callbacks["submit_feedback"](SimpleNamespace(payload={
                    "questionId": "question", "conversationId": "conversation", "ask": "question",
                }))
        toast.assert_awaited_once_with("An unexpected error occurred while submitting feedback.", "error")

    async def test_feedback_form_cleanup_preserves_submission_outcome(self):
        from gpt_rag_ui.api import feedback

        for outcome in (RuntimeError("backend-private"), True, False, asyncio.CancelledError()):
            for cleanup_fails in (False, True, "cancel"):
                with self.subTest(outcome=outcome, cleanup_fails=cleanup_fails):
                    callbacks = {}
                    def register(name):
                        def decorator(callback):
                            callbacks[name] = callback
                            return callback
                        return decorator

                    form = SimpleNamespace(send=AsyncMock(), remove=AsyncMock(
                        side_effect=asyncio.CancelledError() if cleanup_fails == "cancel" else
                        RuntimeError("cleanup-private") if cleanup_fails else None,
                    ))
                    toast = AsyncMock()
                    backend = AsyncMock(
                        side_effect=outcome if isinstance(outcome, BaseException) else None,
                        return_value=outcome,
                    )
                    action = SimpleNamespace(payload={
                        "questionId": "question", "conversationId": "conversation", "rating": 5,
                    })
                    with (
                        patch.object(feedback, "cl", SimpleNamespace(
                            action_callback=register, Message=Mock(return_value=form),
                            CustomElement=Mock(),
                            context=SimpleNamespace(emitter=SimpleNamespace(send_toast=toast)),
                        )),
                        patch.object(feedback, "FEEDBACK_RATING", True),
                        patch.object(feedback, "call_orchestrator_for_feedback", backend),
                        patch.object(feedback.logging, "error") as diagnostic,
                    ):
                        feedback.register_feedback_handlers(
                            lambda: {"authorized": True, "client_principal_id": "no-auth"},
                            allow_standalone_anonymous=True,
                        )
                        await callbacks["show_feedback_form"](action)
                        if isinstance(outcome, asyncio.CancelledError) or cleanup_fails == "cancel":
                            with self.assertRaises(asyncio.CancelledError):
                                await callbacks["submit_feedback"](action)
                            backend.assert_awaited_once()
                            toast.assert_not_awaited()
                            self.assertEqual(
                                0 if isinstance(outcome, asyncio.CancelledError) else 1,
                                form.remove.await_count,
                            )
                            continue
                        await callbacks["submit_feedback"](action)
                    backend.assert_awaited_once()
                    form.remove.assert_awaited_once()
                    expected = (
                        ("An unexpected error occurred while submitting feedback.", "error")
                        if isinstance(outcome, Exception) else
                        ("Thank you for your feedback!", "success") if outcome else
                        ("Error: Failed to submit feedback", "error")
                    )
                    toast.assert_awaited_once_with(*expected)
                    if isinstance(outcome, Exception) or cleanup_fails:
                        self.assertTrue(diagnostic.called)
                        self.assertNotIn("private", str(diagnostic.call_args_list))

    async def test_feedback_notification_failure_does_not_retry_written_feedback(self):
        from gpt_rag_ui.api import feedback
        callbacks = {}
        def register(name):
            def decorator(callback):
                callbacks[name] = callback
                return callback
            return decorator

        failure = RuntimeError("notification")
        toast = AsyncMock(side_effect=failure)
        backend = AsyncMock(return_value=True)
        with (
            patch.object(feedback, "cl", SimpleNamespace(
                action_callback=register,
                context=SimpleNamespace(emitter=SimpleNamespace(send_toast=toast)),
            )),
            patch.object(feedback, "FEEDBACK_RATING", False),
            patch.object(feedback, "call_orchestrator_for_feedback", backend),
        ):
            feedback.register_feedback_handlers(
                lambda: {"authorized": True, "client_principal_id": "no-auth"},
                allow_standalone_anonymous=True,
            )
            with self.assertRaises(RuntimeError) as raised:
                await callbacks["submit_feedback"](SimpleNamespace(payload={
                    "questionId": "question", "conversationId": "conversation",
                }))
        self.assertIs(failure, raised.exception)
        backend.assert_awaited_once()
        toast.assert_awaited_once_with("Thank you for your feedback!", "success")

    async def test_invalidation_callback_failure_does_not_skip_other_sessions(self):
        callback = AsyncMock(side_effect=[RuntimeError("disconnect failure"), None])
        store = CopilotSessionStore(max_sessions=2, ttl_seconds=120, on_invalidate=callback)
        with self.assertLogs("gpt_rag_ui.embed_auth", level="ERROR"):
            await store._notify_invalidated(["first", "second", "first"])
        self.assertEqual(["first", "second"], [call.args[0] for call in callback.await_args_list])

    async def test_cancellation_is_not_converted_to_successful_invalidation(self):
        store = CopilotSessionStore(
            max_sessions=1, ttl_seconds=120, on_invalidate=AsyncMock(side_effect=asyncio.CancelledError),
        )
        with self.assertRaises(asyncio.CancelledError):
            await store._notify_invalidated(["session"])

    async def test_optional_legacy_citation_failure_is_logged_and_omitted(self):
        from gpt_rag_ui.services import citations
        with (
            patch.object(citations, "generate_blob_sas_url", side_effect=RuntimeError("signing failure")),
            self.assertLogs(citations.logger, level="WARNING"),
        ):
            self.assertIsNone(citations._resolve_legacy_reference_href("document.pdf"))
