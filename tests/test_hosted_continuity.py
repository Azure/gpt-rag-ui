import unittest
import unittest.mock

from hosted_agent_client import HostedAgentError, InvocationMessage
from hosted_continuity import ContinuityPersistenceError, HostedContinuityCoordinator
from hosted_continuity_config import HostedContinuitySettings
from hosted_conversation_capability import (
    ConversationCapabilityError,
    ConversationCapabilityManager,
)
from hosted_conversation_store import (
    ConversationIdempotencyCache,
    ConversationItem,
    ConversationLockRegistry,
    ConversationStoreError,
)

OID_A = "11111111-1111-1111-1111-111111111111"
OID_B = "22222222-2222-2222-2222-222222222222"


def _settings(**overrides) -> HostedContinuitySettings:
    kwargs = dict(
        enabled=True,
        owner_binding="capability",
        capability_key="k" * 32,
        capability_key_id="key-1",
        capability_ttl_seconds=900,
        history_max_items=40,
        history_max_tokens=8000,
        history_truncation="drop_oldest",
        store_base_url="https://agent.example.com/openai/v1",
        store_resource_scope="api://hosted-agent/.default",
    )
    kwargs.update(overrides)
    return HostedContinuitySettings(**kwargs)


class FakeStore:
    """In-memory stand-in for ConversationStoreClient."""

    def __init__(self):
        self._conversations: dict[str, list[ConversationItem]] = {}
        self._next_id = 0
        self.create_calls: list[str] = []
        self.list_calls: list[tuple[str, int]] = []
        self.append_calls: list[tuple[str, list[dict]]] = []
        self.fail_list_for: set[str] = set()
        self.fail_append_for: set[str] = set()

    async def create_conversation(self, *, user_access_token: str) -> str:
        self._next_id += 1
        conversation_id = f"conv-{self._next_id}"
        self._conversations[conversation_id] = []
        self.create_calls.append(user_access_token)
        return conversation_id

    async def list_items_ascending(
        self, *, user_access_token: str, conversation_id: str, limit: int
    ) -> list[ConversationItem]:
        self.list_calls.append((conversation_id, limit))
        if conversation_id in self.fail_list_for:
            raise ConversationStoreError("simulated read failure")
        return list(self._conversations.get(conversation_id, []))

    async def append_items(
        self, *, user_access_token: str, conversation_id: str, items: list[dict]
    ) -> None:
        self.append_calls.append((conversation_id, items))
        if conversation_id in self.fail_append_for:
            raise ConversationStoreError("simulated append failure")
        stored = self._conversations.setdefault(conversation_id, [])
        for item in items:
            stored.append(
                ConversationItem(
                    item_id=f"item-{len(stored)}",
                    role=item["role"],
                    content=item["content"],
                )
            )


async def _fake_stream_factory(chunks):
    """Builds a call_hosted_agent_stream-compatible async generator function
    that ignores its arguments and yields the given (text, meta) chunks,
    while recording the arguments it was called with."""

    calls = []

    async def fake_stream(messages, *, conversation_id="", question_id=None,
                           correlation_id=None, user_access_token=""):
        calls.append(
            {
                "messages": list(messages),
                "conversation_id": conversation_id,
                "question_id": question_id,
                "correlation_id": correlation_id,
            }
        )
        for chunk in chunks:
            yield chunk

    return fake_stream, calls


class ContinuityTestCase(unittest.IsolatedAsyncioTestCase):
    async def _make_coordinator(self, **setting_overrides):
        store = FakeStore()
        settings = _settings(**setting_overrides)
        capabilities = ConversationCapabilityManager(
            key=settings.capability_key,
            key_id=settings.capability_key_id,
            ttl_seconds=settings.capability_ttl_seconds,
        )
        coordinator = HostedContinuityCoordinator(
            settings=settings,
            store=store,
            capability_manager=capabilities,
            locks=ConversationLockRegistry(),
            idempotency=ConversationIdempotencyCache(),
        )
        return coordinator, store, capabilities

    async def _run(self, coordinator, stream_fn, **kwargs):
        import hosted_continuity as hc

        defaults = dict(
            capability="",
            oid=OID_A,
            user_ask="hello",
            client_turn_id="turn-1",
            question_id=None,
            correlation_id=None,
            user_access_token="user-token",
        )
        defaults.update(kwargs)
        frames = []
        with unittest.mock.patch.object(hc, "call_hosted_agent_stream", stream_fn):
            async for frame in coordinator.run_turn(**defaults):
                frames.append(frame)
        return frames


class TestCreateAndMint(ContinuityTestCase):
    async def test_no_capability_creates_conversation_and_mints_new_one(self):
        coordinator, store, capabilities = await self._make_coordinator()
        stream_fn, calls = await _fake_stream_factory([("hi there", {})])
        frames = await self._run(coordinator, stream_fn)

        self.assertEqual(len(store.create_calls), 1)
        first_meta = frames[0][1]
        self.assertIn("capability", first_meta)
        self.assertIn("conversation_id", first_meta)
        # The minted capability must validate for the same oid and resolve
        # to the same conversation id just created.
        validated = capabilities.validate(first_meta["capability"], oid=OID_A)
        self.assertEqual(validated.conversation_id, first_meta["conversation_id"])

    async def test_never_mints_around_a_caller_supplied_conversation_id(self):
        """There is no parameter on run_turn/_resolve_conversation_id that
        accepts a caller-supplied conversation id to mint around — the only
        conversation id a capability is ever minted for is one this
        coordinator itself just created via store.create_conversation()."""
        coordinator, store, _ = await self._make_coordinator()
        stream_fn, _ = await _fake_stream_factory([("ok", {})])
        await self._run(coordinator, stream_fn)
        # Only the coordinator-created id may have been used to mint; the
        # store never received any caller-chosen id as input to create.
        self.assertEqual(store.create_calls, ["user-token"])


class TestValidContinuation(ContinuityTestCase):
    async def test_valid_capability_continues_same_conversation_without_recreating(self):
        coordinator, store, capabilities = await self._make_coordinator()
        stream_fn, _ = await _fake_stream_factory([("first", {})])
        first_frames = await self._run(coordinator, stream_fn, client_turn_id="turn-1")
        capability = first_frames[0][1]["capability"]
        conversation_id = first_frames[0][1]["conversation_id"]

        stream_fn2, _ = await _fake_stream_factory([("second", {})])
        second_frames = await self._run(
            coordinator, stream_fn2, capability=capability, client_turn_id="turn-2"
        )
        self.assertEqual(second_frames[0][1]["conversation_id"], conversation_id)
        # Still only one conversation ever created across both turns.
        self.assertEqual(len(store.create_calls), 1)

    async def test_history_from_prior_turn_is_read_and_forwarded(self):
        coordinator, store, capabilities = await self._make_coordinator()
        stream_fn, calls = await _fake_stream_factory([("first-answer", {})])
        first_frames = await self._run(coordinator, stream_fn, client_turn_id="turn-1")
        capability = first_frames[0][1]["capability"]

        stream_fn2, calls2 = await _fake_stream_factory([("second-answer", {})])
        await self._run(
            coordinator, stream_fn2, capability=capability, client_turn_id="turn-2",
            user_ask="follow up question",
        )
        sent_messages = calls2[0]["messages"]
        contents = [m.content for m in sent_messages]
        self.assertIn("hello", contents)
        self.assertIn("first-answer", contents)
        self.assertIn("follow up question", contents)


class TestCrossVersionStatelessRequest(ContinuityTestCase):
    async def test_hosted_stream_never_receives_conversation_reference(self):
        coordinator, store, _ = await self._make_coordinator()
        stream_fn, calls = await _fake_stream_factory([("answer", {})])
        await self._run(coordinator, stream_fn)
        self.assertEqual(calls[0]["conversation_id"], "")

    async def test_hosted_runtime_reported_conversation_id_is_stripped(self):
        coordinator, store, _ = await self._make_coordinator()
        stream_fn, _ = await _fake_stream_factory(
            [("chunk", {"conversation_id": "hosted-runtime-ephemeral-id"})]
        )
        frames = await self._run(coordinator, stream_fn)
        # The first frame carries the real BFF-owned id; later frames must
        # never carry the hosted runtime's own unrelated conversation id.
        later_meta = frames[1][1]
        self.assertNotIn("conversation_id", later_meta)


class TestCapabilityRejection(ContinuityTestCase):
    async def test_forged_capability_falls_back_to_a_new_conversation(self):
        coordinator, store, _ = await self._make_coordinator()
        stream_fn, _ = await _fake_stream_factory([("answer", {})])
        frames = await self._run(coordinator, stream_fn, capability="forged-garbage")
        self.assertEqual(len(store.create_calls), 1)
        self.assertIn("capability", frames[0][1])

    async def test_cross_user_stolen_capability_is_rejected_and_not_reused(self):
        coordinator, store, capabilities = await self._make_coordinator()
        stream_fn, _ = await _fake_stream_factory([("answer", {})])
        victim_frames = await self._run(coordinator, stream_fn, oid=OID_A)
        stolen_capability = victim_frames[0][1]["capability"]
        stolen_conversation_id = victim_frames[0][1]["conversation_id"]

        attacker_stream_fn, _ = await _fake_stream_factory([("answer2", {})])
        attacker_frames = await self._run(
            coordinator,
            attacker_stream_fn,
            capability=stolen_capability,
            oid=OID_B,
            client_turn_id="turn-attacker",
        )
        # A brand-new conversation must be minted for the attacker; the
        # victim's conversation id must never be returned/reused.
        self.assertNotEqual(
            attacker_frames[0][1]["conversation_id"], stolen_conversation_id
        )
        self.assertEqual(len(store.create_calls), 2)

    async def test_expired_capability_falls_back_to_a_new_conversation(self):
        coordinator, store, capabilities = await self._make_coordinator(
            capability_ttl_seconds=60
        )
        stream_fn, _ = await _fake_stream_factory([("answer", {})])
        frames = await self._run(coordinator, stream_fn)
        capability = frames[0][1]["capability"]

        import time
        from unittest.mock import patch

        with patch("time.time", return_value=time.time() + 120):
            stream_fn2, _ = await _fake_stream_factory([("answer2", {})])
            frames2 = await self._run(
                coordinator, stream_fn2, capability=capability, client_turn_id="turn-2"
            )
        self.assertEqual(len(store.create_calls), 2)
        self.assertNotEqual(
            frames2[0][1]["conversation_id"], frames[0][1]["conversation_id"]
        )

    async def test_capability_signed_under_retired_key_is_rejected(self):
        coordinator, store, _ = await self._make_coordinator()
        old_manager = ConversationCapabilityManager(
            key="o" * 32, key_id="old-retired-key", ttl_seconds=900
        )
        stale_capability = old_manager.mint(oid=OID_A, conversation_id="conv-old")
        stream_fn, _ = await _fake_stream_factory([("answer", {})])
        frames = await self._run(coordinator, stream_fn, capability=stale_capability)
        self.assertEqual(len(store.create_calls), 1)
        self.assertNotEqual(frames[0][1]["conversation_id"], "conv-old")


class TestReadAppendErrors(ContinuityTestCase):
    async def test_read_failure_raises_persistence_error_not_success(self):
        coordinator, store, _ = await self._make_coordinator()
        stream_fn, _ = await _fake_stream_factory([("answer", {})])
        frames = await self._run(coordinator, stream_fn)
        conversation_id = frames[0][1]["conversation_id"]
        store.fail_list_for.add(conversation_id)

        stream_fn2, _ = await _fake_stream_factory([("answer2", {})])
        capability = frames[0][1]["capability"]
        with self.assertRaises(ContinuityPersistenceError):
            await self._run(
                coordinator, stream_fn2, capability=capability, client_turn_id="turn-2"
            )

    async def test_append_failure_raises_persistence_error_after_streaming(self):
        """Proves the no-success-shaped-completion-on-append-failure
        requirement: the text still streams (it's already been generated by
        the hosted runtime) but the coordinator must raise before the caller
        can treat the turn as durably committed."""
        coordinator, store, _ = await self._make_coordinator()
        stream_fn, _ = await _fake_stream_factory([("answer", {})])
        frames = await self._run(coordinator, stream_fn)
        conversation_id = frames[0][1]["conversation_id"]
        store.fail_append_for.add(conversation_id)

        stream_fn2, _ = await _fake_stream_factory([("second-answer", {})])
        capability = frames[0][1]["capability"]
        import hosted_continuity as hc

        collected = []
        with self.assertRaises(ContinuityPersistenceError):
            with unittest.mock.patch.object(hc, "call_hosted_agent_stream", stream_fn2):
                async for chunk, meta in coordinator.run_turn(
                    capability=capability,
                    oid=OID_A,
                    user_ask="hi again",
                    client_turn_id="turn-2",
                    question_id=None,
                    correlation_id=None,
                    user_access_token="user-token",
                ):
                    collected.append((chunk, meta))
        # The text did stream before the append failure surfaced.
        self.assertTrue(any(chunk == "second-answer" for chunk, _ in collected))


class TestIdempotency(ContinuityTestCase):
    async def test_duplicate_client_turn_id_is_rejected_without_reappending(self):
        coordinator, store, _ = await self._make_coordinator()
        stream_fn, _ = await _fake_stream_factory([("answer", {})])
        frames = await self._run(coordinator, stream_fn, client_turn_id="turn-1")
        capability = frames[0][1]["capability"]
        append_count_before = len(store.append_calls)

        stream_fn2, _ = await _fake_stream_factory([("answer-retry", {})])
        with self.assertRaises(ContinuityPersistenceError):
            await self._run(
                coordinator, stream_fn2, capability=capability, client_turn_id="turn-1"
            )
        self.assertEqual(len(store.append_calls), append_count_before)


class TestOneInFlightConcurrency(ContinuityTestCase):
    async def test_concurrent_turns_on_same_conversation_are_serialized(self):
        import asyncio

        coordinator, store, _ = await self._make_coordinator()
        stream_fn, _ = await _fake_stream_factory([("answer", {})])
        frames = await self._run(coordinator, stream_fn, client_turn_id="turn-1")
        capability = frames[0][1]["capability"]

        order: list[str] = []

        async def dispatch_stream(messages, *, conversation_id="", question_id=None,
                                   correlation_id=None, user_access_token=""):
            # A single patched function dispatches on the last message's
            # content so both concurrent turns can be driven by one
            # unittest.mock.patch context -- patching the same target twice
            # concurrently (once per coroutine) would itself race, since
            # patch.object save/restore is not coroutine-aware.
            is_slow = messages[-1].content == "a"
            order.append("start")
            if is_slow:
                await asyncio.sleep(0.02)
            order.append("end")
            yield ("slow-answer" if is_slow else "fast-answer", {})

        import hosted_continuity as hc

        async def run_slow():
            async for _ in coordinator.run_turn(
                capability=capability, oid=OID_A, user_ask="a",
                client_turn_id="turn-slow", question_id=None,
                correlation_id=None, user_access_token="user-token",
            ):
                pass

        async def run_fast():
            async for _ in coordinator.run_turn(
                capability=capability, oid=OID_A, user_ask="b",
                client_turn_id="turn-fast", question_id=None,
                correlation_id=None, user_access_token="user-token",
            ):
                pass

        with unittest.mock.patch.object(hc, "call_hosted_agent_stream", dispatch_stream):
            await asyncio.gather(run_slow(), run_fast())
        self.assertEqual(order, ["start", "end", "start", "end"])


class TestInputValidation(ContinuityTestCase):
    async def test_rejects_empty_user_ask(self):
        coordinator, store, _ = await self._make_coordinator()
        stream_fn, _ = await _fake_stream_factory([("answer", {})])
        with self.assertRaises(HostedAgentError):
            await self._run(coordinator, stream_fn, user_ask="   ")

    async def test_rejects_missing_client_turn_id(self):
        coordinator, store, _ = await self._make_coordinator()
        stream_fn, _ = await _fake_stream_factory([("answer", {})])
        with self.assertRaises(HostedAgentError):
            await self._run(coordinator, stream_fn, client_turn_id="")

    async def test_coordinator_construction_requires_enabled_settings(self):
        store = FakeStore()
        capabilities = ConversationCapabilityManager(
            key="k" * 32, key_id="key-1", ttl_seconds=900
        )
        with self.assertRaises(ValueError):
            HostedContinuityCoordinator(
                settings=_settings(enabled=False),
                store=store,
                capability_manager=capabilities,
            )


class TestNoSecretOrRawIdLeakageInLogs(ContinuityTestCase):
    async def test_no_capability_token_secret_or_user_access_token_is_logged(self):
        """Drives a full successful turn plus a rejected-capability turn
        while capturing every log record emitted by hosted_continuity's and
        hosted_conversation_store's loggers, then asserts that neither the
        signing key, the minted opaque capability token, nor the delegated
        user access token value ever appears in a log message."""
        import logging

        coordinator, store, capabilities = await self._make_coordinator()
        stream_fn, _ = await _fake_stream_factory([("answer", {})])

        secret_key = "k" * 32
        user_token = "super-secret-user-access-token-value"

        records: list[str] = []

        class _CollectingHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record.getMessage())

        handler = _CollectingHandler()
        loggers = [
            logging.getLogger("gpt_rag_ui.hosted_continuity"),
            logging.getLogger("gpt_rag_ui.hosted_conversation_store"),
        ]
        for lg in loggers:
            lg.addHandler(handler)
            lg.setLevel(logging.DEBUG)
        try:
            frames = await self._run(
                coordinator, stream_fn, user_access_token=user_token
            )
            capability = frames[0][1]["capability"]

            # Also drive a rejected (forged) capability path, which logs an
            # informational message -- this must still never leak secrets.
            stream_fn2, _ = await _fake_stream_factory([("answer2", {})])
            await self._run(
                coordinator,
                stream_fn2,
                capability="forged-" + capability,
                client_turn_id="turn-2",
                user_access_token=user_token,
            )
        finally:
            for lg in loggers:
                lg.removeHandler(handler)

        joined = "\n".join(records)
        self.assertNotIn(secret_key, joined)
        self.assertNotIn(user_token, joined)
        self.assertNotIn(capability, joined)


if __name__ == "__main__":
    unittest.main()
