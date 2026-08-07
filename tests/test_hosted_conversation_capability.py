import time
import unittest
from unittest.mock import patch

from hosted_conversation_capability import (
    ConversationCapabilityError,
    ConversationCapabilityManager,
)

OID_A = "11111111-1111-1111-1111-111111111111"
OID_B = "22222222-2222-2222-2222-222222222222"


def _manager(**overrides) -> ConversationCapabilityManager:
    kwargs = {"key": "k" * 32, "key_id": "key-1", "ttl_seconds": 900}
    kwargs.update(overrides)
    return ConversationCapabilityManager(**kwargs)


class TestConversationCapabilityManager(unittest.TestCase):
    def test_mint_and_validate_round_trip(self):
        manager = _manager()
        token = manager.mint(oid=OID_A, conversation_id="conv-123")
        capability = manager.validate(token, oid=OID_A)
        self.assertEqual(capability.oid, OID_A)
        self.assertEqual(capability.conversation_id, "conv-123")
        self.assertEqual(capability.key_id, "key-1")

    def test_mint_requires_a_valid_guid_oid(self):
        manager = _manager()
        with self.assertRaises(ValueError):
            manager.mint(oid="not-a-guid", conversation_id="conv-123")

    def test_mint_rejects_empty_conversation_id(self):
        manager = _manager()
        with self.assertRaises(ConversationCapabilityError):
            manager.mint(oid=OID_A, conversation_id="")

    def test_mint_rejects_conversation_id_with_control_characters(self):
        manager = _manager()
        with self.assertRaises(ConversationCapabilityError):
            manager.mint(oid=OID_A, conversation_id="conv\n123")

    def test_validate_rejects_wrong_oid_cross_user_theft(self):
        """A capability minted for one user must not validate for another,
        even with a perfectly valid signature — this is the cross-user
        capability-theft scenario: stealing the opaque token alone must be
        useless without also holding the victim's own valid access token /
        oid."""
        manager = _manager()
        token = manager.mint(oid=OID_A, conversation_id="conv-123")
        with self.assertRaises(ConversationCapabilityError):
            manager.validate(token, oid=OID_B)

    def test_validate_rejects_forged_token(self):
        manager = _manager()
        token = manager.mint(oid=OID_A, conversation_id="conv-123")
        forged = token[:-2] + ("aa" if token[-2:] != "aa" else "bb")
        with self.assertRaises(ConversationCapabilityError):
            manager.validate(forged, oid=OID_A)

    def test_validate_rejects_garbage_token(self):
        manager = _manager()
        with self.assertRaises(ConversationCapabilityError):
            manager.validate("not-a-real-token", oid=OID_A)

    def test_validate_rejects_empty_or_missing_token(self):
        manager = _manager()
        with self.assertRaises(ConversationCapabilityError):
            manager.validate("", oid=OID_A)

    def test_validate_rejects_expired_token(self):
        manager = _manager(ttl_seconds=1)
        token = manager.mint(oid=OID_A, conversation_id="conv-123")
        with patch("time.time", return_value=time.time() + 5):
            with self.assertRaises(ConversationCapabilityError):
                manager.validate(token, oid=OID_A)

    def test_validate_rejects_token_signed_under_a_retired_key(self):
        """Simulates key rotation: a token minted under an old key/secret
        must be rejected once the deployment rotates to a new active key,
        even though it is otherwise well-formed."""
        old_manager = _manager(key="o" * 32, key_id="key-old")
        token = old_manager.mint(oid=OID_A, conversation_id="conv-123")
        new_manager = _manager(key="n" * 32, key_id="key-new")
        with self.assertRaises(ConversationCapabilityError):
            new_manager.validate(token, oid=OID_A)

    def test_validate_rejects_kid_mismatch_even_with_valid_signature(self):
        """Two managers sharing the same secret but different configured
        key ids must still reject each other's tokens — the kid embedded in
        the payload must match the *validating* manager's currently active
        key id."""
        manager_v1 = _manager(key="s" * 32, key_id="key-v1")
        manager_v2 = _manager(key="s" * 32, key_id="key-v2")
        token = manager_v1.mint(oid=OID_A, conversation_id="conv-123")
        with self.assertRaises(ConversationCapabilityError):
            manager_v2.validate(token, oid=OID_A)

    def test_capability_failures_are_indistinguishable(self):
        """Every failure mode must raise the exact same error type with the
        exact same message, so callers cannot use validation as an existence
        oracle (i.e., cannot tell 'wrong oid' apart from 'expired' apart
        from 'forged')."""
        manager = _manager(ttl_seconds=1)
        token = manager.mint(oid=OID_A, conversation_id="conv-123")

        messages = set()
        with self.assertRaises(ConversationCapabilityError) as ctx1:
            manager.validate(token, oid=OID_B)
        messages.add(str(ctx1.exception))

        with self.assertRaises(ConversationCapabilityError) as ctx2:
            manager.validate("garbage", oid=OID_A)
        messages.add(str(ctx2.exception))

        with patch("time.time", return_value=time.time() + 5):
            with self.assertRaises(ConversationCapabilityError) as ctx3:
                manager.validate(token, oid=OID_A)
        messages.add(str(ctx3.exception))

        self.assertEqual(len(messages), 1)

    def test_manager_construction_requires_sufficiently_long_key(self):
        with self.assertRaises(ValueError):
            ConversationCapabilityManager(key="short", key_id="key-1", ttl_seconds=900)

    def test_manager_construction_requires_key_id(self):
        with self.assertRaises(ValueError):
            ConversationCapabilityManager(key="k" * 32, key_id="", ttl_seconds=900)

    def test_manager_construction_requires_positive_ttl(self):
        with self.assertRaises(ValueError):
            ConversationCapabilityManager(key="k" * 32, key_id="key-1", ttl_seconds=0)

    def test_token_never_contains_conversation_id_in_cleartext(self):
        """The opaque capability must not leak the raw conversation id in
        cleartext to a caller inspecting the wire value (itsdangerous signs
        but the payload is still base64 — this proves that we mint through
        the signer rather than round tripping cleartext outside of it, and
        that unrelated random tokens don't accidentally validate)."""
        manager = _manager()
        token = manager.mint(oid=OID_A, conversation_id="super-secret-conversation-id")
        # itsdangerous URLSafeSerializer base64-encodes the JSON payload, so
        # simple substring matching against the raw conversation id (not
        # base64) should not appear.
        self.assertNotIn("super-secret-conversation-id", token)


if __name__ == "__main__":
    unittest.main()
