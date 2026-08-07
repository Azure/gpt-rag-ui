"""Signed opaque capability binding a hosted-agent managed conversation to a
validated Entra object id (oid).

The capability is minted by this BFF immediately after it creates a managed
Conversation resource under the *current authenticated user's own* request
flow (see ``hosted_conversation_store.py`` / ``hosted_continuity.py``); it is
the only continuity handle ever returned to the caller. The raw managed
conversation id it wraps is never disclosed directly, and a capability must
never be minted around a caller-supplied conversation id.

Validation of an untrusted capability never reveals *which* check failed —
bad signature, expired token, retired/rotated signing key, or oid mismatch
all raise the same ``ConversationCapabilityError``. Per ADR-0003, callers
(e.g. ``hosted_continuity.py``) must treat every failure identically: fail
closed with a single opaque not-found error and never mint a new
conversation around a rejected *presented* capability, exactly as if the
capability were a cross-user or forged reference. Only a genuinely *absent*
capability on a legitimate new chat may create a fresh managed conversation.
This avoids the capability doubling as an existence oracle.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from itsdangerous import BadData, URLSafeTimedSerializer

from auth_common import normalize_guid

_MAX_CONVERSATION_ID_LENGTH = 256
_MIN_KEY_LENGTH = 32
_SALT = "gpt-rag-hosted-continuity-capability-v1"


class ConversationCapabilityError(ValueError):
    """Raised for any invalid, expired, forged, retired-key, or oid-mismatched
    capability. Intentionally carries no detail that would let a caller
    distinguish the failure reason."""


@dataclass(frozen=True)
class ConversationCapability:
    oid: str
    conversation_id: str
    key_id: str


def _validate_conversation_id(value: str) -> str:
    conversation_id = str(value or "").strip()
    if (
        not conversation_id
        or len(conversation_id) > _MAX_CONVERSATION_ID_LENGTH
        or any(ord(char) < 32 for char in conversation_id)
    ):
        raise ConversationCapabilityError("Invalid capability.")
    return conversation_id


class ConversationCapabilityManager:
    """Mints and validates opaque owner-binding capabilities.

    ``key`` and ``key_id`` must come from Key Vault-backed configuration
    (``HOSTED_CONVERSATION_CAPABILITY_KEY`` / ``_KEY_ID``, see
    ``hosted_continuity_config.py``); this class never reads configuration
    itself and never logs the key or a minted/validated token.
    """

    def __init__(self, *, key: str, key_id: str, ttl_seconds: int):
        if not key or len(key) < _MIN_KEY_LENGTH:
            raise ValueError(
                f"A capability signing key of at least {_MIN_KEY_LENGTH} "
                "characters is required."
            )
        if not key_id:
            raise ValueError("A capability key id is required.")
        if ttl_seconds < 1:
            raise ValueError("Capability TTL must be a positive number of seconds.")
        self.key_id = key_id
        self.ttl_seconds = ttl_seconds
        self._serializer = URLSafeTimedSerializer(
            key,
            salt=_SALT,
            signer_kwargs={"digest_method": hashlib.sha256},
        )

    def mint(self, *, oid: str, conversation_id: str) -> str:
        """Mint a capability bound to a BFF-created managed conversation.

        Must only be called immediately after this BFF creates the managed
        conversation under the current authenticated user's own flow; never
        call this with a caller-supplied conversation id.
        """
        canonical_oid = normalize_guid(oid, claim_name="oid")
        canonical_conversation_id = _validate_conversation_id(conversation_id)
        return self._serializer.dumps(
            {
                "v": 1,
                "oid": canonical_oid,
                "cid": canonical_conversation_id,
                "kid": self.key_id,
            }
        )

    def validate(self, token: str, *, oid: str) -> ConversationCapability:
        """Validate an opaque capability against the caller's validated oid.

        Raises ``ConversationCapabilityError`` for every failure mode (bad
        signature, expired token, unknown/retired key id, oid mismatch,
        missing/malformed token) with the same message and type, so callers
        cannot use this as an existence oracle.
        """
        if not token or not isinstance(token, str) or len(token) > 8192:
            raise ConversationCapabilityError("Invalid capability.")
        try:
            canonical_oid = normalize_guid(oid, claim_name="oid")
        except ValueError as exc:
            raise ConversationCapabilityError("Invalid capability.") from exc

        try:
            payload = self._serializer.loads(token, max_age=self.ttl_seconds)
        except BadData as exc:
            raise ConversationCapabilityError("Invalid capability.") from exc

        if not isinstance(payload, dict) or payload.get("v") != 1:
            raise ConversationCapabilityError("Invalid capability.")
        # A capability's kid must match this manager's *current* active key;
        # a capability signed under a previously-rotated-out key will fail
        # signature verification above once the deployment's configured
        # secret changes, and a stale kid alone is rejected here too so key
        # rotation cannot be bypassed by an attacker who still holds the old
        # secret through some other compromise.
        if payload.get("kid") != self.key_id:
            raise ConversationCapabilityError("Invalid capability.")

        token_oid = str(payload.get("oid") or "")
        if not token_oid or token_oid != canonical_oid:
            raise ConversationCapabilityError("Invalid capability.")

        conversation_id = _validate_conversation_id(str(payload.get("cid") or ""))
        return ConversationCapability(
            oid=canonical_oid,
            conversation_id=conversation_id,
            key_id=self.key_id,
        )
