"""Signed opaque expiring cursor for the panel conversation list endpoint
(issue #611, ADR-0004).

Reuses the same signing pattern already used for download grants
(``download_security.py``) and the hosted-continuity capability
(``hosted_conversation_capability.py``): an ``itsdangerous``
``URLSafeTimedSerializer`` keyed off the existing ``CHAINLIT_AUTH_SECRET``
(already Key-Vault-backed, already provisioned in every mode). No new
signing key or Key Vault secret is introduced for pagination.

The cursor carries only an opaque skip offset bound to the caller's
validated ``oid`` -- never a raw continuation token from Cosmos and never
another principal's identifier. A cursor is a pure pagination convenience:
unlike the hosted-continuity capability, it grants no access by itself
(every list query is independently re-scoped to the live caller's oid), so
any invalid/expired/cross-user cursor is treated as a caller input error
(422), not an authorization failure.
"""

from __future__ import annotations

import hashlib

from itsdangerous import BadData, URLSafeTimedSerializer

from auth_common import normalize_guid

_SALT = "gpt-rag-panel-cursor-v1"
_MAX_CURSOR_LENGTH = 2048


class PanelCursorError(ValueError):
    """Raised for any missing, tampered, expired, or cross-user cursor."""


class PanelCursorManager:
    def __init__(self, *, secret: str, ttl_seconds: int):
        if not secret:
            raise ValueError("A signing secret is required for panel cursors.")
        if ttl_seconds < 1:
            raise ValueError("Panel cursor TTL must be a positive number of seconds.")
        self.ttl_seconds = ttl_seconds
        self._serializer = URLSafeTimedSerializer(
            secret,
            salt=_SALT,
            signer_kwargs={"digest_method": hashlib.sha256},
        )

    def mint(self, *, oid: str, skip: int) -> str:
        canonical_oid = normalize_guid(oid, claim_name="oid")
        if skip < 0:
            raise ValueError("skip must not be negative.")
        return self._serializer.dumps({"v": 1, "oid": canonical_oid, "skip": skip})

    def resolve(self, cursor: str | None, *, oid: str) -> int:
        """Return the skip offset encoded by ``cursor``, or ``0`` when
        ``cursor`` is empty/absent (the first page). Raises
        ``PanelCursorError`` for any non-empty cursor that is malformed,
        expired, or bound to a different oid -- callers must map this to a
        422 (a caller input problem, not an ownership/authorization
        failure, since every subsequent query is independently re-scoped
        to the live caller's own oid)."""
        if cursor is None or cursor == "":
            return 0
        if not isinstance(cursor, str) or len(cursor) > _MAX_CURSOR_LENGTH:
            raise PanelCursorError("Invalid cursor.")
        try:
            canonical_oid = normalize_guid(oid, claim_name="oid")
        except ValueError as exc:
            raise PanelCursorError("Invalid cursor.") from exc
        try:
            payload = self._serializer.loads(cursor, max_age=self.ttl_seconds)
        except BadData as exc:
            raise PanelCursorError("Invalid or expired cursor.") from exc
        if not isinstance(payload, dict) or payload.get("v") != 1:
            raise PanelCursorError("Invalid cursor.")
        if str(payload.get("oid") or "") != canonical_oid:
            raise PanelCursorError("Invalid cursor.")
        skip = payload.get("skip")
        if not isinstance(skip, int) or skip < 0:
            raise PanelCursorError("Invalid cursor.")
        return skip
