import time
import unittest
from unittest.mock import patch

from panel_cursor import PanelCursorError, PanelCursorManager

OID_A = "11111111-1111-1111-1111-111111111111"
OID_B = "22222222-2222-2222-2222-222222222222"


class PanelCursorManagerTests(unittest.TestCase):
    def setUp(self):
        self.manager = PanelCursorManager(secret="s" * 32, ttl_seconds=60)

    def test_empty_cursor_resolves_to_zero(self):
        self.assertEqual(self.manager.resolve(None, oid=OID_A), 0)
        self.assertEqual(self.manager.resolve("", oid=OID_A), 0)

    def test_round_trip_preserves_skip(self):
        token = self.manager.mint(oid=OID_A, skip=40)
        self.assertEqual(self.manager.resolve(token, oid=OID_A), 40)

    def test_tampered_cursor_is_rejected(self):
        token = self.manager.mint(oid=OID_A, skip=40)
        tampered = token[:-1] + ("a" if token[-1] != "a" else "b")
        with self.assertRaises(PanelCursorError):
            self.manager.resolve(tampered, oid=OID_A)

    def test_expired_cursor_is_rejected(self):
        token = self.manager.mint(oid=OID_A, skip=10)
        with patch("panel_cursor.URLSafeTimedSerializer.loads") as mocked:
            from itsdangerous import SignatureExpired

            mocked.side_effect = SignatureExpired("expired")
            with self.assertRaises(PanelCursorError):
                self.manager.resolve(token, oid=OID_A)

    def test_cursor_minted_for_one_oid_rejected_for_another(self):
        token = self.manager.mint(oid=OID_A, skip=25)
        with self.assertRaises(PanelCursorError):
            self.manager.resolve(token, oid=OID_B)

    def test_oversized_cursor_rejected_without_decoding(self):
        with self.assertRaises(PanelCursorError):
            self.manager.resolve("x" * 3000, oid=OID_A)

    def test_negative_skip_cannot_be_minted(self):
        with self.assertRaises(ValueError):
            self.manager.mint(oid=OID_A, skip=-1)

    def test_malformed_oid_when_resolving_is_rejected(self):
        token = self.manager.mint(oid=OID_A, skip=1)
        with self.assertRaises(PanelCursorError):
            self.manager.resolve(token, oid="not-a-guid")

    def test_mint_normalizes_oid_casing(self):
        token = self.manager.mint(oid=OID_A.upper(), skip=5)
        self.assertEqual(self.manager.resolve(token, oid=OID_A), 5)


if __name__ == "__main__":
    unittest.main()
