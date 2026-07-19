import unittest

from feedback import _feedback_requires_ownership


class FeedbackSecurityTests(unittest.TestCase):
    def test_standalone_anonymous_preserves_legacy_feedback(self):
        self.assertFalse(
            _feedback_requires_ownership(
                {"authorized": True, "client_principal_id": "no-auth"},
                allow_standalone_anonymous=True,
            )
        )

    def test_standalone_oauth_requires_conversation_ownership(self):
        self.assertTrue(
            _feedback_requires_ownership(
                {"auth_source": "oauth"},
                allow_standalone_anonymous=False,
            )
        )

    def test_copilot_modes_always_require_conversation_ownership(self):
        for auth_mode in ("anonymous", "entra"):
            with self.subTest(auth_mode=auth_mode):
                self.assertTrue(
                    _feedback_requires_ownership(
                        {"copilot_auth_mode": auth_mode},
                        allow_standalone_anonymous=True,
                    )
                )


if __name__ == "__main__":
    unittest.main()
