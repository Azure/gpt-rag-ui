import os
import time
import unittest
from unittest.mock import patch

import jwt
from chainlit.user import User

from embed_auth import create_embed_session_jwt


class EmbedAuthTests(unittest.TestCase):
    def test_chainlit_session_is_capped_by_access_token_expiry(self):
        expires_at = int(time.time()) + 120
        user = User(
            identifier="user-id",
            metadata={
                "access_token": "entra-token",
                "access_token_expires_at": expires_at,
            },
        )

        with patch.dict(
            os.environ,
            {"CHAINLIT_AUTH_SECRET": "test-secret-with-adequate-length"},
        ):
            session_token = create_embed_session_jwt(user, expires_at)
            claims = jwt.decode(
                session_token,
                "test-secret-with-adequate-length",
                algorithms=["HS256"],
            )

        self.assertEqual(expires_at, claims["exp"])


if __name__ == "__main__":
    unittest.main()
