import os

import jwt
from chainlit.auth import create_jwt
from chainlit.user import User


def create_embed_session_jwt(user: User, access_token_expires_at: int) -> str:
    """Create Chainlit's internal session JWT, capped by the Entra token expiry."""

    session_token = create_jwt(user)
    payload = jwt.decode(
        session_token,
        options={"verify_signature": False},
        algorithms=["HS256"],
    )
    payload["exp"] = min(int(payload["exp"]), int(access_token_expires_at))
    secret = os.environ.get("CHAINLIT_AUTH_SECRET")
    if not secret:
        raise RuntimeError("CHAINLIT_AUTH_SECRET is required for authenticated sessions.")
    return jwt.encode(payload, secret, algorithm="HS256")
