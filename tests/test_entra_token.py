import json
import time
import unittest

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from entra_token import EntraTokenError, EntraTokenValidator


TENANT_ID = "11111111-2222-3333-4444-555555555555"
AUDIENCE = "api://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"


class EntraTokenValidatorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_jwk = json.loads(RSAAlgorithm.to_jwk(self.private_key.public_key()))
        public_jwk.update({"kid": "test-key", "use": "sig", "alg": "RS256"})
        self.jwks = {"keys": [public_jwk]}

        async def load_jwks():
            return self.jwks

        self.validator = EntraTokenValidator(
            tenant_id=TENANT_ID,
            audience=AUDIENCE,
            clock_skew_seconds=0,
            jwks_loader=load_jwks,
        )

    def create_token(self, **overrides):
        kid = overrides.pop("_kid", "test-key")
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "tid": TENANT_ID,
            "oid": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
            "sub": "subject",
            "name": "Portal User",
            "preferred_username": "portal.user@example.com",
            "scp": "openid user_impersonation",
            "iat": now,
            "nbf": now - 1,
            "exp": now + 300,
        }
        claims.update(overrides)
        return jwt.encode(
            claims,
            self.private_key,
            algorithm="RS256",
            headers={"kid": kid},
        )

    async def test_accepts_valid_v2_access_token(self):
        claims = await self.validator.validate(self.create_token())

        self.assertEqual(TENANT_ID, claims["tid"])
        self.assertEqual(
            "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
            claims["oid"],
        )

    async def test_rejects_wrong_audience(self):
        with self.assertRaises(EntraTokenError):
            await self.validator.validate(
                self.create_token(aud="api://different")
            )

    async def test_rejects_wrong_issuer_or_tenant(self):
        for overrides in (
            {"iss": "https://issuer.example.com"},
            {"tid": "99999999-8888-7777-6666-555555555555"},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(EntraTokenError):
                    await self.validator.validate(self.create_token(**overrides))

    async def test_rejects_expired_token(self):
        with self.assertRaises(EntraTokenError):
            await self.validator.validate(
                self.create_token(exp=int(time.time()) - 10)
            )

    async def test_rejects_token_without_stable_subject(self):
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": ISSUER,
                "aud": AUDIENCE,
                "tid": TENANT_ID,
                "scp": "user_impersonation",
                "iat": now,
                "nbf": now - 1,
                "exp": now + 300,
            },
            self.private_key,
            algorithm="RS256",
            headers={"kid": "test-key"},
        )
        with self.assertRaisesRegex(EntraTokenError, "oid or sub"):
            await self.validator.validate(token)

    async def test_rejects_token_without_required_delegated_scope(self):
        for scope_claim in ("other_scope", None):
            with self.subTest(scope_claim=scope_claim):
                with self.assertRaisesRegex(EntraTokenError, "required"):
                    await self.validator.validate(
                        self.create_token(scp=scope_claim)
                    )

    async def test_unknown_key_ids_do_not_force_repeated_jwks_refreshes(self):
        loader_calls = 0

        async def counted_loader():
            nonlocal loader_calls
            loader_calls += 1
            return self.jwks

        validator = EntraTokenValidator(
            tenant_id=TENANT_ID,
            audience=AUDIENCE,
            jwks_loader=counted_loader,
        )

        for kid in ("unknown-one", "unknown-two"):
            with self.assertRaisesRegex(EntraTokenError, "signing key"):
                await validator.validate(self.create_token(_kid=kid))

        self.assertEqual(1, loader_calls)

    async def test_rejects_algorithm_confusion(self):
        token = jwt.encode(
            {
                "iss": ISSUER,
                "aud": AUDIENCE,
                "tid": TENANT_ID,
                "oid": "user",
                "scp": "user_impersonation",
                "exp": int(time.time()) + 300,
            },
            "not-a-public-key-but-long-enough-for-hs256",
            algorithm="HS256",
            headers={"kid": "test-key"},
        )
        with self.assertRaisesRegex(EntraTokenError, "RS256"):
            await self.validator.validate(token)


if __name__ == "__main__":
    unittest.main()
