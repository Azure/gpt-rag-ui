import asyncio
import json
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm


class EntraTokenError(ValueError):
    """Raised when an embedded-session Entra token cannot be trusted."""


JwksLoader = Callable[[], Awaitable[Mapping[str, Any]]]


class EntraTokenValidator:
    def __init__(
        self,
        *,
        tenant_id: str,
        audience: str,
        required_scope: str = "user_impersonation",
        cache_ttl_seconds: int = 3600,
        unknown_key_refresh_interval_seconds: int = 60,
        clock_skew_seconds: int = 60,
        jwks_loader: JwksLoader | None = None,
    ):
        self.tenant_id = tenant_id
        self.audience = audience
        self.required_scope = required_scope
        self.issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
        self.jwks_url = (
            f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        )
        self.cache_ttl_seconds = cache_ttl_seconds
        self.unknown_key_refresh_interval_seconds = (
            unknown_key_refresh_interval_seconds
        )
        self.clock_skew_seconds = clock_skew_seconds
        self._jwks_loader = jwks_loader or self._load_jwks
        self._keys: dict[str, Any] = {}
        self._loaded_at = 0.0
        self._last_unknown_key_refresh_at = 0.0
        self._lock = asyncio.Lock()

    async def _load_jwks(self) -> Mapping[str, Any]:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(5.0),
            follow_redirects=False,
        ) as client:
            response = await client.get(self.jwks_url)
            response.raise_for_status()
            if len(response.content) > 1_000_000:
                raise EntraTokenError("The Entra JWKS response is unexpectedly large.")
            try:
                payload = response.json()
            except ValueError as exc:
                raise EntraTokenError(
                    "The Entra JWKS response is not valid JSON."
                ) from exc
            if not isinstance(payload, dict):
                raise EntraTokenError("The Entra JWKS response is not an object.")
            return payload

    async def _refresh_keys(self) -> None:
        payload = await self._jwks_loader()
        raw_keys = payload.get("keys")
        if not isinstance(raw_keys, list) or not raw_keys or len(raw_keys) > 50:
            raise EntraTokenError("The Entra JWKS response does not contain valid keys.")

        keys: dict[str, Any] = {}
        for raw_key in raw_keys:
            if not isinstance(raw_key, dict):
                continue
            kid = raw_key.get("kid")
            if (
                isinstance(kid, str)
                and kid
                and raw_key.get("kty") == "RSA"
                and raw_key.get("use", "sig") == "sig"
            ):
                try:
                    keys[kid] = RSAAlgorithm.from_jwk(json.dumps(raw_key))
                except (TypeError, ValueError, jwt.PyJWTError):
                    continue

        if not keys:
            raise EntraTokenError("The Entra JWKS response has no usable signing keys.")
        self._keys = keys
        self._loaded_at = time.monotonic()

    async def _get_key(self, kid: str) -> Any:
        cache_is_fresh = (
            self._keys
            and time.monotonic() - self._loaded_at < self.cache_ttl_seconds
        )
        if cache_is_fresh and kid in self._keys:
            return self._keys[kid]

        async with self._lock:
            now = time.monotonic()
            cache_is_fresh = (
                self._keys
                and now - self._loaded_at < self.cache_ttl_seconds
            )
            should_refresh_unknown_key = (
                cache_is_fresh
                and kid not in self._keys
                and now - self._last_unknown_key_refresh_at
                >= self.unknown_key_refresh_interval_seconds
            )
            if not cache_is_fresh:
                await self._refresh_keys()
            elif should_refresh_unknown_key:
                self._last_unknown_key_refresh_at = now
                await self._refresh_keys()
            key = self._keys.get(kid)
            if key is None:
                self._last_unknown_key_refresh_at = time.monotonic()

        if key is None:
            raise EntraTokenError("The token signing key is not trusted.")
        return key

    async def validate(self, token: str) -> dict[str, Any]:
        if not token or len(token) > 16_384:
            raise EntraTokenError("The bearer token is missing or too large.")

        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise EntraTokenError("The bearer token header is invalid.") from exc

        if header.get("alg") != "RS256":
            raise EntraTokenError("Only RS256 Entra access tokens are accepted.")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise EntraTokenError("The bearer token does not identify a signing key.")

        key = await self._get_key(kid)
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.clock_skew_seconds,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise EntraTokenError("The Entra access token is invalid.") from exc

        if claims.get("tid") != self.tenant_id:
            raise EntraTokenError("The Entra access token tenant is not allowed.")
        scopes = {
            scope
            for scope in str(claims.get("scp") or "").split()
            if scope
        }
        if self.required_scope not in scopes:
            raise EntraTokenError(
                f"The Entra access token is missing the required "
                f"'{self.required_scope}' delegated scope."
            )
        if not (claims.get("oid") or claims.get("sub")):
            raise EntraTokenError(
                "The Entra access token must contain an oid or sub claim."
            )
        return claims
