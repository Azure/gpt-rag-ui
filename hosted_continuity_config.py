"""Configuration for the opt-in hosted-agent cross-version continuity path.

All settings here are inert unless ``HOSTED_CONTINUITY_ENABLED=true``. While
the flag is false (the default), the existing hosted-agent behavior — a
per-turn managed conversation id round-tripped by the hosted runtime itself
and full history resent from the Chainlit chat context, see
``hosted_agent_client.py`` and ``app.py`` — is completely unchanged, and none
of the other settings below are evaluated.

When enabled, this UI (the BFF) becomes the exclusive owner of the Foundry
managed Conversation used for continuity: it mints an opaque, signed
capability bound to the caller's validated Entra ``oid`` instead of ever
handing the raw managed conversation id back to the caller (see
``hosted_conversation_capability.py``), and reads/writes conversation history
through ``hosted_conversation_store.py`` under an explicit bounded-history
policy (max items, then max tokens, dropping the oldest first).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

OwnerBindingMode = Literal["capability", "delegated"]
HistoryTruncation = Literal["drop_oldest"]

_TRUE_VALUES = {"1", "true", "yes", "y", "on"}
_FALSE_VALUES = {"0", "false", "no", "n", "off"}
_LOCAL_HTTP_HOSTS = {"localhost", "127.0.0.1", "::1"}
_MIN_CAPABILITY_KEY_LENGTH = 32


class HostedContinuityConfigError(ValueError):
    """Raised when hosted-agent continuity configuration is missing or invalid."""


@dataclass(frozen=True)
class HostedContinuitySettings:
    enabled: bool = False
    owner_binding: OwnerBindingMode = "capability"
    owner_binding_validated: bool = False
    capability_key: str = ""
    capability_key_id: str = ""
    capability_ttl_seconds: int = 900
    history_max_items: int = 40
    history_max_tokens: int = 8000
    history_truncation: HistoryTruncation = "drop_oldest"
    store_base_url: str = ""
    store_resource_scope: str = ""

    @property
    def uses_capability_binding(self) -> bool:
        return self.enabled and self.owner_binding == "capability"

    @property
    def uses_delegated_binding(self) -> bool:
        """True only once the delegated owner-binding mode has been both
        selected *and* explicitly marked validated; otherwise it stays inert
        even if ``HOSTED_CONVERSATION_OWNER_BINDING=delegated`` is set (this
        can only happen transiently since ``load_hosted_continuity_settings``
        rejects that combination outright when continuity is enabled)."""
        return (
            self.enabled
            and self.owner_binding == "delegated"
            and self.owner_binding_validated
        )


def _read_setting(
    config,
    environ: Mapping[str, str],
    key: str,
    default: str = "",
) -> str:
    env_value = environ.get(key)
    if env_value is not None and str(env_value).strip():
        return str(env_value).strip()
    try:
        value = config.get(key, default, str)
    except Exception:
        return default
    return str(value or default).strip()


def _parse_bool(value: str, *, key: str, default: bool) -> bool:
    if not value:
        return default
    normalized = value.lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise HostedContinuityConfigError(
        f"{key} must be one of true/false, 1/0, yes/no, or on/off."
    )


def _parse_bounded_int(
    value: str,
    *,
    key: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise HostedContinuityConfigError(f"{key} must be an integer.") from exc
    if not minimum <= parsed <= maximum:
        raise HostedContinuityConfigError(
            f"{key} must be between {minimum} and {maximum}."
        )
    return parsed


def _validate_store_base_url(value: str) -> str:
    base_url = value.rstrip("/")
    if not base_url:
        raise HostedContinuityConfigError(
            "HOSTED_CONTINUITY_ENABLED is true but "
            "HOSTED_CONVERSATION_STORE_BASE_URL is not configured."
        )
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HostedContinuityConfigError(
            "HOSTED_CONVERSATION_STORE_BASE_URL must be an absolute HTTP(S) URL."
        )
    if parsed.scheme != "https" and parsed.hostname not in _LOCAL_HTTP_HOSTS:
        raise HostedContinuityConfigError(
            "HOSTED_CONVERSATION_STORE_BASE_URL must use HTTPS except for "
            "local development."
        )
    return base_url


def _validate_store_resource_scope(value: str) -> str:
    scope = value.strip()
    if not scope:
        raise HostedContinuityConfigError(
            "HOSTED_CONTINUITY_ENABLED is true but "
            "HOSTED_CONVERSATION_STORE_RESOURCE_SCOPE (or HOSTED_AGENT_RESOURCE_SCOPE "
            "as a fallback) is not configured."
        )
    if "management.azure.com" in scope.lower():
        raise HostedContinuityConfigError(
            "HOSTED_CONVERSATION_STORE_RESOURCE_SCOPE must be a data-plane scope, "
            "not Azure ARM."
        )
    if not scope.endswith("/.default"):
        raise HostedContinuityConfigError(
            "HOSTED_CONVERSATION_STORE_RESOURCE_SCOPE must be an explicit scope "
            "ending in '/.default'."
        )
    return scope


def load_hosted_continuity_settings(
    config,
    environ: Mapping[str, str] | None = None,
) -> HostedContinuitySettings:
    """Load and validate the opt-in hosted continuity settings.

    Settings other than the enable flag are intentionally ignored while the
    feature is disabled, matching the pattern used by ``embed_config.py``, so
    existing hosted-agent deployments keep their current behavior with zero
    additional required configuration.
    """
    environ = environ if environ is not None else os.environ
    enabled = _parse_bool(
        _read_setting(config, environ, "HOSTED_CONTINUITY_ENABLED"),
        key="HOSTED_CONTINUITY_ENABLED",
        default=False,
    )
    if not enabled:
        return HostedContinuitySettings()

    owner_binding = _read_setting(
        config, environ, "HOSTED_CONVERSATION_OWNER_BINDING", "capability"
    ).lower()
    if owner_binding not in {"capability", "delegated"}:
        raise HostedContinuityConfigError(
            "HOSTED_CONVERSATION_OWNER_BINDING must be 'capability' (default) "
            "or 'delegated'."
        )

    owner_binding_validated = _parse_bool(
        _read_setting(config, environ, "HOSTED_CONVERSATION_OWNER_BINDING_VALIDATED"),
        key="HOSTED_CONVERSATION_OWNER_BINDING_VALIDATED",
        default=False,
    )
    if owner_binding == "delegated" and not owner_binding_validated:
        raise HostedContinuityConfigError(
            "HOSTED_CONVERSATION_OWNER_BINDING=delegated is inert until "
            "HOSTED_CONVERSATION_OWNER_BINDING_VALIDATED=true is explicitly set "
            "after review. Use the default 'capability' binding until the "
            "delegated mode has been validated."
        )

    capability_key = _read_setting(config, environ, "HOSTED_CONVERSATION_CAPABILITY_KEY")
    capability_key_id = _read_setting(
        config, environ, "HOSTED_CONVERSATION_CAPABILITY_KEY_ID"
    )
    if owner_binding == "capability":
        if not capability_key or len(capability_key) < _MIN_CAPABILITY_KEY_LENGTH:
            raise HostedContinuityConfigError(
                "HOSTED_CONVERSATION_CAPABILITY_KEY is required (at least "
                f"{_MIN_CAPABILITY_KEY_LENGTH} characters) when "
                "HOSTED_CONVERSATION_OWNER_BINDING=capability. Provide it via a "
                "Key Vault reference, never a literal secret."
            )
        if not capability_key_id:
            raise HostedContinuityConfigError(
                "HOSTED_CONVERSATION_CAPABILITY_KEY_ID is required when "
                "HOSTED_CONVERSATION_OWNER_BINDING=capability, so retired keys "
                "can be rejected after rotation."
            )

    capability_ttl_seconds = _parse_bounded_int(
        _read_setting(config, environ, "HOSTED_CONVERSATION_CAPABILITY_TTL_SECONDS"),
        key="HOSTED_CONVERSATION_CAPABILITY_TTL_SECONDS",
        default=900,
        minimum=60,
        maximum=86400,
    )
    history_max_items = _parse_bounded_int(
        _read_setting(config, environ, "HOSTED_HISTORY_MAX_ITEMS"),
        key="HOSTED_HISTORY_MAX_ITEMS",
        default=40,
        minimum=1,
        maximum=500,
    )
    history_max_tokens = _parse_bounded_int(
        _read_setting(config, environ, "HOSTED_HISTORY_MAX_TOKENS"),
        key="HOSTED_HISTORY_MAX_TOKENS",
        default=8000,
        minimum=256,
        maximum=200_000,
    )
    history_truncation = _read_setting(
        config, environ, "HOSTED_HISTORY_TRUNCATION", "drop_oldest"
    ).lower()
    if history_truncation != "drop_oldest":
        raise HostedContinuityConfigError(
            "HOSTED_HISTORY_TRUNCATION only supports 'drop_oldest'."
        )

    store_base_url = _validate_store_base_url(
        _read_setting(config, environ, "HOSTED_CONVERSATION_STORE_BASE_URL")
    )
    store_resource_scope = _validate_store_resource_scope(
        _read_setting(config, environ, "HOSTED_CONVERSATION_STORE_RESOURCE_SCOPE")
        or _read_setting(config, environ, "HOSTED_AGENT_RESOURCE_SCOPE")
    )

    return HostedContinuitySettings(
        enabled=True,
        owner_binding=owner_binding,  # type: ignore[arg-type]
        owner_binding_validated=owner_binding_validated,
        capability_key=capability_key,
        capability_key_id=capability_key_id,
        capability_ttl_seconds=capability_ttl_seconds,
        history_max_items=history_max_items,
        history_max_tokens=history_max_tokens,
        history_truncation=history_truncation,  # type: ignore[arg-type]
        store_base_url=store_base_url,
        store_resource_scope=store_resource_scope,
    )
