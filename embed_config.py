import hashlib
import os
import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from connectors.appconfig import AppConfigClient


class EmbedConfigError(ValueError):
    """Raised when Copilot embedding configuration is unsafe or incomplete."""


@dataclass(frozen=True)
class EmbedSettings:
    enabled: bool = False
    allowed_origins: tuple[str, ...] = ()
    ui_origin: str = ""
    root_path: str = ""
    auth_mode: Literal["anonymous", "entra"] | None = None
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    entra_tenant_id: str = ""
    entra_audience: str = ""
    entra_required_scope: str = "user_impersonation"
    entra_allowed_client_ids: tuple[str, ...] = ()
    session_ttl_seconds: int = 3600
    max_sessions: int = 1000
    bootstrap_rate_limit_per_minute: int = 60

    @property
    def uses_entra(self) -> bool:
        return self.enabled and self.auth_mode == "entra"

    @property
    def runtime_allowed_origins(self) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                origin
                for origin in (self.ui_origin, *self.allowed_origins)
                if origin
            )
        )

    @property
    def public_url(self) -> str:
        return f"{self.ui_origin}{self.root_path}" if self.ui_origin else ""

    @property
    def cookie_path(self) -> str:
        return self.root_path or "/"

    @property
    def chainlit_auth_cookie_name(self) -> str:
        if not self.root_path:
            return "access_token"
        suffix = hashlib.sha256(self.root_path.encode("ascii")).hexdigest()[:12]
        return f"gpt_rag_access_token_{suffix}"

    @property
    def entra_issuer(self) -> str:
        return (
            f"https://login.microsoftonline.com/{self.entra_tenant_id}/v2.0"
            if self.entra_tenant_id
            else ""
        )


_TENANT_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_ROOT_PATH_RE = re.compile(
    r"^/[A-Za-z0-9][A-Za-z0-9._~-]*"
    r"(?:/[A-Za-z0-9][A-Za-z0-9._~-]*)*$"
)
_TRUE_VALUES = {"1", "true", "yes", "y", "on"}
_FALSE_VALUES = {"0", "false", "no", "n", "off"}
_LOCAL_HTTP_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _read_setting(
    config: AppConfigClient,
    environ: Mapping[str, str],
    key: str,
) -> str:
    env_value = environ.get(key)
    if env_value is not None and str(env_value).strip():
        return str(env_value).strip()
    return str(config.get(key, "", str) or "").strip()


def _parse_bool(value: str, *, key: str, default: bool) -> bool:
    if not value:
        return default
    normalized = value.lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise EmbedConfigError(
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
        raise EmbedConfigError(f"{key} must be an integer.") from exc
    if not minimum <= parsed <= maximum:
        raise EmbedConfigError(
            f"{key} must be between {minimum} and {maximum}."
        )
    return parsed


def _normalize_origin(
    value: str,
    *,
    key: str = "CHAINLIT_ALLOWED_ORIGINS",
) -> str:
    origin = value.strip()
    if not origin or origin in {"*", "null"}:
        raise EmbedConfigError(
            f"{key} must contain an explicit http(s) origin; "
            "wildcards and the null origin are not allowed."
        )

    try:
        parsed = urllib.parse.urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise EmbedConfigError(f"Invalid origin '{origin}': {exc}") from exc

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise EmbedConfigError(
            f"Invalid origin '{origin}': an http:// or https:// origin is required."
        )
    if parsed.username or parsed.password:
        raise EmbedConfigError(
            f"Invalid origin '{origin}': credentials are not allowed."
        )
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        root_path_hint = (
            " Configure CHAINLIT_ROOT_PATH separately."
            if key == "CHAINLIT_URL"
            else ""
        )
        raise EmbedConfigError(
            f"Invalid {key} origin '{origin}': paths, query strings, and "
            f"fragments are not allowed.{root_path_hint}"
        )
    if port is not None and port <= 0:
        raise EmbedConfigError(
            f"Invalid origin '{origin}': the port must be between 1 and 65535."
        )

    hostname = parsed.hostname.lower()
    if "*" in hostname:
        raise EmbedConfigError(
            f"Invalid origin '{origin}': wildcard hosts are not allowed."
        )
    if parsed.scheme == "http" and hostname not in _LOCAL_HTTP_HOSTS:
        raise EmbedConfigError(
            f"Invalid origin '{origin}': non-local embedding must use HTTPS."
        )

    default_port = 80 if parsed.scheme == "http" else 443
    host_for_origin = f"[{hostname}]" if ":" in hostname else hostname
    port_suffix = f":{port}" if port and port != default_port else ""
    return f"{parsed.scheme}://{host_for_origin}{port_suffix}"


def _normalize_root_path(value: str) -> str:
    root_path = value.strip()
    if not root_path or root_path == "/":
        return ""
    if (
        len(root_path) > 128
        or not _ROOT_PATH_RE.fullmatch(root_path)
        or root_path.endswith("/")
        or "//" in root_path
        or "%" in root_path
        or "\\" in root_path
        or any(
            segment in {".", ".."}
            for segment in root_path.split("/")[1:]
        )
    ):
        raise EmbedConfigError(
            "CHAINLIT_ROOT_PATH must be empty, '/', or a canonical absolute "
            "path such as '/gpt-rag' with no trailing slash, empty segments, "
            "dot segments, percent encoding, query, or fragment."
        )
    return root_path


def _parse_guid_list(value: str, *, key: str) -> tuple[str, ...]:
    if not value:
        raise EmbedConfigError(f"{key} is required and must not be empty.")

    normalized: list[str] = []
    for item in value.split(","):
        client_id = item.strip().lower()
        if not _TENANT_ID_RE.fullmatch(client_id):
            raise EmbedConfigError(
                f"{key} must contain only comma-separated application client GUIDs."
            )
        if client_id not in normalized:
            normalized.append(client_id)
    if len(normalized) > 50:
        raise EmbedConfigError(f"{key} supports at most 50 application client GUIDs.")
    return tuple(normalized)


def _parse_origins(value: str) -> tuple[str, ...]:
    if not value:
        raise EmbedConfigError(
            "CHAINLIT_ALLOWED_ORIGINS is required when CHAINLIT_COPILOT_ENABLED=true."
        )

    normalized: list[str] = []
    for item in value.split(","):
        origin = _normalize_origin(item)
        if origin not in normalized:
            normalized.append(origin)

    if len(normalized) > 20:
        raise EmbedConfigError(
            "CHAINLIT_ALLOWED_ORIGINS supports at most 20 explicit origins."
        )
    return tuple(normalized)


def load_embed_settings(
    config: AppConfigClient,
    environ: Mapping[str, str] | None = None,
) -> EmbedSettings:
    """Load and validate opt-in Copilot settings.

    Settings other than the enable flag are intentionally ignored while embedding
    is disabled so existing standalone deployments keep their current behavior.
    """

    environ = environ if environ is not None else os.environ
    enabled = _parse_bool(
        _read_setting(config, environ, "CHAINLIT_COPILOT_ENABLED"),
        key="CHAINLIT_COPILOT_ENABLED",
        default=False,
    )
    if not enabled:
        return EmbedSettings()

    allowed_origins = _parse_origins(
        _read_setting(config, environ, "CHAINLIT_ALLOWED_ORIGINS")
    )

    auth_mode = _read_setting(
        config,
        environ,
        "CHAINLIT_COPILOT_AUTH_MODE",
    ).lower()
    if auth_mode not in {"anonymous", "entra"}:
        raise EmbedConfigError(
            "CHAINLIT_COPILOT_AUTH_MODE is required when Copilot embedding is "
            "enabled and must be exactly 'anonymous' or 'entra'."
        )

    ui_origin = _normalize_origin(
        _read_setting(config, environ, "CHAINLIT_URL"),
        key="CHAINLIT_URL",
    )
    if not ui_origin.startswith("https://"):
        raise EmbedConfigError(
            "CHAINLIT_URL must use HTTPS when Copilot embedding is enabled."
        )
    root_path = _normalize_root_path(
        _read_setting(config, environ, "CHAINLIT_ROOT_PATH")
    )
    if ui_origin in allowed_origins and not root_path:
        raise EmbedConfigError(
            "A portal origin matching CHAINLIT_URL requires a non-root "
            "CHAINLIT_ROOT_PATH so portal and GPT-RAG routes remain path-separated."
        )

    cookie_samesite = (
        _read_setting(config, environ, "CHAINLIT_COOKIE_SAMESITE") or "lax"
    ).lower()
    if cookie_samesite not in {"lax", "strict", "none"}:
        raise EmbedConfigError(
            "CHAINLIT_COOKIE_SAMESITE must be 'lax', 'strict', or 'none'."
        )
    if cookie_samesite == "none" and any(
        origin.startswith("http://") for origin in allowed_origins
    ):
        raise EmbedConfigError(
            "CHAINLIT_COOKIE_SAMESITE=none requires HTTPS origins."
        )

    tenant_id = _read_setting(
        config, environ, "CHAINLIT_COPILOT_ENTRA_TENANT_ID"
    )
    audience = _read_setting(
        config, environ, "CHAINLIT_COPILOT_ENTRA_AUDIENCE"
    )
    required_scope = (
        _read_setting(
            config, environ, "CHAINLIT_COPILOT_ENTRA_REQUIRED_SCOPE"
        )
        or "user_impersonation"
    )
    allowed_client_ids: tuple[str, ...] = ()
    if auth_mode == "entra":
        if not _TENANT_ID_RE.fullmatch(tenant_id):
            raise EmbedConfigError(
                "CHAINLIT_COPILOT_ENTRA_TENANT_ID must be a tenant GUID "
                "when CHAINLIT_COPILOT_AUTH_MODE=entra."
            )
        tenant_id = tenant_id.lower()
        if not audience or any(character.isspace() for character in audience):
            raise EmbedConfigError(
                "CHAINLIT_COPILOT_ENTRA_AUDIENCE is required and cannot contain "
                "whitespace when CHAINLIT_COPILOT_AUTH_MODE=entra."
            )
        if any(character.isspace() for character in required_scope):
            raise EmbedConfigError(
                "CHAINLIT_COPILOT_ENTRA_REQUIRED_SCOPE must contain one scope name."
            )
        allowed_client_ids = _parse_guid_list(
            _read_setting(
                config,
                environ,
                "CHAINLIT_COPILOT_ENTRA_ALLOWED_CLIENT_IDS",
            ),
            key="CHAINLIT_COPILOT_ENTRA_ALLOWED_CLIENT_IDS",
        )

    session_ttl_seconds = _parse_bounded_int(
        _read_setting(config, environ, "CHAINLIT_COPILOT_SESSION_TTL_SECONDS"),
        key="CHAINLIT_COPILOT_SESSION_TTL_SECONDS",
        default=3600,
        minimum=60,
        maximum=86400,
    )
    max_sessions = _parse_bounded_int(
        _read_setting(config, environ, "CHAINLIT_COPILOT_MAX_SESSIONS"),
        key="CHAINLIT_COPILOT_MAX_SESSIONS",
        default=1000,
        minimum=1,
        maximum=10000,
    )
    bootstrap_rate_limit_per_minute = _parse_bounded_int(
        _read_setting(
            config,
            environ,
            "CHAINLIT_COPILOT_BOOTSTRAP_RATE_LIMIT_PER_MINUTE",
        ),
        key="CHAINLIT_COPILOT_BOOTSTRAP_RATE_LIMIT_PER_MINUTE",
        default=60,
        minimum=1,
        maximum=600,
    )
    return EmbedSettings(
        enabled=True,
        allowed_origins=allowed_origins,
        ui_origin=ui_origin,
        root_path=root_path,
        auth_mode=auth_mode,
        cookie_samesite=cookie_samesite,
        entra_tenant_id=tenant_id,
        entra_audience=audience,
        entra_required_scope=required_scope,
        entra_allowed_client_ids=allowed_client_ids,
        session_ttl_seconds=session_ttl_seconds,
        max_sessions=max_sessions,
        bootstrap_rate_limit_per_minute=bootstrap_rate_limit_per_minute,
    )


def configure_chainlit_allowed_origins(
    settings: EmbedSettings,
    chainlit_config,
) -> None:
    """Set in-memory CORS origins before Chainlit creates its server app."""

    if not settings.enabled:
        return
    chainlit_config.project.allow_origins = list(settings.runtime_allowed_origins)
