import logging
import uuid

from connectors.appconfig import AppConfigClient


logger = logging.getLogger("gpt_rag_ui.auth_common")


def normalize_guid(value: str, *, claim_name: str) -> str:
    try:
        return str(uuid.UUID(str(value or "").strip()))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{claim_name} must be a GUID.") from exc


def canonical_principal_id(tenant_id: str, object_id: str) -> str:
    tenant = normalize_guid(tenant_id, claim_name="tid")
    principal = normalize_guid(object_id, claim_name="oid")
    return f"{tenant}:{principal}"


def _read_list(config: AppConfigClient, key: str) -> list[str]:
    value = config.get(key, "", str) or ""
    return [item.strip() for item in value.split(",") if item.strip()]


def is_user_authorized(
    config: AppConfigClient,
    principal_name: str,
    principal_id: str,
) -> bool:
    allowed_names = {
        value.casefold() for value in _read_list(config, "ALLOWED_USER_NAMES")
    }
    allowed_ids = {
        value.lower() for value in _read_list(config, "ALLOWED_USER_PRINCIPALS")
    }

    if not (allowed_names or allowed_ids):
        return True

    normalized_principal_id = str(principal_id or "").strip().lower()
    candidate_ids = {normalized_principal_id}
    if ":" in normalized_principal_id:
        _, object_id = normalized_principal_id.split(":", 1)
        if object_id:
            candidate_ids.add(object_id)

    if (
        str(principal_name or "").strip().casefold() in allowed_names
        or not candidate_ids.isdisjoint(allowed_ids)
    ):
        return True

    logger.warning(
        "Access denied for principal '%s' (%s). No matching allow list entry.",
        principal_name,
        principal_id,
    )
    return False
