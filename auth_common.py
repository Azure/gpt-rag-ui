import logging

from connectors.appconfig import AppConfigClient


logger = logging.getLogger("gpt_rag_ui.auth_common")


def canonical_principal_id(tenant_id: str, object_id: str) -> str:
    tenant = str(tenant_id or "").strip().lower()
    principal = str(object_id or "").strip().lower()
    if not tenant or not principal:
        raise ValueError("Both tid and oid are required for a stable user identity.")
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
            # Keep the established bare-oid allow-list contract used by the
            # orchestrator while preferring tid:oid for new UI configuration.
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
