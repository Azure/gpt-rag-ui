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


def safe_profile_metadata(metadata: dict | None) -> dict:
    """Return the non-secret identity fields that may be cached or serialized."""

    metadata = metadata or {}
    tenant_id = normalize_guid(metadata.get("tenant_id"), claim_name="tid")
    object_id = normalize_guid(metadata.get("object_id"), claim_name="oid")
    principal_id = canonical_principal_id(tenant_id, object_id)
    declared_principal = str(
        metadata.get("principal_id")
        or metadata.get("client_principal_id")
        or ""
    ).strip().lower()
    if declared_principal and declared_principal not in {principal_id, object_id}:
        raise ValueError("The declared principal does not match tid and oid.")

    raw_group_ids = metadata.get("client_group_names")
    group_values = (
        list(raw_group_ids)[:200]
        if isinstance(raw_group_ids, (list, tuple, set))
        else []
    )
    group_ids = []
    for value in group_values:
        try:
            group_ids.append(normalize_guid(value, claim_name="group"))
        except ValueError:
            logger.warning("Ignoring a non-GUID group claim")

    return {
        "authorized": bool(metadata.get("authorized", True)),
        "tenant_id": tenant_id,
        "object_id": object_id,
        "principal_id": principal_id,
        "client_principal_id": object_id,
        "client_principal_name": str(
            metadata.get("client_principal_name") or ""
        ).strip(),
        "client_group_names": group_ids,
        "user_name": principal_id,
    }


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
            # Existing deployments commonly allow-list a bare oid. Keep
            # accepting it while storing the tenant-qualified identity.
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
