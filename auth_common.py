import logging

from connectors.appconfig import AppConfigClient


logger = logging.getLogger("gpt_rag_ui.auth_common")


def _read_list(config: AppConfigClient, key: str) -> list[str]:
    value = config.get(key, "", str) or ""
    return [item.strip() for item in value.split(",") if item.strip()]


def is_user_authorized(
    config: AppConfigClient,
    principal_name: str,
    principal_id: str,
) -> bool:
    allowed_names = _read_list(config, "ALLOWED_USER_NAMES")
    allowed_ids = _read_list(config, "ALLOWED_USER_PRINCIPALS")

    if not (allowed_names or allowed_ids):
        return True
    if principal_name in allowed_names or principal_id in allowed_ids:
        return True

    logger.warning(
        "Access denied for principal '%s' (%s). No matching allow list entry.",
        principal_name,
        principal_id,
    )
    return False
