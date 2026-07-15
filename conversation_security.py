from orchestrator_client import call_orchestrator_get_conversation
from auth_common import canonical_principal_id
from embed_auth import resolve_access_token


def principal_id_from_metadata(metadata: dict | None) -> str:
    metadata = metadata or {}
    try:
        canonical_id = canonical_principal_id(
            str(metadata.get("tenant_id") or ""),
            str(metadata.get("object_id") or ""),
        )
    except ValueError:
        return ""

    declared_id = str(
        metadata.get("principal_id")
        or metadata.get("client_principal_id")
        or ""
    ).strip().lower()
    if declared_id and declared_id != canonical_id:
        return ""
    return canonical_id


def conversation_belongs_to(conversation: dict, metadata: dict | None) -> bool:
    """Check the identity returned by the token-scoped orchestrator endpoint.

    Chainlit uses tid:oid as its stable identity. The token-scoped orchestrator
    currently returns a bare oid, which is accepted only after the request has
    been authenticated with the same validated user token.
    """

    metadata = metadata or {}
    canonical_id = principal_id_from_metadata(metadata)
    tenant_id = str(metadata.get("tenant_id") or "").strip().lower()
    object_id = str(metadata.get("object_id") or "").strip().lower()
    if not canonical_id or not tenant_id or not object_id:
        return False

    user_context = conversation.get("user_context") or {}
    conversation_principal = str(
        conversation.get("principal_id")
        or user_context.get("principal_id")
        or user_context.get("client_principal_id")
        or user_context.get("oid")
        or ""
    ).strip().lower()
    conversation_tenant = str(
        conversation.get("tenant_id")
        or user_context.get("tenant_id")
        or user_context.get("tid")
        or ""
    ).strip().lower()

    if conversation_principal == canonical_id:
        return not conversation_tenant or conversation_tenant == tenant_id
    if conversation_principal != object_id:
        return False
    return not conversation_tenant or conversation_tenant == tenant_id


async def get_owned_conversation(
    conversation_id: str,
    metadata: dict | None,
) -> dict | None:
    access_token = await resolve_access_token(metadata)
    if not access_token:
        return None
    conversation = await call_orchestrator_get_conversation(
        access_token=access_token,
        conversation_id=conversation_id,
    )
    if not conversation or not conversation_belongs_to(conversation, metadata):
        return None
    return conversation
