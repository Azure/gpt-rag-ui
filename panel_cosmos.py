"""Panel-only Cosmos DB client for owner-index and feedback metadata
(issue #611, ADR-0004). Constructed and used only when
``DEPLOY_ADMINISTRATIVE_PANEL`` and ``PANEL_HISTORY_ENABLED`` are both
true (see ``panel_config.py``); no code path here runs otherwise.

Mirrors the connection-pooling and credential pattern already used by the
orchestrator's Cosmos client (a single persistent ``CosmosClient`` reusing
TCP/TLS across requests, authenticated with the same chained managed
identity / Azure CLI credential used elsewhere in this app), scoped to two
metadata-only containers:

* the owner index (``panel_config.PanelSettings.owner_index_container``) —
  ``principal_id`` (validated Entra ``oid``) -> conversation id, title,
  timestamps; nothing else.
* feedback (``panel_config.PanelSettings.feedback_container``) —
  ``principal_id`` -> feedback records (rating/category/comment/message
  reference); no message content, no citations.

Both containers are partitioned by ``/principal_id``, matching the
existing classic-mode ``conversations`` container convention.
"""

from __future__ import annotations

import logging

from azure.cosmos.aio import CosmosClient
from azure.cosmos.exceptions import CosmosHttpResponseError, CosmosResourceNotFoundError

from connectors.appconfig import AppConfigClient
from panel_config import PanelSettings

logger = logging.getLogger("gpt_rag_ui.panel_cosmos")


class PanelStoreError(RuntimeError):
    """Raised for any Cosmos failure that is not a plain not-found read.

    Callers must treat this as an explicit downstream/dependency failure
    (HTTP 502), never a 404-equivalent and never a silently degraded
    response.
    """


class PanelCosmosClient:
    """Thin async wrapper owning the two panel metadata containers.

    A single persistent ``CosmosClient`` is created once and reused, exactly
    like the orchestrator's ``CosmosDBClient``, to avoid a per-request
    TCP/TLS handshake.
    """

    def __init__(self, settings: PanelSettings, config: AppConfigClient):
        if not (settings.deploy_administrative_panel and settings.history_enabled):
            raise ValueError(
                "PanelCosmosClient requires DEPLOY_ADMINISTRATIVE_PANEL=true "
                "and PANEL_HISTORY_ENABLED=true."
            )
        if not settings.database_account_name or not settings.database_name:
            raise ValueError(
                "PanelCosmosClient requires database_account_name and "
                "database_name."
            )
        self.settings = settings
        db_uri = (
            f"https://{settings.database_account_name}.documents.azure.com:443/"
        )
        self._client = CosmosClient(db_uri, credential=config.aiocredential)
        self._database_name = settings.database_name

    def _container(self, container_name: str):
        db = self._client.get_database_client(database=self._database_name)
        return db.get_container_client(container_name)

    @property
    def owner_index_container(self):
        return self._container(self.settings.owner_index_container)

    @property
    def feedback_container(self):
        return self._container(self.settings.feedback_container)

    async def read_item(self, container_name: str, item_id: str, partition_key: str):
        try:
            return await self._container(container_name).read_item(
                item=item_id, partition_key=partition_key
            )
        except CosmosResourceNotFoundError:
            return None
        except CosmosHttpResponseError as exc:
            logger.error(
                "[panel_cosmos] read failed (container=%s, status=%s)",
                container_name,
                getattr(exc, "status_code", "unknown"),
            )
            raise PanelStoreError("Panel metadata read failed.") from exc

    async def upsert_item(self, container_name: str, body: dict) -> dict:
        try:
            return await self._container(container_name).upsert_item(body=body)
        except CosmosHttpResponseError as exc:
            logger.error(
                "[panel_cosmos] upsert failed (container=%s, status=%s)",
                container_name,
                getattr(exc, "status_code", "unknown"),
            )
            raise PanelStoreError("Panel metadata write failed.") from exc

    async def delete_item(self, container_name: str, item_id: str, partition_key: str) -> None:
        try:
            await self._container(container_name).delete_item(
                item=item_id, partition_key=partition_key
            )
        except CosmosResourceNotFoundError:
            return
        except CosmosHttpResponseError as exc:
            logger.error(
                "[panel_cosmos] delete failed (container=%s, status=%s)",
                container_name,
                getattr(exc, "status_code", "unknown"),
            )
            raise PanelStoreError("Panel metadata delete failed.") from exc

    async def query_items(
        self,
        container_name: str,
        *,
        query: str,
        parameters: list[dict],
        partition_key: str,
    ) -> list[dict]:
        try:
            items = []
            async for item in self._container(container_name).query_items(
                query=query,
                parameters=parameters,
                partition_key=partition_key,
            ):
                items.append(item)
            return items
        except CosmosHttpResponseError as exc:
            logger.error(
                "[panel_cosmos] query failed (container=%s, status=%s)",
                container_name,
                getattr(exc, "status_code", "unknown"),
            )
            raise PanelStoreError("Panel metadata query failed.") from exc

    async def aclose(self) -> None:
        await self._client.close()


_panel_cosmos_client_instance: PanelCosmosClient | None = None


def get_panel_cosmos_client(
    settings: PanelSettings, config: AppConfigClient
) -> PanelCosmosClient:
    """Return a process-wide singleton ``PanelCosmosClient``.

    Callers must only invoke this when ``settings.deploy_administrative_panel``
    and ``settings.history_enabled`` are both true (enforced by the
    constructor above); every caller in this codebase already gates on that
    before reaching here.
    """
    global _panel_cosmos_client_instance
    if _panel_cosmos_client_instance is None:
        _panel_cosmos_client_instance = PanelCosmosClient(settings, config)
    return _panel_cosmos_client_instance


def reset_panel_cosmos_client_for_tests() -> None:
    """Test-only hook to drop the process-wide singleton between tests."""
    global _panel_cosmos_client_instance
    _panel_cosmos_client_instance = None
