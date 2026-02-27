"""
Custom Data Layer for Chainlit that persists conversations and feedback to the GPT-RAG orchestrator.
"""

import asyncio
import logging
import uuid

from datetime import datetime
from typing import Optional
from azure.cosmos.aio import CosmosClient
from azure.identity.aio import DefaultAzureCredential as AsyncDefaultAzureCredential
from chainlit.context import context
from chainlit.step import StepDict
from chainlit.data.base import BaseDataLayer
from chainlit.logger import logger
from chainlit.types import (
    PaginatedResponse,
    Pagination,
    ThreadDict,
    ThreadFilter,
    PageInfo,
)
from chainlit.user import PersistedUser, User
import chainlit as cl
from dependencies import get_config

_logger = logger.getChild("OrchestratorDataLayer")

# Suppress noisy Azure SDK logs
logging.getLogger("azure.identity").setLevel(logging.WARNING)
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)

def _get_current_timestamp() -> str:
    """Get current timestamp in Chainlit format (ISO 8601 with Z suffix, no microseconds)."""
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

@cl.data_layer
def get_data_layer():
    return OrchestratorDataLayer()

# Configuration - using the same pattern as app.py
config = get_config()
COSMOS_DB_ENDPOINT = config.get("COSMOS_DB_ENDPOINT", str)
COSMOS_DB_DATABASE_NAME = config.get("DATABASE_NAME", str)
COSMOS_USERS_CONTAINER = "chainlit_users"

# Process-level singletons for credential and Cosmos client
_credential: Optional[AsyncDefaultAzureCredential] = None
_cosmos_client: Optional[CosmosClient] = None
_init_lock = asyncio.Lock()


async def get_cosmos_client() -> CosmosClient:
    """Get or create the singleton Cosmos DB client."""
    global _credential, _cosmos_client
    
    if _cosmos_client:
        return _cosmos_client
    
    async with _init_lock:
        if _cosmos_client:
            return _cosmos_client
        
        if not _credential:
            _credential = AsyncDefaultAzureCredential()
        
        _cosmos_client = CosmosClient(COSMOS_DB_ENDPOINT, credential=_credential)
        return _cosmos_client



class OrchestratorDataLayer(BaseDataLayer):
    """Custom data layer for Chainlit that persists users and conversations to Cosmos DB."""

    async def get_user(self, identifier: str) -> Optional[PersistedUser]:
        """Fetch a user by identifier from Cosmos DB."""
        try:
            client = await get_cosmos_client()
            db = client.get_database_client(COSMOS_DB_DATABASE_NAME)
            container = db.get_container_client(COSMOS_USERS_CONTAINER)
            
            try:
                user_doc = await container.read_item(item=identifier, partition_key=identifier)
                return PersistedUser(
                    id=user_doc.get("id", identifier),
                    identifier=user_doc.get("identifier"),
                    createdAt=user_doc.get("createdAt"),
                    metadata=user_doc.get("metadata", {})
                )
            except Exception:
                return None
        except Exception as e:
            _logger.error("Error getting user: %s", e)
            return None

    async def create_thread(self, thread_dict: ThreadDict) -> str:
        """Thread creation is handled by orchestrator via the chat interface."""
        return thread_dict["id"]

    async def list_threads(
        self,
        pagination: Pagination,
        filters: ThreadFilter
    ) -> PaginatedResponse[ThreadDict]:
        """List conversations for current user from Cosmos DB."""
        empty_response = PaginatedResponse(
            data=[],
            pageInfo=PageInfo(hasNextPage=False, startCursor=None, endCursor=None)
        )
        
        try:
            user_id = filters.userId if hasattr(filters, 'userId') else None
            if not user_id:
                return empty_response
            
            user = await self.get_user(user_id)
            if not user or not user.metadata:
                return empty_response
            
            principal_id = user.metadata.get("principal_id")
            if not principal_id:
                return empty_response
            
            skip = getattr(pagination, 'offset', None) or getattr(pagination, 'after', None) or 0
            limit = getattr(pagination, 'limit', None) or getattr(pagination, 'first', None) or 10
            if isinstance(skip, str):
                skip = int(skip)
            if isinstance(limit, str):
                limit = int(limit)
            
            client = await get_cosmos_client()
            db = client.get_database_client(COSMOS_DB_DATABASE_NAME)
            container = db.get_container_client("conversations")

            query = (
                """
                SELECT c.id, c.name, c._ts, c.lastUpdated
                FROM c
                WHERE c.principal_id = @principal_id 
                  AND (NOT IS_DEFINED(c.isDeleted) OR c.isDeleted = false)
                ORDER BY c._ts DESC
                OFFSET @skip LIMIT @limit
                """
            )

            params = [
                {"name": "@principal_id", "value": principal_id},
                {"name": "@skip", "value": skip},
                {"name": "@limit", "value": limit},
            ]

            items_iterable = container.query_items(
                query=query,
                parameters=params,
                partition_key=principal_id,
            )

            threads = []
            async for conv in items_iterable:
                thread = ThreadDict(
                    id=conv.get("id"),
                    name=conv.get("name"),
                    createdAt=conv.get("lastUpdated"),
                    userId=principal_id,
                    userIdentifier=user_id,
                    metadata={
                        "principal_id": principal_id,
                    },
                )
                threads.append(thread)

            has_more = len(threads) == limit
            return PaginatedResponse(
                data=threads,
                pageInfo=PageInfo(
                    hasNextPage=has_more,
                    startCursor=str(skip),
                    endCursor=str(skip + len(threads)) if has_more else None,
                ),
            )
                
        except Exception as e:
            _logger.error("Error listing threads: %s", e)
            raise

    async def create_user(self, user: User) -> Optional[PersistedUser]:
        """Create or update a user in Cosmos DB."""
        try:
            principal_id = user.metadata.get("principal_id") if user.metadata else None
            if not principal_id:
                principal_id = user.metadata.get("client_principal_id") if user.metadata else None
            
            if not principal_id:
                _logger.warning("No principal_id in user metadata for %s", user.identifier)
                return None
            
            user_doc = {
                "id": user.identifier,
                "identifier": user.identifier,
                "principal_id": principal_id,
                "metadata": user.metadata or {},
                "createdAt": datetime.now().isoformat()
            }
            
            client = await get_cosmos_client()
            db = client.get_database_client(COSMOS_DB_DATABASE_NAME)
            container = db.get_container_client(COSMOS_USERS_CONTAINER)
            
            try:
                await container.create_item(body=user_doc)
            except Exception as e:
                if "Conflict" in str(e) or "409" in str(e):
                    await container.replace_item(item=user.identifier, body=user_doc)
                else:
                    raise
            
            persisted = PersistedUser(
                id=user.identifier,
                identifier=user.identifier,
                createdAt=user_doc["createdAt"],
                metadata=user.metadata or {}
            )
            
            try:
                cl.user_session.set("user", persisted)
            except Exception:
                pass
            
            return persisted
            
        except Exception as e:
            _logger.error("Error creating user: %s", e)
            return None
    
    async def upsert_feedback(self, feedback) -> str:
        return ""
    
    async def delete_feedback(self, feedback_id: str) -> bool:
        return True
    
    async def create_element(self, element_dict) -> None:
        pass
    
    async def get_element(self, thread_id: str, element_id: str):
        return None
    
    async def delete_element(self, element_id: str) -> bool:
        return True
    
    async def create_step(self, step_dict) -> StepDict:
        return step_dict
    
    async def update_step(self, step_dict) -> StepDict:
        return step_dict
    
    async def delete_step(self, step_id: str) -> bool:
        return True
    
    def _messages_to_steps(self, messages: list, thread_id: str) -> list:
        """Convert conversation messages to Chainlit StepDict format."""
        steps = []
        for msg in messages:
            role = msg.get("role", "")
            text = msg.get("text", "")
            step_type = "user_message" if role == "user" else "assistant_message"
            
            steps.append({
                "id": str(uuid.uuid4()),
                "threadId": thread_id,
                "type": step_type,
                "output": text,
                "createdAt": _get_current_timestamp(),
                "isError": False,
                "metadata": {}
            })
        return steps

    async def get_thread(self, thread_id: str) -> Optional[ThreadDict]:
        """Retrieve a conversation from Cosmos DB by thread_id."""
        try:
            client = await get_cosmos_client()
            db = client.get_database_client(COSMOS_DB_DATABASE_NAME)
            container = db.get_container_client("conversations")
            
            query = "SELECT * FROM c WHERE c.id = @thread_id"
            items = []
            async for item in container.query_items(
                query=query,
                parameters=[{"name": "@thread_id", "value": thread_id}],
                max_item_count=1
            ):
                items.append(item)
            
            if not items:
                return None
            
            conv = items[0]
            
            # Filter out soft-deleted conversations
            if conv.get("isDeleted") == True:
                return None
            
            principal_id = conv.get("principal_id")
            user_context = conv.get("user_context", {})
            user_identifier = user_context.get("user_name") or principal_id
            
            ts_value = conv.get("_ts")
            created_at = None
            if ts_value:
                try:
                    if isinstance(ts_value, str):
                        created_at = ts_value if ts_value.endswith("Z") else ts_value + "Z"
                    else:
                        created_at = datetime.fromtimestamp(ts_value).isoformat() + "Z"
                except (ValueError, TypeError):
                    pass
            
            messages = conv.get("messages", [])
            steps = self._messages_to_steps(messages, thread_id)
            
            return ThreadDict(
                id=conv["id"],
                name=conv.get("name", ""),
                createdAt=created_at,
                userId=principal_id,
                userIdentifier=user_identifier,
                tags=[],
                metadata={"principal_id": principal_id},
                steps=steps
            )
                
        except Exception as e:
            _logger.error("Error getting thread: %s", e)
            return None
    
    async def update_thread(self, thread_id: str, **kwargs) -> None:
        cl.user_session.set("conversation_id", thread_id)
        pass
    
    async def delete_thread(self, thread_id: str) -> bool:
        return False
    
    async def get_thread_author(self, thread_id: str) -> Optional[str]:
        """Get the author name of a thread."""
        try:
            client = await get_cosmos_client()
            db = client.get_database_client(COSMOS_DB_DATABASE_NAME)
            container = db.get_container_client("conversations")
            
            query = "SELECT c.user_context FROM c WHERE c.id = @thread_id"
            async for item in container.query_items(
                query=query,
                parameters=[{"name": "@thread_id", "value": thread_id}],
                max_item_count=1
            ):
                user_context = item.get("user_context")
                if user_context:
                    return user_context.get("user_name")
            return None
                
        except Exception as e:
            _logger.error("Error getting thread author: %s", e)
            return None
    
    async def delete_user_session(self, id: str) -> bool:
        return True
    
    async def build_debug_url(self) -> str:
            return ""
