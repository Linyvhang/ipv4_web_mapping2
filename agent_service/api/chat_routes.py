"""自然语言资产分析 Agent API。"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status

from agent_service.models.chat_schema import AgentChatRequest, AgentChatResponse
from agent_service.providers.base import ModelProviderError
from agent_service.services.chat_agent_graph import chat_response_from_state
from agent_service.services.chat_agent_state import initial_chat_state
from agent_service.services.ip_analysis import AssetNotFoundError, UnsupportedAddressError
from agent_service.services.task_orchestrator import CachedModelConflictError


def create_chat_agent_router(graph: Any, checkpointer: Any | None = None) -> APIRouter:
    """创建使用 LangGraph Checkpoint 的多轮问答路由。"""

    router = APIRouter(prefix="/agent", tags=["agent"])

    @router.post("/chat", response_model=AgentChatResponse)
    async def chat(request: AgentChatRequest) -> AgentChatResponse:
        conversation_id = request.conversation_id or uuid4().hex
        config = {"configurable": {"thread_id": conversation_id}}
        previous_context: dict[str, Any] = {}
        if request.conversation_id is not None:
            snapshot = await graph.aget_state(config)
            values = snapshot.values or {}
            if values:
                previous_context = {
                    key: values.get(key)
                    for key in (
                        "intent",
                        "target_ip",
                        "from_scan_round",
                        "to_scan_round",
                        "task_id",
                    )
                    if values.get(key) is not None
                }
        try:
            state = await graph.ainvoke(
                initial_chat_state(
                    request.question,
                    scan_round=request.scan_round,
                    conversation_id=conversation_id,
                    previous_context=previous_context,
                ),
                config=config,
            )
        except CachedModelConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ModelProviderError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except AssetNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        except UnsupportedAddressError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc
        return chat_response_from_state(state)

    @router.delete("/conversations/{conversation_id}")
    async def delete_conversation(conversation_id: str) -> dict[str, object]:
        if checkpointer is None:
            raise HTTPException(status_code=503, detail="Checkpoint 尚未启用")
        if not 8 <= len(conversation_id) <= 64 or not all(
            character.isalnum() or character in "_-" for character in conversation_id
        ):
            raise HTTPException(status_code=422, detail="conversation_id 格式无效")
        await checkpointer.adelete_thread(conversation_id)
        return {"conversation_id": conversation_id, "deleted": True}

    return router
