"""自然语言资产分析 Agent API。"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status

from agent_service.models.chat_schema import AgentChatRequest, AgentChatResponse
from agent_service.providers.base import ModelProviderError
from agent_service.services.chat_agent_graph import chat_response_from_state
from agent_service.services.chat_agent_state import initial_chat_state
from agent_service.services.ip_analysis import AssetNotFoundError, UnsupportedAddressError
from agent_service.services.task_orchestrator import CachedModelConflictError


def create_chat_agent_router(graph: Any) -> APIRouter:
    """创建执行自然语言 LangGraph 的单轮问答路由。"""

    router = APIRouter(prefix="/agent", tags=["agent"])

    @router.post("/chat", response_model=AgentChatResponse)
    async def chat(request: AgentChatRequest) -> AgentChatResponse:
        try:
            state = await graph.ainvoke(
                initial_chat_state(
                    request.question,
                    scan_round=request.scan_round,
                )
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

    return router
