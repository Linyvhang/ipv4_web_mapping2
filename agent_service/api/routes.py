"""单 IP 分析 API 路由。"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status

from agent_service.models.analysis_schema import AnalysisResult
from agent_service.providers.base import ModelProviderError
from agent_service.services.ip_analysis import AssetNotFoundError, UnsupportedAddressError
from agent_service.services.single_ip_graph import initial_state
from agent_service.services.task_orchestrator import (
    CachedModelConflictError,
    SingleIPExecution,
)

from .schemas import IPAnalysisRequest, IPAnalysisResponse


def create_single_ip_router(graph: Any) -> APIRouter:
    """创建通过 LangGraph 执行单 IP 分析的路由。"""

    router = APIRouter(prefix="/analysis", tags=["analysis"])

    @router.post("/ip", response_model=IPAnalysisResponse)
    async def analyze_ip(request: IPAnalysisRequest) -> IPAnalysisResponse:
        try:
            state = await graph.ainvoke(
                initial_state(
                    str(request.ip),
                    scan_round=request.scan_round,
                    save_result=request.save_result,
                )
            )
            execution = state["execution"]
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

        return _to_response(execution)

    return router


def _to_response(execution: SingleIPExecution) -> IPAnalysisResponse:
    result = execution.result
    if isinstance(result, AnalysisResult):
        result_json = result.model_dump(mode="json")
    else:
        result_json = result.result_json
    return IPAnalysisResponse(
        task_id=execution.task_id,
        task_item_id=execution.task_item_id,
        reused=execution.reused,
        result=result_json,
    )

