"""单 IP 分析 API 路由。"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse

from agent_service.models.analysis_schema import AnalysisResult
from agent_service.providers.base import ModelProviderError
from agent_service.services.ip_analysis import AssetNotFoundError, UnsupportedAddressError
from agent_service.services.single_ip_graph import initial_state
from agent_service.services.task_orchestrator import (
    CachedModelConflictError,
    SingleIPExecution,
)

from .schemas import IPAnalysisRequest, IPAnalysisResponse


GRAPH_NODE_LABELS = {
    "load_asset": "读取扫描数据",
    "check_cache": "检查已有结果",
    "return_cached": "复用已有结果",
    "create_task": "创建分析任务",
    "analyze_asset": "模型分析资产",
    "validate_analysis": "校验分析证据",
    "prepare_retry": "准备重新分析",
    "build_fallback": "生成安全降级结果",
    "persist_result": "保存分析结果",
}


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

    @router.post("/ip/stream")
    async def analyze_ip_stream(request: IPAnalysisRequest) -> StreamingResponse:
        """以 NDJSON 流返回 LangGraph 节点进度和最终分析结果。"""

        async def event_stream() -> AsyncIterator[str]:
            yield _ndjson(
                {
                    "type": "start",
                    "steps": [
                        {"node": node, "label": label}
                        for node, label in GRAPH_NODE_LABELS.items()
                    ],
                }
            )
            execution: SingleIPExecution | None = None
            try:
                async for update in graph.astream(
                    initial_state(
                        str(request.ip),
                        scan_round=request.scan_round,
                        save_result=request.save_result,
                    ),
                    stream_mode="updates",
                ):
                    for node_name, node_update in update.items():
                        yield _ndjson(
                            {
                                "type": "node",
                                "node": node_name,
                                "label": GRAPH_NODE_LABELS.get(
                                    node_name, node_name
                                ),
                                "status": "completed",
                            }
                        )
                        if isinstance(node_update, dict):
                            candidate = node_update.get("execution")
                            if isinstance(candidate, SingleIPExecution):
                                execution = candidate

                if execution is None:
                    raise RuntimeError("LangGraph 未返回分析执行结果")
                yield _ndjson(
                    {
                        "type": "result",
                        "data": _to_response(execution).model_dump(mode="json"),
                    }
                )
            except CachedModelConflictError as exc:
                yield _stream_error(409, str(exc))
            except ModelProviderError as exc:
                yield _stream_error(502, str(exc))
            except AssetNotFoundError as exc:
                yield _stream_error(404, str(exc))
            except UnsupportedAddressError as exc:
                yield _stream_error(400, str(exc))
            except Exception:
                yield _stream_error(500, "分析流程发生内部错误")

        return StreamingResponse(
            event_stream(),
            media_type="application/x-ndjson",
            headers={
                "Cache-Control": "no-cache",
                "X-Content-Type-Options": "nosniff",
            },
        )

    return router


def _ndjson(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"


def _stream_error(status_code: int, detail: str) -> str:
    return _ndjson(
        {"type": "error", "status_code": status_code, "detail": detail}
    )


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

