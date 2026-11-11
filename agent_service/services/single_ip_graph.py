"""LangGraph 单 IP 分析流程适配层。

图只负责流程编排，业务逻辑仍由 ``SingleIPTaskOrchestrator`` 执行。
LangGraph 采用延迟导入，避免仅使用数据模型或 Repository 测试时必须安装图运行时。
"""

from __future__ import annotations

from typing import Any, TypedDict

from agent_service.models.analysis_schema import AnalysisResult
from agent_service.models.input_schema import AssetAnalysisInput

from .analysis_validation import (
    build_safe_fallback_result,
    validate_analysis_result,
)
from .task_orchestrator import SingleIPExecution, SingleIPTaskOrchestrator


class SingleIPGraphState(TypedDict, total=False):
    """单 IP 图的输入和输出状态。"""

    ip: str
    scan_round: int | None
    save_result: bool
    asset: AssetAnalysisInput
    cached_execution: SingleIPExecution | None
    task_id: int
    task_item_id: int
    analysis_result: AnalysisResult
    validation_errors: list[str]
    retry_count: int
    max_retries: int
    fallback_used: bool
    execution: SingleIPExecution


def initial_state(
    ip: str,
    *,
    scan_round: int | None = None,
    save_result: bool = True,
) -> SingleIPGraphState:
    """构造图的初始状态，供 API/Worker 入口复用。"""

    return {
        "ip": ip,
        "scan_round": scan_round,
        "save_result": save_result,
        "retry_count": 0,
        "max_retries": 1,
        "fallback_used": False,
    }


def build_single_ip_graph(orchestrator: SingleIPTaskOrchestrator) -> Any:
    """构建并编译单 IP LangGraph 的第一版多节点流程。

    ``langgraph`` 未安装时抛出明确错误；这使基础 Schema/Repository 测试不必
    启动图运行时，同时保留生产环境的显式依赖检查。
    """

    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:  # pragma: no cover - 取决于部署依赖
        raise RuntimeError(
            "运行单 IP LangGraph 前请安装 requirements.txt 中的 langgraph"
        ) from exc

    async def load_asset_node(
        state: SingleIPGraphState,
    ) -> dict[str, AssetAnalysisInput]:
        asset = await orchestrator.load_asset(
            state["ip"], scan_round=state.get("scan_round")
        )
        return {"asset": asset}

    async def check_cache_node(
        state: SingleIPGraphState,
    ) -> dict[str, SingleIPExecution | None]:
        cached = await orchestrator.get_cached_execution(state["asset"])
        return {"cached_execution": cached}

    def route_after_cache(state: SingleIPGraphState) -> str:
        return "cached" if state.get("cached_execution") is not None else "miss"

    def return_cached_node(
        state: SingleIPGraphState,
    ) -> dict[str, SingleIPExecution]:
        execution = state.get("cached_execution")
        if execution is None:  # pragma: no cover - 由条件边保证
            raise RuntimeError("缓存分支缺少 cached_execution")
        return {"execution": execution}

    async def create_task_node(
        state: SingleIPGraphState,
    ) -> dict[str, int]:
        task_id, item_id = await orchestrator.start_task(
            state["asset"],
            requested_ip=state["ip"],
            requested_scan_round=state.get("scan_round"),
            save_result=state.get("save_result", True),
        )
        return {"task_id": task_id, "task_item_id": item_id}

    async def analyze_asset_node(
        state: SingleIPGraphState,
    ) -> dict[str, AnalysisResult]:
        try:
            result = await orchestrator.analyze_asset(
                state["asset"], state.get("validation_errors")
            )
        except Exception as exc:
            await orchestrator.fail_task(
                task_id=state["task_id"],
                item_id=state["task_item_id"],
                error=exc,
            )
            raise
        return {"analysis_result": result}

    def validate_analysis_node(
        state: SingleIPGraphState,
    ) -> dict[str, list[str]]:
        validation = validate_analysis_result(
            state["analysis_result"], state["asset"]
        )
        return {"validation_errors": list(validation.errors)}

    def route_after_validation(state: SingleIPGraphState) -> str:
        if not state.get("validation_errors"):
            return "valid"
        if state.get("retry_count", 0) < state.get("max_retries", 1):
            return "retry"
        return "fallback"

    def prepare_retry_node(state: SingleIPGraphState) -> dict[str, int]:
        return {"retry_count": state.get("retry_count", 0) + 1}

    def build_fallback_node(
        state: SingleIPGraphState,
    ) -> dict[str, AnalysisResult | bool]:
        result = build_safe_fallback_result(
            state["analysis_result"], state.get("validation_errors", [])
        )
        return {"analysis_result": result, "fallback_used": True}

    async def persist_result_node(
        state: SingleIPGraphState,
    ) -> dict[str, SingleIPExecution]:
        try:
            execution = await orchestrator.complete_task(
                task_id=state["task_id"],
                item_id=state["task_item_id"],
                result=state["analysis_result"],
                save_result=state.get("save_result", True),
            )
        except Exception as exc:
            await orchestrator.fail_task(
                task_id=state["task_id"],
                item_id=state["task_item_id"],
                error=exc,
            )
            raise
        return {"execution": execution}

    graph = StateGraph(SingleIPGraphState)
    graph.add_node("load_asset", load_asset_node)
    graph.add_node("check_cache", check_cache_node)
    graph.add_node("return_cached", return_cached_node)
    graph.add_node("create_task", create_task_node)
    graph.add_node("analyze_asset", analyze_asset_node)
    graph.add_node("validate_analysis", validate_analysis_node)
    graph.add_node("prepare_retry", prepare_retry_node)
    graph.add_node("build_fallback", build_fallback_node)
    graph.add_node("persist_result", persist_result_node)
    graph.add_edge(START, "load_asset")
    graph.add_edge("load_asset", "check_cache")
    graph.add_conditional_edges(
        "check_cache",
        route_after_cache,
        {"cached": "return_cached", "miss": "create_task"},
    )
    graph.add_edge("return_cached", END)
    graph.add_edge("create_task", "analyze_asset")
    graph.add_edge("analyze_asset", "validate_analysis")
    graph.add_conditional_edges(
        "validate_analysis",
        route_after_validation,
        {
            "valid": "persist_result",
            "retry": "prepare_retry",
            "fallback": "build_fallback",
        },
    )
    graph.add_edge("prepare_retry", "analyze_asset")
    graph.add_edge("build_fallback", "persist_result")
    graph.add_edge("persist_result", END)
    return graph.compile()

