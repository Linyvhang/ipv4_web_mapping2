"""LangGraph 单 IP 分析流程适配层。

图只负责流程编排，业务逻辑仍由 ``SingleIPTaskOrchestrator`` 执行。
LangGraph 采用延迟导入，避免仅使用数据模型或 Repository 测试时必须安装图运行时。
"""

from __future__ import annotations

from typing import Any, TypedDict

from .task_orchestrator import SingleIPExecution, SingleIPTaskOrchestrator


class SingleIPGraphState(TypedDict, total=False):
    """单 IP 图的输入和输出状态。"""

    ip: str
    scan_round: int | None
    save_result: bool
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
    }


def build_single_ip_graph(orchestrator: SingleIPTaskOrchestrator) -> Any:
    """构建并编译单节点 LangGraph。

    ``langgraph`` 未安装时抛出明确错误；这使基础 Schema/Repository 测试不必
    启动图运行时，同时保留生产环境的显式依赖检查。
    """

    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:  # pragma: no cover - 取决于部署依赖
        raise RuntimeError(
            "运行单 IP LangGraph 前请安装 requirements.txt 中的 langgraph"
        ) from exc

    async def analyze_node(state: SingleIPGraphState) -> dict[str, SingleIPExecution]:
        execution = await orchestrator.execute(
            state["ip"],
            scan_round=state.get("scan_round"),
            save_result=state.get("save_result", True),
        )
        return {"execution": execution}

    graph = StateGraph(SingleIPGraphState)
    graph.add_node("analyze", analyze_node)
    graph.add_edge(START, "analyze")
    graph.add_edge("analyze", END)
    return graph.compile()

