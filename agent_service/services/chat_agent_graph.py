"""自然语言资产分析 Agent 的第一版 LangGraph 工作流。"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from agent_service.models.chat_schema import (
    AgentChatResponse,
    AgentEvidence,
    QuestionUnderstanding,
    ToolCallRecord,
    ToolUseSummary,
)
from agent_service.tools.asset_tools import (
    AgentToolPermissionError,
    AssetAgentToolRegistry,
    UnknownAgentToolError,
)

from .chat_agent_state import ChatAgentState
from .chat_understanding import ChatRequestValidator, QuestionUnderstandingProvider


def _product_values(service: dict[str, Any]) -> tuple[str | None, str | None]:
    product = service.get("product") or {}
    return (
        product.get("normalized_product_name") or product.get("raw_product_name"),
        product.get("normalized_version") or product.get("raw_version"),
    )


def _scan_evidence(asset: dict[str, Any]) -> list[AgentEvidence]:
    evidence: list[AgentEvidence] = []
    for service in asset.get("services", []):
        product, version = _product_values(service)
        protocol = service.get("transport_protocol", "unknown")
        service_type = service.get("service_type", "unknown")
        port = service.get("port")
        detail = service.get("banner") or f"{port}/{protocol} {service_type}"
        evidence.append(
            AgentEvidence(
                source="service_fingerprint",
                detail=str(detail),
                port=port,
                service_type=service_type,
                product=product,
                version=version,
                confidence=service.get("confidence"),
            )
        )
    return evidence


def _analysis_evidence(result: dict[str, Any]) -> list[AgentEvidence]:
    return [
        AgentEvidence(
            source=str(item.get("source") or item.get("source_type") or "analysis"),
            detail=str(item.get("detail") or "分析证据"),
            confidence=item.get("confidence"),
        )
        for item in result.get("evidence", [])
    ]


def _latest_success_data(state: ChatAgentState, tool_name: str) -> dict[str, Any] | None:
    for record in reversed(state["tool_history"]):
        if record.name == tool_name and record.status == "success":
            return record.result_data
    return None


def _compose_success_answer(state: ChatAgentState) -> tuple[str, list[AgentEvidence]]:
    ip = state.get("target_ip") or "目标 IP"
    intent = state.get("intent")
    analysis_data = _latest_success_data(state, "get_ip_analysis_result")
    create_data = _latest_success_data(state, "create_ip_analysis")
    scan_data = _latest_success_data(state, "get_ip_scan_data")

    if create_data is not None:
        result = create_data.get("result", {})
        summary = result.get("summary", {})
        action = "复用了已有分析结果" if create_data.get("reused") else "已完成新的分析任务"
        answer = f"{ip} {action}。{summary.get('description') or '已生成标准分析结果。'}"
        return answer, _analysis_evidence(result)

    if analysis_data is not None:
        result = analysis_data.get("result", {})
        summary = result.get("summary", {})
        risks = result.get("risks", [])
        answer = summary.get("description") or f"已读取 {ip} 的保存分析结果。"
        if risks:
            risk_titles = "、".join(str(risk.get("title", "疑似风险")) for risk in risks[:3])
            answer += f" 当前记录 {len(risks)} 项疑似风险：{risk_titles}。"
        evidence = _analysis_evidence(result)
        if intent == "explain_result" and scan_data is not None:
            evidence.extend(_scan_evidence(scan_data.get("asset", {})))
            answer += " 判断依据同时参考了保存的分析证据和原始服务指纹。"
        return answer, evidence

    if scan_data is not None:
        asset = scan_data.get("asset", {})
        services = asset.get("services", [])
        if services:
            labels = [
                f"{service.get('port')}/{service.get('transport_protocol', 'tcp')} "
                f"{service.get('service_type', 'unknown')}"
                for service in services[:5]
            ]
            answer = (
                f"{ip} 在扫描批次 {asset.get('scan_round')} 中发现 {len(services)} 个服务："
                + "、".join(labels)
                + "。"
            )
        else:
            answer = f"{ip} 存在扫描记录，但当前结果没有可展示的服务指纹。"
        return answer, _scan_evidence(asset)

    return "工具已执行，但没有返回可展示的数据。", []


def chat_response_from_state(state: ChatAgentState) -> AgentChatResponse:
    """把完成的图状态转换为稳定 API 契约。"""

    intent = state.get("intent") or "missing_target"
    return AgentChatResponse(
        answer=state.get("answer") or "当前没有可用回答。",
        intent=intent,
        target_ip=state.get("target_ip"),
        status=state.get("status", "failed"),
        tools_used=[
            ToolUseSummary(name=record.name, status=record.status, message=record.message)
            for record in state.get("tool_history", [])
        ],
        evidence=state.get("evidence", []),
        limitations=state.get("limitations", []),
    )


def build_chat_agent_graph(
    *,
    understanding_provider: QuestionUnderstandingProvider,
    request_validator: ChatRequestValidator,
    tool_registry: AssetAgentToolRegistry,
) -> Any:
    """构建问题理解、验证、工具调用和模板回答的 LangGraph。"""

    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("运行自然语言 Agent 前请安装 langgraph") from exc

    async def understand_question_node(state: ChatAgentState) -> dict[str, Any]:
        understanding = await understanding_provider.understand(state["question"])
        return {
            "understanding": understanding,
            "intent": understanding.intent,
            "target_ip": understanding.target_ip,
            "explicit_analysis_request": understanding.explicit_analysis_request,
        }

    def validate_request_node(state: ChatAgentState) -> dict[str, Any]:
        understanding = state.get("understanding")
        if understanding is None:  # pragma: no cover - 固定边保证
            return {"request_error": "问题理解结果缺失", "status": "failed"}
        validation = request_validator.validate(state["question"], understanding)
        if validation.valid:
            return {"request_error": None, "status": "pending"}
        return {
            "request_error": validation.error,
            "status": validation.status,
        }

    def route_after_validation(state: ChatAgentState) -> str:
        if state.get("status") == "unsupported":
            return "unsupported"
        if state.get("request_error"):
            return "invalid"
        return "valid"

    def reject_unsupported_node(state: ChatAgentState) -> dict[str, Any]:
        return {
            "answer": state.get("request_error")
            or "该请求不在只读资产分析能力范围内。",
            "status": "unsupported",
            "evidence": [],
        }

    def select_tool_node(state: ChatAgentState) -> dict[str, Any]:
        if state["tool_call_count"] >= state["max_tool_calls"]:
            return {
                "selected_tool": None,
                "request_error": "已达到最大工具调用次数",
                "continue_tool_loop": False,
            }
        intent = state.get("intent")
        used_tools = {record.name for record in state["tool_history"]}
        if intent == "create_analysis":
            selected = "create_ip_analysis"
        elif intent == "explain_result" and "get_ip_analysis_result" in used_tools:
            selected = "get_ip_scan_data"
        elif intent in {"query_analysis_result", "explain_result"}:
            selected = "get_ip_analysis_result"
        else:
            selected = "get_ip_scan_data"

        arguments: dict[str, Any] = {
            "ip": state["target_ip"],
            "scan_round": state.get("scan_round"),
        }
        if selected == "create_ip_analysis":
            arguments["save_result"] = True
        return {
            "selected_tool": selected,
            "tool_arguments": arguments,
            "continue_tool_loop": False,
        }

    async def execute_tool_node(state: ChatAgentState) -> dict[str, Any]:
        selected = state.get("selected_tool")
        sequence = state["tool_call_count"] + 1
        if selected is None:
            record = ToolCallRecord(
                sequence=sequence,
                name="get_ip_scan_data",
                arguments={},
                status="failed",
                message="没有可执行的工具",
            )
            return {
                "tool_history": [*state["tool_history"], record],
                "tool_call_count": sequence,
            }
        try:
            result = await tool_registry.execute(
                selected,
                state["tool_arguments"],
                allow_task_creation=state["explicit_analysis_request"],
            )
            record = ToolCallRecord(
                sequence=sequence,
                name=selected,
                arguments=dict(state["tool_arguments"]),
                status=result.status,
                message=result.message,
                result_data=result.data,
            )
        except AgentToolPermissionError as exc:
            record = ToolCallRecord(
                sequence=sequence,
                name=selected,
                arguments=dict(state["tool_arguments"]),
                status="denied",
                message=str(exc),
            )
        except (UnknownAgentToolError, ValidationError, ValueError) as exc:
            record = ToolCallRecord(
                sequence=sequence,
                name=selected,
                arguments=dict(state["tool_arguments"]),
                status="failed",
                message=str(exc),
            )
        return {
            "tool_history": [*state["tool_history"], record],
            "tool_call_count": sequence,
        }

    def evaluate_result_node(state: ChatAgentState) -> dict[str, Any]:
        last = state["tool_history"][-1]
        if last.status == "success":
            should_continue = (
                state.get("intent") == "explain_result"
                and last.name == "get_ip_analysis_result"
                and state["tool_call_count"] < state["max_tool_calls"]
            )
            return {
                "status": "pending" if should_continue else "success",
                "continue_tool_loop": should_continue,
            }
        if last.status == "not_found":
            return {"status": "not_found", "continue_tool_loop": False}
        return {"status": "failed", "continue_tool_loop": False}

    def route_after_evaluation(state: ChatAgentState) -> str:
        return "continue" if state.get("continue_tool_loop") else "answer"

    def compose_answer_node(state: ChatAgentState) -> dict[str, Any]:
        if state.get("request_error") and not state["tool_history"]:
            return {
                "answer": state["request_error"],
                "evidence": [],
                "status": state.get("status", "invalid_request"),
            }
        if not state["tool_history"]:
            return {"answer": "当前没有可用的工具结果。", "evidence": [], "status": "failed"}
        last = state["tool_history"][-1]
        if last.status == "not_found":
            if last.name == "get_ip_analysis_result":
                answer = (
                    f"{state.get('target_ip')} 尚无已保存的分析结果。"
                    "如需创建分析，请明确提出‘帮我分析这个 IP’。"
                )
            else:
                answer = f"未找到 {state.get('target_ip')} 的已有扫描数据。"
            return {"answer": answer, "evidence": [], "status": "not_found"}
        if last.status in {"failed", "denied"}:
            return {
                "answer": last.message or "工具执行失败。",
                "evidence": [],
                "status": "failed",
            }
        answer, evidence = _compose_success_answer(state)
        return {"answer": answer, "evidence": evidence, "status": "success"}

    graph = StateGraph(ChatAgentState)
    graph.add_node("understand_question", understand_question_node)
    graph.add_node("validate_request", validate_request_node)
    graph.add_node("reject_unsupported_request", reject_unsupported_node)
    graph.add_node("select_tool", select_tool_node)
    graph.add_node("execute_tool", execute_tool_node)
    graph.add_node("evaluate_result", evaluate_result_node)
    graph.add_node("compose_answer", compose_answer_node)
    graph.add_edge(START, "understand_question")
    graph.add_edge("understand_question", "validate_request")
    graph.add_conditional_edges(
        "validate_request",
        route_after_validation,
        {
            "unsupported": "reject_unsupported_request",
            "invalid": "compose_answer",
            "valid": "select_tool",
        },
    )
    graph.add_edge("reject_unsupported_request", END)
    graph.add_edge("select_tool", "execute_tool")
    graph.add_edge("execute_tool", "evaluate_result")
    graph.add_conditional_edges(
        "evaluate_result",
        route_after_evaluation,
        {"continue": "select_tool", "answer": "compose_answer"},
    )
    graph.add_edge("compose_answer", END)
    return graph.compile()
