"""自然语言资产分析 Agent 的第一版 LangGraph 工作流。"""

from __future__ import annotations

from ipaddress import ip_address
from time import perf_counter
from typing import Any

from pydantic import ValidationError

from agent_service.models.chat_schema import (
    AgentChatResponse,
    AgentEvidence,
    PriorityAsset,
    AgentWorkflowStep,
    QuestionUnderstanding,
    ToolCallRecord,
    ToolUseSummary,
)
from agent_service.providers.base import ModelProviderError
from agent_service.services.chat_ai import AgentAnswerProvider, AgentToolSelectionProvider
from agent_service.tools.asset_tools import (
    AgentToolPermissionError,
    AssetAgentToolRegistry,
    UnknownAgentToolError,
)

from .chat_agent_state import ChatAgentState
from .chat_understanding import (
    ChatRequestValidator,
    QuestionUnderstandingProvider,
    apply_conversation_context,
)


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


_RISK_PRIORITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _batch_priority_assets(report: dict[str, Any]) -> list[PriorityAsset]:
    """根据批量报告的已验证字段生成可解释、可重复的处置顺序。"""

    services_by_ip: dict[str, set[str]] = {}
    for item in report.get("ports", []):
        label = (
            f"{item.get('port')}/{item.get('transport_protocol', 'tcp')} "
            f"{item.get('service_type', 'unknown')}"
        )
        for ip in item.get("ips", []):
            services_by_ip.setdefault(ip, set()).add(label)

    products_by_ip: dict[str, set[str]] = {}
    for item in report.get("products", []):
        label = str(item.get("product") or "未知产品")
        if item.get("version"):
            label += f" {item['version']}"
        for ip in item.get("ips", []):
            products_by_ip.setdefault(ip, set()).add(label)

    items = sorted(
        report.get("attention_items", []),
        key=lambda item: (
            -_RISK_PRIORITY.get(str(item.get("risk_level")), 0),
            -int(item.get("risk_count", 0)),
            int(ip_address(str(item.get("ip")))),
        ),
    )
    priorities: list[PriorityAsset] = []
    for rank, item in enumerate(items, start=1):
        ip = str(item.get("ip"))
        risk_titles = [str(title) for title in item.get("risk_titles", [])]
        risk_level = str(item.get("risk_level"))
        risk_count = int(item.get("risk_count", 0))
        reasons = [f"资产整体风险等级为 {risk_level}", f"记录 {risk_count} 条疑似风险"]
        if risk_titles:
            reasons.append("重点风险：" + "、".join(risk_titles[:3]))
        priorities.append(
            PriorityAsset(
                rank=rank,
                ip=ip,
                scan_round=item.get("scan_round"),
                risk_level=risk_level,
                risk_count=risk_count,
                risk_titles=risk_titles,
                exposed_services=sorted(services_by_ip.get(ip, set()))[:10],
                products=sorted(products_by_ip.get(ip, set()))[:10],
                reasons=reasons,
            )
        )
    return priorities


def _compose_success_answer(
    state: ChatAgentState,
) -> tuple[str, list[AgentEvidence], list[PriorityAsset]]:
    ip = state.get("target_ip") or "目标 IP"
    intent = state.get("intent")
    analysis_data = _latest_success_data(state, "get_ip_analysis_result")
    create_data = _latest_success_data(state, "create_ip_analysis")
    scan_data = _latest_success_data(state, "get_ip_scan_data")
    comparison_data = _latest_success_data(state, "compare_ip_scan_rounds")
    batch_report_data = _latest_success_data(state, "get_batch_report")

    if batch_report_data is not None:
        report = batch_report_data.get("report", {})
        overview = report.get("overview", {})
        priority_assets = _batch_priority_assets(report)
        answer = (
            f"批量任务 {batch_report_data.get('task_id')} 的统计报告包含 "
            f"{overview.get('analyzed_assets', 0)} 个有效资产、"
            f"{overview.get('total_services', 0)} 个服务和 "
            f"{overview.get('total_risks', 0)} 条疑似风险；"
            f"失败资产 {overview.get('failed_assets', 0)} 个。"
        )
        evidence = [AgentEvidence(source="batch_report", detail=answer)]
        if priority_assets:
            first = priority_assets[0]
            reason = "；".join(first.reasons)
            answer += f" 建议优先核查 {first.ip}：{reason}。"
            evidence.extend(
                AgentEvidence(
                    source="batch_priority",
                    detail=f"优先级 {item.rank}：{item.ip}；" + "；".join(item.reasons),
                )
                for item in priority_assets[:5]
            )
        else:
            answer += " 报告没有标记需要重点关注的资产，现有事实不足以确定处置优先级。"
        if overview.get("failed_assets", 0) or overview.get("missing_results", 0):
            answer += " 失败或缺少分析结果的资产尚未完成风险判断，也应优先补齐数据。"
        return answer, evidence, priority_assets

    if comparison_data is not None:
        comparison = comparison_data.get("comparison", {})
        summary = comparison.get("summary", {})
        risk = comparison.get("risk_changes", {})
        answer = (
            f"{ip} 从扫描批次 {comparison.get('from_scan_round')} 到 "
            f"{comparison.get('to_scan_round')} 的状态为 {comparison.get('change_status')}："
            f"新增服务 {summary.get('added_service_count', 0)} 个，"
            f"消失服务 {summary.get('removed_service_count', 0)} 个，"
            f"产品变化 {summary.get('product_change_count', 0)} 项。"
        )
        if risk.get("available"):
            answer += f" 风险变化方向为 {risk.get('direction')}。"
        else:
            answer += " 至少一个批次没有保存的分析结果，暂不能比较风险。"
        evidence = [
            AgentEvidence(
                source="scan_round_comparison",
                detail=answer,
            )
        ]
        return answer, evidence, []

    if create_data is not None:
        result = create_data.get("result", {})
        summary = result.get("summary", {})
        action = "复用了已有分析结果" if create_data.get("reused") else "已完成新的分析任务"
        answer = f"{ip} {action}。{summary.get('description') or '已生成标准分析结果。'}"
        return answer, _analysis_evidence(result), []

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
        return answer, evidence, []

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
        return answer, _scan_evidence(asset), []

    return "工具已执行，但没有返回可展示的数据。", [], []


def chat_response_from_state(state: ChatAgentState) -> AgentChatResponse:
    """把完成的图状态转换为稳定 API 契约。"""

    intent = state.get("intent") or "missing_target"
    return AgentChatResponse(
        answer=state.get("answer") or "当前没有可用回答。",
        intent=intent,
        target_ip=state.get("target_ip"),
        from_scan_round=state.get("from_scan_round"),
        to_scan_round=state.get("to_scan_round"),
        task_id=state.get("task_id"),
        conversation_id=state.get("conversation_id", "stateless"),
        context_reused=state.get("context_reused", False),
        status=state.get("status", "failed"),
        model_provider=state.get("model_provider", "rules"),
        fallback_used=state.get("fallback_used", False),
        workflow_trace=state.get("workflow_trace", []),
        tools_used=[
            ToolUseSummary(name=record.name, status=record.status, message=record.message)
            for record in state.get("tool_history", [])
        ],
        evidence=state.get("evidence", []),
        priority_assets=state.get("priority_assets", []),
        limitations=state.get("limitations", []),
    )


def build_chat_agent_graph(
    *,
    understanding_provider: QuestionUnderstandingProvider,
    fallback_understanding_provider: QuestionUnderstandingProvider | None = None,
    tool_selection_provider: AgentToolSelectionProvider | None = None,
    answer_provider: AgentAnswerProvider | None = None,
    request_validator: ChatRequestValidator,
    tool_registry: AssetAgentToolRegistry,
    checkpointer: Any | None = None,
) -> Any:
    """构建问题理解、验证、工具调用和模板回答的 LangGraph。"""

    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("运行自然语言 Agent 前请安装 langgraph") from exc

    def fallback_update(state: ChatAgentState, step: str) -> dict[str, Any]:
        return {
            "fallback_used": True,
            "fallback_steps": [*state.get("fallback_steps", []), step],
        }

    def with_context(state: ChatAgentState, understanding: QuestionUnderstanding):
        resolved = apply_conversation_context(
            state["question"],
            understanding,
            context_intent=state.get("context_intent"),
            context_target_ip=state.get("context_target_ip"),
            context_from_scan_round=state.get("context_from_scan_round"),
            context_to_scan_round=state.get("context_to_scan_round"),
            context_task_id=state.get("context_task_id"),
        )
        return resolved

    def traced(
        state: ChatAgentState,
        update: dict[str, Any],
        *,
        node: str,
        status: str,
        detail: str,
        started: float,
        tool_name: str | None = None,
        fallback_reason: str | None = None,
    ) -> dict[str, Any]:
        trace = AgentWorkflowStep(
            sequence=len(state.get("workflow_trace", [])) + 1,
            node=node,
            status=status,
            detail=detail,
            duration_ms=round(max((perf_counter() - started) * 1000, 0), 2),
            tool_name=tool_name,
            fallback_reason=fallback_reason,
        )
        return {
            **update,
            "workflow_trace": [*state.get("workflow_trace", []), trace],
        }

    async def understand_question_node(state: ChatAgentState) -> dict[str, Any]:
        started = perf_counter()
        update: dict[str, Any] = {
            "model_provider": understanding_provider.provider_name,
        }
        fallback_reason = None
        try:
            understanding = await understanding_provider.understand(state["question"])
        except ModelProviderError:
            if fallback_understanding_provider is None:
                raise
            understanding = await fallback_understanding_provider.understand(
                state["question"]
            )
            update.update(fallback_update(state, "understand_question"))
            fallback_reason = "模型问题理解失败，已改用规则理解器"
        understanding = with_context(state, understanding)
        return traced(
            state,
            {
                **update,
                "understanding": understanding,
                "intent": understanding.intent,
                "context_reused": understanding.uses_conversation_context,
                "target_ip": understanding.target_ip,
                "explicit_analysis_request": understanding.explicit_analysis_request,
                "from_scan_round": understanding.from_scan_round,
                "to_scan_round": understanding.to_scan_round,
                "task_id": understanding.task_id,
            },
            node="understand_question",
            status="fallback" if fallback_reason else "success",
            detail=f"识别意图：{understanding.intent}",
            started=started,
            fallback_reason=fallback_reason,
        )

    async def validate_request_node(state: ChatAgentState) -> dict[str, Any]:
        started = perf_counter()
        understanding = state.get("understanding")
        if understanding is None:  # pragma: no cover - 固定边保证
            return traced(
                state,
                {"request_error": "问题理解结果缺失", "status": "failed"},
                node="validate_request",
                status="failed",
                detail="问题理解结果缺失",
                started=started,
            )
        validation = request_validator.validate(state["question"], understanding)
        if validation.valid:
            return traced(
                state,
                {"request_error": None, "status": "pending"},
                node="validate_request",
                status="success",
                detail="IP、权限和请求范围校验通过",
                started=started,
            )
        if fallback_understanding_provider is not None and not state.get("fallback_used"):
            fallback = await fallback_understanding_provider.understand(state["question"])
            fallback = with_context(state, fallback)
            fallback_validation = request_validator.validate(state["question"], fallback)
            update = {
                **fallback_update(state, "validate_request"),
                "understanding": fallback,
                "intent": fallback.intent,
                "context_reused": fallback.uses_conversation_context,
                "target_ip": fallback.target_ip,
                "explicit_analysis_request": fallback.explicit_analysis_request,
                "from_scan_round": fallback.from_scan_round,
                "to_scan_round": fallback.to_scan_round,
                "task_id": fallback.task_id,
            }
            if fallback_validation.valid:
                return traced(
                    state,
                    {**update, "request_error": None, "status": "pending"},
                    node="validate_request",
                    status="fallback",
                    detail="规则理解结果通过程序校验",
                    started=started,
                    fallback_reason="模型理解结果未通过程序安全校验",
                )
            return traced(
                state,
                {
                    **update,
                    "request_error": fallback_validation.error,
                    "status": fallback_validation.status,
                },
                node="validate_request",
                status="fallback",
                detail=fallback_validation.error or "请求未通过校验",
                started=started,
                fallback_reason="模型理解结果未通过程序安全校验",
            )
        return traced(
            state,
            {"request_error": validation.error, "status": validation.status},
            node="validate_request",
            status="denied" if validation.status == "unsupported" else "failed",
            detail=validation.error or "请求未通过校验",
            started=started,
        )

    def route_after_validation(state: ChatAgentState) -> str:
        if state.get("status") == "unsupported":
            return "unsupported"
        if state.get("request_error"):
            return "invalid"
        return "valid"

    def reject_unsupported_node(state: ChatAgentState) -> dict[str, Any]:
        started = perf_counter()
        return traced(
            state,
            {
                "answer": state.get("request_error")
                or "该请求不在只读资产分析能力范围内。",
                "status": "unsupported",
                "evidence": [],
            },
            node="reject_unsupported_request",
            status="denied",
            detail="已拒绝超出只读分析范围的请求",
            started=started,
        )

    def deterministic_tool(state: ChatAgentState) -> str:
        intent = state.get("intent")
        used_tools = {record.name for record in state["tool_history"]}
        if intent == "create_analysis":
            return "create_ip_analysis"
        if intent == "compare_scan_rounds":
            return "compare_ip_scan_rounds"
        if intent == "query_batch_report":
            return "get_batch_report"
        if intent == "explain_result" and "get_ip_analysis_result" in used_tools:
            return "get_ip_scan_data"
        if intent in {"query_analysis_result", "explain_result"}:
            return "get_ip_analysis_result"
        return "get_ip_scan_data"

    def canonical_arguments(state: ChatAgentState, selected: str) -> dict[str, Any]:
        if selected == "compare_ip_scan_rounds":
            return {
                "ip": state["target_ip"],
                "from_scan_round": state.get("from_scan_round"),
                "to_scan_round": state.get("to_scan_round"),
            }
        if selected == "get_batch_report":
            return {"task_id": state.get("task_id")}
        arguments: dict[str, Any] = {
            "ip": state["target_ip"],
            "scan_round": state.get("scan_round"),
        }
        if selected == "create_ip_analysis":
            arguments["save_result"] = True
        return arguments

    async def select_tool_node(state: ChatAgentState) -> dict[str, Any]:
        started = perf_counter()
        if state["tool_call_count"] >= state["max_tool_calls"]:
            return traced(
                state,
                {
                    "selected_tool": None,
                    "request_error": "已达到最大工具调用次数",
                    "continue_tool_loop": False,
                },
                node="select_tool",
                status="denied",
                detail="已达到最大工具调用次数",
                started=started,
            )
        used_tools = {record.name for record in state["tool_history"]}
        update: dict[str, Any] = {}
        selected = deterministic_tool(state)
        fallback_reason = None
        if tool_selection_provider is not None and not state.get("fallback_used"):
            try:
                choice = await tool_selection_provider.select_tool(
                    question=state["question"],
                    intent=state["intent"],
                    target_ip=state["target_ip"],
                    scan_round=state.get("scan_round"),
                    used_tools=sorted(used_tools),
                    definitions=tool_registry.definitions,
                )
                if choice.name in used_tools:
                    raise ValueError("模型选择了已使用的工具")
                if choice.name == "create_ip_analysis" and (
                    state.get("intent") != "create_analysis"
                    or not state.get("explicit_analysis_request")
                ):
                    raise ValueError("模型尝试在未授权时创建分析任务")
                model_ip = choice.arguments.get("ip")
                if model_ip is not None and model_ip != state.get("target_ip"):
                    raise ValueError("模型工具参数中的 IP 与已校验 IP 不一致")
                if choice.name == "compare_ip_scan_rounds" and (
                    choice.arguments.get("from_scan_round")
                    != state.get("from_scan_round")
                    or choice.arguments.get("to_scan_round")
                    != state.get("to_scan_round")
                ):
                    raise ValueError("模型工具参数中的扫描批次与已校验批次不一致")
                if choice.name == "get_batch_report" and (
                    choice.arguments.get("task_id") != state.get("task_id")
                ):
                    raise ValueError("模型工具参数中的任务 ID 与已校验任务不一致")
                selected = choice.name
            except (ModelProviderError, ValidationError, ValueError):
                selected = deterministic_tool(state)
                update.update(fallback_update(state, "select_tool"))
                fallback_reason = "模型工具决策失败或越权，已使用程序规则"
        return traced(
            state,
            {
                **update,
                "selected_tool": selected,
                "tool_arguments": canonical_arguments(state, selected),
                "continue_tool_loop": False,
            },
            node="select_tool",
            status="fallback" if fallback_reason else "success",
            detail=f"选择白名单工具：{selected}",
            started=started,
            tool_name=selected,
            fallback_reason=fallback_reason,
        )

    async def execute_tool_node(state: ChatAgentState) -> dict[str, Any]:
        started = perf_counter()
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
            return traced(
                state,
                {
                    "tool_history": [*state["tool_history"], record],
                    "tool_call_count": sequence,
                },
                node="execute_tool",
                status="failed",
                detail="没有可执行的工具",
                started=started,
                tool_name=record.name,
            )
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
        trace_status = (
            "success"
            if record.status == "success"
            else "not_found"
            if record.status == "not_found"
            else "denied"
            if record.status == "denied"
            else "failed"
        )
        return traced(
            state,
            {
                "tool_history": [*state["tool_history"], record],
                "tool_call_count": sequence,
            },
            node="execute_tool",
            status=trace_status,
            detail=record.message or f"已执行 {record.name}",
            started=started,
            tool_name=record.name,
        )

    def evaluate_result_node(state: ChatAgentState) -> dict[str, Any]:
        started = perf_counter()
        last = state["tool_history"][-1]
        if last.status == "success":
            used_tools = {record.name for record in state["tool_history"]}
            should_continue = (
                state.get("intent") == "explain_result"
                and not {"get_ip_analysis_result", "get_ip_scan_data"}.issubset(used_tools)
                and state["tool_call_count"] < state["max_tool_calls"]
            )
            return traced(
                state,
                {
                    "status": "pending" if should_continue else "success",
                    "continue_tool_loop": should_continue,
                },
                node="evaluate_result",
                status="success",
                detail=("证据不足，继续选择工具" if should_continue else "工具结果足以回答"),
                started=started,
                tool_name=last.name,
            )
        if last.status == "not_found":
            return traced(
                state,
                {"status": "not_found", "continue_tool_loop": False},
                node="evaluate_result",
                status="not_found",
                detail="工具未找到对应数据",
                started=started,
                tool_name=last.name,
            )
        return traced(
            state,
            {"status": "failed", "continue_tool_loop": False},
            node="evaluate_result",
            status="failed",
            detail="工具结果不可用于回答",
            started=started,
            tool_name=last.name,
        )

    def route_after_evaluation(state: ChatAgentState) -> str:
        return "continue" if state.get("continue_tool_loop") else "answer"

    async def compose_answer_node(state: ChatAgentState) -> dict[str, Any]:
        started = perf_counter()
        if state.get("request_error") and not state["tool_history"]:
            return traced(
                state,
                {
                    "answer": state["request_error"],
                    "evidence": [],
                    "status": state.get("status", "invalid_request"),
                },
                node="compose_answer",
                status="failed",
                detail="根据请求校验结果生成说明",
                started=started,
            )
        if not state["tool_history"]:
            return traced(
                state,
                {"answer": "当前没有可用的工具结果。", "evidence": [], "status": "failed"},
                node="compose_answer",
                status="failed",
                detail="没有可用于回答的工具结果",
                started=started,
            )
        last = state["tool_history"][-1]
        if last.status == "not_found":
            if last.name == "get_batch_report":
                answer = f"批量任务 {state.get('task_id')} 尚无已保存的统计报告。"
            elif last.name == "compare_ip_scan_rounds":
                answer = last.message or "指定扫描批次或资产数据不存在。"
            elif last.name == "get_ip_analysis_result":
                answer = (
                    f"{state.get('target_ip')} 尚无已保存的分析结果。"
                    "如需创建分析，请明确提出‘帮我分析这个 IP’。"
                )
            else:
                answer = f"未找到 {state.get('target_ip')} 的已有扫描数据。"
            return traced(
                state,
                {"answer": answer, "evidence": [], "status": "not_found"},
                node="compose_answer",
                status="not_found",
                detail="生成未找到数据的说明",
                started=started,
                tool_name=last.name,
            )
        if last.status in {"failed", "denied"}:
            return traced(
                state,
                {
                    "answer": last.message or "工具执行失败。",
                    "evidence": [],
                    "status": "failed",
                },
                node="compose_answer",
                status="failed",
                detail="根据工具错误生成说明",
                started=started,
                tool_name=last.name,
            )
        answer, evidence, priority_assets = _compose_success_answer(state)
        update: dict[str, Any] = {}
        fallback_reason = None
        if answer_provider is not None and not state.get("fallback_used"):
            try:
                answer = await answer_provider.generate_answer(
                    question=state["question"],
                    intent=state["intent"],
                    target_ip=state["target_ip"],
                    tool_history=state["tool_history"],
                    evidence=evidence,
                    limitations=state["limitations"],
                    template_answer=answer,
                )
            except ModelProviderError:
                update.update(fallback_update(state, "compose_answer"))
                fallback_reason = "模型回答生成失败，已使用程序模板"
        return traced(
            state,
            {
                **update,
                "answer": answer,
                "evidence": evidence,
                "priority_assets": priority_assets,
                "status": "success",
            },
            node="compose_answer",
            status="fallback" if fallback_reason else "success",
            detail=f"生成回答并引用 {len(evidence)} 条证据",
            started=started,
            fallback_reason=fallback_reason,
        )

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
    return graph.compile(checkpointer=checkpointer)
