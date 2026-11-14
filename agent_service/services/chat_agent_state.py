"""自然语言 Agent 的 LangGraph State 和初始状态构造。"""

from __future__ import annotations

from typing import Any, TypedDict

from agent_service.models.chat_schema import (
    AgentChatRequest,
    AgentChatStatus,
    AgentEvidence,
    AgentIntent,
    AgentToolName,
    AgentWorkflowStep,
    QuestionUnderstanding,
    ToolCallRecord,
)


DEFAULT_CHAT_LIMITATIONS = [
    "回答仅基于已有扫描数据",
    "当前扫描只覆盖指定常用端口",
]


class ChatAgentState(TypedDict):
    """六节点自然语言 Agent 共享的原始状态。"""

    question: str
    conversation_id: str
    context_reused: bool
    context_intent: AgentIntent | None
    context_target_ip: str | None
    context_from_scan_round: int | None
    context_to_scan_round: int | None
    context_task_id: int | None
    scan_round: int | None
    intent: AgentIntent | None
    understanding: QuestionUnderstanding | None
    target_ip: str | None
    from_scan_round: int | None
    to_scan_round: int | None
    task_id: int | None
    explicit_analysis_request: bool
    request_error: str | None
    selected_tool: AgentToolName | None
    tool_arguments: dict[str, Any]
    tool_history: list[ToolCallRecord]
    tool_call_count: int
    max_tool_calls: int
    continue_tool_loop: bool
    answer: str | None
    evidence: list[AgentEvidence]
    limitations: list[str]
    status: AgentChatStatus
    model_provider: str
    fallback_used: bool
    fallback_steps: list[str]
    workflow_trace: list[AgentWorkflowStep]


def initial_chat_state(
    question: str,
    *,
    scan_round: int | None = None,
    conversation_id: str = "stateless",
    previous_context: dict[str, Any] | None = None,
) -> ChatAgentState:
    """校验用户入口参数并构造无共享可变对象的初始状态。"""

    request = AgentChatRequest(
        question=question,
        scan_round=scan_round,
        conversation_id=(None if conversation_id == "stateless" else conversation_id),
    )
    context = previous_context or {}
    return {
        "question": request.question,
        "conversation_id": conversation_id,
        "context_reused": False,
        "context_intent": context.get("intent"),
        "context_target_ip": context.get("target_ip"),
        "context_from_scan_round": context.get("from_scan_round"),
        "context_to_scan_round": context.get("to_scan_round"),
        "context_task_id": context.get("task_id"),
        "scan_round": request.scan_round,
        "intent": None,
        "understanding": None,
        "target_ip": None,
        "from_scan_round": None,
        "to_scan_round": None,
        "task_id": None,
        "explicit_analysis_request": False,
        "request_error": None,
        "selected_tool": None,
        "tool_arguments": {},
        "tool_history": [],
        "tool_call_count": 0,
        "max_tool_calls": 2,
        "continue_tool_loop": False,
        "answer": None,
        "evidence": [],
        "limitations": list(DEFAULT_CHAT_LIMITATIONS),
        "status": "pending",
        "model_provider": "rules",
        "fallback_used": False,
        "fallback_steps": [],
        "workflow_trace": [],
    }
