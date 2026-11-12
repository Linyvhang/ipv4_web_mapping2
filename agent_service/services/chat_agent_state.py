"""自然语言 Agent 的 LangGraph State 和初始状态构造。"""

from __future__ import annotations

from typing import Any, TypedDict

from agent_service.models.chat_schema import (
    AgentChatRequest,
    AgentChatStatus,
    AgentEvidence,
    AgentIntent,
    AgentToolName,
    ToolCallRecord,
)


DEFAULT_CHAT_LIMITATIONS = [
    "回答仅基于已有扫描数据",
    "当前扫描只覆盖指定常用端口",
]


class ChatAgentState(TypedDict):
    """六节点自然语言 Agent 共享的原始状态。"""

    question: str
    scan_round: int | None
    intent: AgentIntent | None
    target_ip: str | None
    explicit_analysis_request: bool
    request_error: str | None
    selected_tool: AgentToolName | None
    tool_arguments: dict[str, Any]
    tool_history: list[ToolCallRecord]
    tool_call_count: int
    max_tool_calls: int
    answer: str | None
    evidence: list[AgentEvidence]
    limitations: list[str]
    status: AgentChatStatus


def initial_chat_state(
    question: str,
    *,
    scan_round: int | None = None,
) -> ChatAgentState:
    """校验用户入口参数并构造无共享可变对象的初始状态。"""

    request = AgentChatRequest(question=question, scan_round=scan_round)
    return {
        "question": request.question,
        "scan_round": request.scan_round,
        "intent": None,
        "target_ip": None,
        "explicit_analysis_request": False,
        "request_error": None,
        "selected_tool": None,
        "tool_arguments": {},
        "tool_history": [],
        "tool_call_count": 0,
        "max_tool_calls": 2,
        "answer": None,
        "evidence": [],
        "limitations": list(DEFAULT_CHAT_LIMITATIONS),
        "status": "pending",
    }
