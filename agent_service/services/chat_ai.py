"""自然语言 Agent 的模型能力接口。"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from agent_service.models.chat_schema import (
    AgentEvidence,
    AgentIntent,
    AgentToolSelection,
    ToolCallRecord,
)
from agent_service.services.chat_understanding import QuestionUnderstandingProvider
if TYPE_CHECKING:
    from agent_service.tools.asset_tools import AgentToolDefinition


class AgentToolSelectionProvider(Protocol):
    """从白名单定义中选择一个工具。"""

    @property
    def provider_name(self) -> str:
        ...

    async def select_tool(
        self,
        *,
        question: str,
        intent: AgentIntent,
        target_ip: str,
        scan_round: int | None,
        used_tools: list[str],
        definitions: tuple["AgentToolDefinition", ...],
    ) -> AgentToolSelection:
        ...


class AgentAnswerProvider(Protocol):
    """仅根据已执行工具的事实生成自然语言回答。"""

    @property
    def provider_name(self) -> str:
        ...

    async def generate_answer(
        self,
        *,
        question: str,
        intent: AgentIntent,
        target_ip: str,
        tool_history: list[ToolCallRecord],
        evidence: list[AgentEvidence],
        limitations: list[str],
        template_answer: str,
    ) -> str:
        ...


class NaturalLanguageAgentProvider(
    QuestionUnderstandingProvider,
    AgentToolSelectionProvider,
    AgentAnswerProvider,
    Protocol,
):
    """完整自然语言 Provider：理解、工具选择和事实回答。"""
