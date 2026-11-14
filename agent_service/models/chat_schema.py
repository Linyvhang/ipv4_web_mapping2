"""自然语言资产分析 Agent 的输入、决策和输出 Schema。"""

from __future__ import annotations

from ipaddress import IPv4Address, ip_address
from typing import Any, Literal

from pydantic import Field, field_validator

from .analysis_schema import Confidence, SchemaModel


AgentIntent = Literal[
    "query_scan_data",
    "query_analysis_result",
    "create_analysis",
    "explain_result",
    "compare_scan_rounds",
    "query_batch_report",
    "unsupported",
    "missing_target",
]
AgentToolName = Literal[
    "get_ip_scan_data",
    "get_ip_analysis_result",
    "create_ip_analysis",
    "compare_ip_scan_rounds",
    "get_batch_report",
]
AgentChatStatus = Literal[
    "pending",
    "success",
    "not_found",
    "invalid_request",
    "unsupported",
    "failed",
]
ToolCallStatus = Literal["pending", "success", "not_found", "failed", "denied"]
RequestValidationStatus = Literal["valid", "invalid_request", "unsupported"]
WorkflowStepStatus = Literal["success", "fallback", "failed", "denied", "not_found"]


def validate_optional_ipv4(value: str | None) -> str | None:
    """验证并规范化可选 IPv4。"""

    if value is None:
        return None
    try:
        address = ip_address(value)
    except ValueError as exc:
        raise ValueError("target_ip must be a valid IPv4 address") from exc
    if not isinstance(address, IPv4Address):
        raise ValueError("target_ip must be a valid IPv4 address")
    return str(address)


class AgentChatRequest(SchemaModel):
    """自然语言 Agent 的单轮输入。"""

    question: str = Field(min_length=1, max_length=2000)
    scan_round: int | None = Field(default=None, ge=1)

    @field_validator("question")
    @classmethod
    def normalize_question(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("question must not be blank")
        return normalized


class QuestionUnderstanding(SchemaModel):
    """问题理解节点生成的结构化判断。"""

    intent: AgentIntent
    target_ip: str | None = None
    explicit_analysis_request: bool = False
    from_scan_round: int | None = Field(default=None, ge=1)
    to_scan_round: int | None = Field(default=None, ge=1)
    task_id: int | None = Field(default=None, ge=1)
    confidence: Confidence
    reason: str

    _validate_target_ip = field_validator("target_ip")(validate_optional_ipv4)


class RequestValidation(SchemaModel):
    """程序安全规则对问题理解结果的校验结论。"""

    valid: bool
    status: RequestValidationStatus
    error: str | None = None


class AgentToolSelection(SchemaModel):
    """模型只能选择白名单工具；实际参数由程序重新构造。"""

    name: AgentToolName
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolCallRecord(SchemaModel):
    """一次可审计的白名单工具调用记录。"""

    sequence: int = Field(ge=1)
    name: AgentToolName
    arguments: dict[str, Any] = Field(default_factory=dict)
    status: ToolCallStatus = "pending"
    message: str | None = None
    result_data: dict[str, Any] = Field(default_factory=dict)


class ToolUseSummary(SchemaModel):
    """API 返回给用户的精简工具轨迹。"""

    name: AgentToolName
    status: ToolCallStatus
    message: str | None = None


class AgentEvidence(SchemaModel):
    """问答中引用的结构化扫描或分析证据。"""

    source: str
    detail: str
    port: int | None = Field(default=None, ge=1, le=65535)
    service_type: str | None = None
    product: str | None = None
    version: str | None = None
    confidence: Confidence | None = None


class AgentWorkflowStep(SchemaModel):
    """一个可安全公开的 LangGraph 节点执行轨迹。"""

    sequence: int = Field(ge=1)
    node: str = Field(min_length=1, max_length=80)
    status: WorkflowStepStatus
    detail: str = Field(min_length=1, max_length=500)
    duration_ms: float = Field(ge=0)
    tool_name: AgentToolName | None = None
    fallback_reason: str | None = Field(default=None, max_length=300)


class AgentChatResponse(SchemaModel):
    """自然语言 Agent 的稳定输出契约。"""

    schema_version: Literal["1.0"] = "1.0"
    answer: str
    intent: AgentIntent
    target_ip: str | None = None
    from_scan_round: int | None = Field(default=None, ge=1)
    to_scan_round: int | None = Field(default=None, ge=1)
    task_id: int | None = Field(default=None, ge=1)
    status: AgentChatStatus
    model_provider: str = "rules"
    fallback_used: bool = False
    workflow_trace: list[AgentWorkflowStep] = Field(default_factory=list)
    tools_used: list[ToolUseSummary] = Field(default_factory=list)
    evidence: list[AgentEvidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    _validate_target_ip = field_validator("target_ip")(validate_optional_ipv4)
