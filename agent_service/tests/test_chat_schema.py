import pytest
from pydantic import ValidationError

from agent_service.models.chat_schema import (
    AgentChatRequest,
    AgentChatResponse,
    AgentEvidence,
    QuestionUnderstanding,
    ToolCallRecord,
    ToolUseSummary,
)


def test_chat_request_normalizes_question_and_validates_scan_round() -> None:
    request = AgentChatRequest(question="  查询 192.0.2.10 的服务  ", scan_round=3)

    assert request.question == "查询 192.0.2.10 的服务"
    assert request.scan_round == 3

    with pytest.raises(ValidationError):
        AgentChatRequest(question="   ")
    with pytest.raises(ValidationError):
        AgentChatRequest(question="查询服务", scan_round=0)


def test_question_understanding_requires_supported_intent_and_ipv4() -> None:
    understanding = QuestionUnderstanding(
        intent="create_analysis",
        target_ip="192.0.2.10",
        explicit_analysis_request=True,
        confidence=0.9,
        reason="用户明确要求分析",
    )

    assert understanding.target_ip == "192.0.2.10"
    assert understanding.explicit_analysis_request is True

    with pytest.raises(ValidationError):
        QuestionUnderstanding(
            intent="scan_host",
            target_ip="192.0.2.10",
            confidence=1.0,
            reason="不支持的意图",
        )
    with pytest.raises(ValidationError):
        QuestionUnderstanding(
            intent="query_scan_data",
            target_ip="2001:db8::1",
            confidence=1.0,
            reason="第一版仅支持 IPv4",
        )


def test_tool_call_record_rejects_unknown_tools_and_invalid_sequence() -> None:
    record = ToolCallRecord(
        sequence=1,
        name="get_ip_scan_data",
        arguments={"ip": "192.0.2.10"},
        status="success",
        message="已读取扫描数据",
        result_data={"found": True},
    )

    assert record.name == "get_ip_scan_data"
    assert record.result_data["found"] is True

    with pytest.raises(ValidationError):
        ToolCallRecord(sequence=0, name="get_ip_scan_data")
    with pytest.raises(ValidationError):
        ToolCallRecord(sequence=1, name="run_sql")


def test_chat_response_serializes_tool_trace_and_evidence() -> None:
    response = AgentChatResponse(
        answer="该 IP 发现 SSH 服务。",
        intent="query_scan_data",
        target_ip="192.0.2.10",
        status="success",
        tools_used=[
            ToolUseSummary(
                name="get_ip_scan_data",
                status="success",
                message="已读取扫描数据",
            )
        ],
        evidence=[
            AgentEvidence(
                source="service_fingerprint",
                detail="SSH-2.0-OpenSSH_9.2",
                port=22,
                service_type="ssh",
                product="OpenSSH",
                version="9.2",
                confidence=0.9,
            )
        ],
        limitations=["回答仅基于已有扫描数据"],
    )

    payload = response.model_dump(mode="json")
    assert payload["schema_version"] == "1.0"
    assert payload["tools_used"][0]["name"] == "get_ip_scan_data"
    assert payload["evidence"][0]["port"] == 22


def test_chat_models_forbid_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        AgentChatRequest(question="查询服务", sql="SELECT 1")
