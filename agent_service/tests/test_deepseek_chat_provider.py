import asyncio
import json

import httpx
import pytest

from agent_service.models.chat_schema import AgentEvidence, ToolCallRecord
from agent_service.providers.base import ModelProviderError
from agent_service.providers.deepseek_chat import DeepSeekNaturalLanguageProvider
from agent_service.tools.asset_tools import AssetAgentToolRegistry


def provider_with(handler):
    return DeepSeekNaturalLanguageProvider(
        "test-secret", transport=httpx.MockTransport(handler)
    )


def response(*, content=None, finish_reason="stop", tool_calls=None):
    message = {"content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return httpx.Response(
        200,
        json={"choices": [{"finish_reason": finish_reason, "message": message}]},
    )


def test_understanding_uses_json_mode_and_validates_schema():
    def handler(request):
        body = json.loads(request.content)
        assert body["response_format"] == {"type": "json_object"}
        assert body["thinking"] == {"type": "disabled"}
        assert request.headers["authorization"] == "Bearer test-secret"
        return response(content=json.dumps({
            "intent": "query_scan_data",
            "target_ip": "192.0.2.10",
            "explicit_analysis_request": False,
            "confidence": 0.93,
            "reason": "查询已有服务",
        }))

    result = asyncio.run(provider_with(handler).understand("192.0.2.10 有什么服务"))
    assert result.intent == "query_scan_data"
    assert result.target_ip == "192.0.2.10"


def test_tool_selection_only_exposes_whitelist_and_parses_one_call():
    def handler(request):
        body = json.loads(request.content)
        names = [item["function"]["name"] for item in body["tools"]]
        assert names == [definition.name for definition in AssetAgentToolRegistry.DEFINITIONS]
        assert body["tool_choice"] == "required"
        return response(
            finish_reason="tool_calls",
            tool_calls=[{
                "id": "call-1",
                "type": "function",
                "function": {
                    "name": "get_ip_scan_data",
                    "arguments": '{"ip":"192.0.2.10"}',
                },
            }],
        )

    result = asyncio.run(provider_with(handler).select_tool(
        question="有什么服务",
        intent="query_scan_data",
        target_ip="192.0.2.10",
        scan_round=None,
        used_tools=[],
        definitions=AssetAgentToolRegistry.DEFINITIONS,
    ))
    assert result.name == "get_ip_scan_data"


def test_answer_generation_receives_facts_and_returns_natural_text():
    def handler(request):
        body = json.loads(request.content)
        facts = json.loads(body["messages"][1]["content"])
        assert facts["verified_target_ip"] == "192.0.2.10"
        assert facts["tool_results"][0]["name"] == "get_ip_scan_data"
        return response(content="该 IP 发现 SSH 服务；结论仅基于已有常用端口扫描。")

    answer = asyncio.run(provider_with(handler).generate_answer(
        question="有什么服务",
        intent="query_scan_data",
        target_ip="192.0.2.10",
        tool_history=[ToolCallRecord(
            sequence=1,
            name="get_ip_scan_data",
            status="success",
            result_data={"found": True},
        )],
        evidence=[AgentEvidence(source="service_fingerprint", detail="SSH")],
        limitations=["回答仅基于已有扫描数据"],
        template_answer="发现 SSH 服务。",
    ))
    assert "SSH" in answer


@pytest.mark.parametrize("status", [401, 429, 500])
def test_http_errors_are_sanitized(status):
    provider = provider_with(lambda _: httpx.Response(status, text="test-secret"))
    with pytest.raises(ModelProviderError, match=f"HTTP {status}") as error:
        asyncio.run(provider.understand("192.0.2.10 有什么服务"))
    assert "test-secret" not in str(error.value)


def test_invalid_tool_arguments_and_missing_key_are_rejected():
    provider = provider_with(lambda _: response(
        finish_reason="tool_calls",
        tool_calls=[{"function": {
            "name": "get_ip_scan_data", "arguments": "not-json"
        }}],
    ))
    with pytest.raises(ModelProviderError, match="工具调用"):
        asyncio.run(provider.select_tool(
            question="服务", intent="query_scan_data", target_ip="192.0.2.10",
            scan_round=None, used_tools=[], definitions=AssetAgentToolRegistry.DEFINITIONS,
        ))
    with pytest.raises(ValueError, match="DEEPSEEK_API_KEY"):
        DeepSeekNaturalLanguageProvider.from_env({})
