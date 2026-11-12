import inspect

import pytest

from agent_service.services.chat_agent_graph import (
    build_chat_agent_graph,
    chat_response_from_state,
)
from agent_service.services.chat_agent_state import initial_chat_state
from agent_service.services.chat_understanding import (
    ChatRequestValidator,
    RuleBasedQuestionUnderstandingProvider,
)
from agent_service.tools.asset_tools import AgentToolResult


class FakeToolRegistry:
    def __init__(self, *, analysis_found: bool = True, scan_found: bool = True):
        self.analysis_found = analysis_found
        self.scan_found = scan_found
        self.calls: list[tuple[str, dict, bool]] = []

    async def execute(self, name, arguments, *, allow_task_creation=False):
        self.calls.append((name, arguments, allow_task_creation))
        ip = arguments["ip"]
        if name == "get_ip_scan_data":
            if not self.scan_found:
                return AgentToolResult(
                    tool_name=name,
                    status="not_found",
                    message="未找到扫描数据",
                    data={"found": False, "ip": ip},
                )
            return AgentToolResult(
                tool_name=name,
                status="success",
                message="已读取扫描数据",
                data={
                    "found": True,
                    "asset": {
                        "ip": ip,
                        "scan_round": arguments.get("scan_round") or 3,
                        "services": [
                            {
                                "port": 22,
                                "transport_protocol": "tcp",
                                "service_type": "ssh",
                                "banner": "SSH-2.0-OpenSSH_9.2",
                                "confidence": 0.9,
                                "product": {
                                    "normalized_product_name": "OpenSSH",
                                    "normalized_version": "9.2",
                                },
                            }
                        ],
                    },
                },
            )
        result = {
            "analysis_id": "analysis-chat-test",
            "ip": ip,
            "scan_round": arguments.get("scan_round") or 3,
            "summary": {"description": "发现 SSH 服务，当前风险较低。"},
            "risks": [],
            "evidence": [
                {
                    "source": "ssh.banner",
                    "detail": "SSH-2.0-OpenSSH_9.2",
                    "confidence": 0.9,
                }
            ],
        }
        if name == "get_ip_analysis_result":
            if not self.analysis_found:
                return AgentToolResult(
                    tool_name=name,
                    status="not_found",
                    message="没有保存的分析结果",
                    data={"found": False, "ip": ip},
                )
            return AgentToolResult(
                tool_name=name,
                status="success",
                message="已读取分析结果",
                data={"found": True, "result": result},
            )
        assert name == "create_ip_analysis"
        assert allow_task_creation is True
        return AgentToolResult(
            tool_name=name,
            status="success",
            message="已完成新的分析任务",
            data={
                "found": True,
                "task_id": 10,
                "task_item_id": 11,
                "reused": False,
                "result": result,
            },
        )


def make_graph(registry: FakeToolRegistry):
    return build_chat_agent_graph(
        understanding_provider=RuleBasedQuestionUnderstandingProvider(),
        request_validator=ChatRequestValidator(),
        tool_registry=registry,
    )


def test_graph_contains_planned_nodes_and_async_boundaries() -> None:
    graph = make_graph(FakeToolRegistry()).get_graph()

    assert set(graph.nodes) == {
        "__start__",
        "understand_question",
        "validate_request",
        "reject_unsupported_request",
        "select_tool",
        "execute_tool",
        "evaluate_result",
        "compose_answer",
        "__end__",
    }
    assert inspect.iscoroutinefunction(graph.nodes["understand_question"].data.afunc)
    assert inspect.iscoroutinefunction(graph.nodes["execute_tool"].data.afunc)


@pytest.mark.asyncio
async def test_scan_question_selects_scan_tool_and_returns_evidence() -> None:
    registry = FakeToolRegistry()

    state = await make_graph(registry).ainvoke(
        initial_chat_state("192.0.2.10 开放了哪些服务？")
    )
    response = chat_response_from_state(state)

    assert response.status == "success"
    assert response.intent == "query_scan_data"
    assert "22/tcp ssh" in response.answer
    assert response.evidence[0].product == "OpenSSH"
    assert [call[0] for call in registry.calls] == ["get_ip_scan_data"]


@pytest.mark.asyncio
async def test_analysis_query_reads_saved_result_once() -> None:
    registry = FakeToolRegistry()

    state = await make_graph(registry).ainvoke(
        initial_chat_state("192.0.2.10 有哪些风险？", scan_round=3)
    )
    response = chat_response_from_state(state)

    assert response.status == "success"
    assert "风险较低" in response.answer
    assert [call[0] for call in registry.calls] == ["get_ip_analysis_result"]


@pytest.mark.asyncio
async def test_explanation_uses_two_tools_and_stops_at_limit() -> None:
    registry = FakeToolRegistry()

    state = await make_graph(registry).ainvoke(
        initial_chat_state("为什么 192.0.2.10 被判断为低风险？")
    )
    response = chat_response_from_state(state)

    assert response.status == "success"
    assert [call[0] for call in registry.calls] == [
        "get_ip_analysis_result",
        "get_ip_scan_data",
    ]
    assert state["tool_call_count"] == state["max_tool_calls"] == 2
    assert len(response.evidence) == 2


@pytest.mark.asyncio
async def test_explicit_analysis_request_is_the_only_creation_path() -> None:
    registry = FakeToolRegistry()

    state = await make_graph(registry).ainvoke(
        initial_chat_state("帮我分析 192.0.2.10")
    )
    response = chat_response_from_state(state)

    assert response.status == "success"
    assert response.intent == "create_analysis"
    assert registry.calls[0][0] == "create_ip_analysis"
    assert registry.calls[0][2] is True
    assert "新的分析任务" in response.answer


@pytest.mark.asyncio
async def test_missing_ip_and_prohibited_request_do_not_call_tools() -> None:
    registry = FakeToolRegistry()

    missing = await make_graph(registry).ainvoke(
        initial_chat_state("这个 IP 有哪些服务？")
    )
    prohibited = await make_graph(registry).ainvoke(
        initial_chat_state("帮我扫描 192.0.2.10")
    )

    assert missing["status"] == "invalid_request"
    assert "提供" in missing["answer"]
    assert prohibited["status"] == "unsupported"
    assert "只能分析已有扫描数据" in prohibited["answer"]
    assert registry.calls == []


@pytest.mark.asyncio
async def test_missing_analysis_does_not_silently_create_task() -> None:
    registry = FakeToolRegistry(analysis_found=False)

    state = await make_graph(registry).ainvoke(
        initial_chat_state("192.0.2.10 有哪些风险？")
    )
    response = chat_response_from_state(state)

    assert response.status == "not_found"
    assert "明确提出" in response.answer
    assert [call[0] for call in registry.calls] == ["get_ip_analysis_result"]
    assert all(call[0] != "create_ip_analysis" for call in registry.calls)
