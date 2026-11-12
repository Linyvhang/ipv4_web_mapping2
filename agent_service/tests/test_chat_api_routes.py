import pytest
from fastapi import HTTPException

from agent_service.api.chat_routes import create_chat_agent_router
from agent_service.models.chat_schema import AgentChatRequest
from agent_service.providers.base import ModelProviderError


class FakeChatGraph:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.states: list[dict] = []

    async def ainvoke(self, state: dict):
        self.states.append(state)
        if self.error is not None:
            raise self.error
        return {
            **state,
            "intent": "query_scan_data",
            "target_ip": "192.0.2.10",
            "answer": "该 IP 发现 SSH 服务。",
            "status": "success",
        }


def get_chat_endpoint(graph: FakeChatGraph):
    router = create_chat_agent_router(graph)
    return next(route for route in router.routes if route.path == "/agent/chat")


def test_chat_route_declares_standard_response_model() -> None:
    route = get_chat_endpoint(FakeChatGraph())

    assert "POST" in route.methods
    assert route.response_model is not None
    assert route.response_model.__name__ == "AgentChatResponse"


@pytest.mark.asyncio
async def test_chat_route_executes_graph_with_safe_initial_state() -> None:
    graph = FakeChatGraph()
    route = get_chat_endpoint(graph)

    response = await route.endpoint(
        AgentChatRequest(question="  查询 192.0.2.10 的服务  ", scan_round=3)
    )

    assert response.status == "success"
    assert response.intent == "query_scan_data"
    assert response.target_ip == "192.0.2.10"
    assert graph.states[0]["question"] == "查询 192.0.2.10 的服务"
    assert graph.states[0]["scan_round"] == 3
    assert graph.states[0]["max_tool_calls"] == 2


@pytest.mark.asyncio
async def test_chat_route_maps_model_provider_failure_to_502() -> None:
    route = get_chat_endpoint(FakeChatGraph(ModelProviderError("模型不可用")))

    with pytest.raises(HTTPException) as captured:
        await route.endpoint(AgentChatRequest(question="分析 192.0.2.10"))

    assert captured.value.status_code == 502
    assert captured.value.detail == "模型不可用"
