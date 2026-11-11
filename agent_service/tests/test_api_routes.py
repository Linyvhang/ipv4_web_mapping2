import json

import pytest

from agent_service.api import IPAnalysisRequest, create_single_ip_router
from agent_service.models.analysis_schema import AnalysisResult
from agent_service.services.task_orchestrator import SingleIPExecution


def make_result() -> AnalysisResult:
    return AnalysisResult.model_validate(
        {
            "analysis_id": "api-001",
            "ip": "192.0.2.10",
            "scan_round": 1,
            "scan_time": "2026-10-30T00:00:00Z",
            "summary": {
                "risk_level": "info",
                "description": "API 测试结果",
                "confidence": 0.8,
            },
            "metadata": {
                "model_provider": "mock",
                "model_name": "mock-model",
                "prompt_version": "1.0",
            },
        }
    )


class FakeGraph:
    async def ainvoke(self, state):
        assert state == {
            "ip": "192.0.2.10",
            "scan_round": 1,
            "save_result": True,
            "retry_count": 0,
            "max_retries": 1,
            "fallback_used": False,
        }
        return {
            **state,
            "execution": SingleIPExecution(10, 11, False, make_result()),
        }

    async def astream(self, state, *, stream_mode: str):
        assert stream_mode == "updates"
        yield {"load_asset": {"asset": object()}}
        yield {
            "persist_result": {
                "execution": SingleIPExecution(10, 11, False, make_result())
            }
        }


def test_single_ip_route_returns_standard_result() -> None:
    router = create_single_ip_router(FakeGraph())
    route = next(route for route in router.routes if route.path == "/analysis/ip")
    assert "POST" in route.methods
    assert route.response_model is not None


@pytest.mark.asyncio
async def test_single_ip_route_executes_langgraph() -> None:
    router = create_single_ip_router(FakeGraph())
    route = next(route for route in router.routes if route.path == "/analysis/ip")

    response = await route.endpoint(
        IPAnalysisRequest.model_validate(
            {"ip": "192.0.2.10", "scan_round": 1, "save_result": True}
        )
    )

    assert response.task_id == 10
    assert response.result["analysis_id"] == "api-001"


@pytest.mark.asyncio
async def test_stream_route_emits_node_progress_and_result() -> None:
    router = create_single_ip_router(FakeGraph())
    route = next(
        route for route in router.routes if route.path == "/analysis/ip/stream"
    )

    response = await route.endpoint(
        IPAnalysisRequest.model_validate({"ip": "192.0.2.10"})
    )
    chunks = []
    async for chunk in response.body_iterator:
        chunks.append(chunk.decode() if isinstance(chunk, bytes) else chunk)
    events = [
        json.loads(line)
        for line in "".join(chunks).splitlines()
        if line.strip()
    ]

    assert response.media_type == "application/x-ndjson"
    assert events[0]["type"] == "start"
    assert events[1]["node"] == "load_asset"
    assert events[-1]["type"] == "result"
    assert events[-1]["data"]["result"]["analysis_id"] == "api-001"


def test_request_schema_accepts_ipv4_and_defaults_save() -> None:
    request = IPAnalysisRequest.model_validate({"ip": "192.0.2.10"})
    assert str(request.ip) == "192.0.2.10"
    assert request.save_result is True


def test_single_ip_route_rejects_ipv6() -> None:
    with pytest.raises(ValueError, match="仅支持 IPv4"):
        IPAnalysisRequest.model_validate({"ip": "2001:db8::1"})
