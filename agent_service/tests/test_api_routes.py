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


class FakeOrchestrator:
    async def execute(self, ip: str, *, scan_round: int | None, save_result: bool):
        assert ip == "192.0.2.10"
        assert scan_round == 1
        assert save_result is True
        return SingleIPExecution(10, 11, False, make_result())


def test_single_ip_route_returns_standard_result() -> None:
    router = create_single_ip_router(FakeOrchestrator())
    route = next(route for route in router.routes if route.path == "/analysis/ip")
    assert "POST" in route.methods
    assert route.response_model is not None


def test_request_schema_accepts_ipv4_and_defaults_save() -> None:
    request = IPAnalysisRequest.model_validate({"ip": "192.0.2.10"})
    assert str(request.ip) == "192.0.2.10"
    assert request.save_result is True


def test_single_ip_route_rejects_ipv6() -> None:
    with pytest.raises(ValueError, match="仅支持 IPv4"):
        IPAnalysisRequest.model_validate({"ip": "2001:db8::1"})
