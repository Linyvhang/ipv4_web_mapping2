import inspect

import pytest
from pydantic import ValidationError

from agent_service.models.analysis_schema import AnalysisResult
from agent_service.providers.base import ModelInfo, ModelProvider, ModelProviderError
from agent_service.providers.mock import MockModelProvider


def valid_result_payload() -> dict:
    return {
        "analysis_id": "analysis-mock-001",
        "ip": "192.0.2.10",
        "scan_round": 1,
        "scan_time": "2026-10-30T00:00:00Z",
        "summary": {
            "primary_asset_type": "Web服务器",
            "risk_level": "info",
            "description": "Mock 分析结果",
            "confidence": 0.5,
        },
        "metadata": {
            "model_provider": "mock",
            "model_name": "mock-model",
            "prompt_version": "1.0",
        },
    }


def test_provider_protocol_defines_async_structured_output() -> None:
    assert isinstance(ModelProvider.info, property)
    assert inspect.iscoroutinefunction(ModelProvider.generate_structured)


def test_mock_provider_returns_validated_result_and_records_prompt() -> None:
    provider = MockModelProvider(
        valid_result_payload(),
        provider="test",
        model_name="test-model",
    )

    result = provider.build_structured("分析 192.0.2.10", AnalysisResult)

    assert isinstance(result, AnalysisResult)
    assert result.ip == "192.0.2.10"
    assert provider.info == ModelInfo("test", "test-model", "1.0")
    assert provider.calls == ["分析 192.0.2.10"]


def test_mock_provider_factory_can_build_dynamic_results() -> None:
    def factory(prompt: str, output_model: type[AnalysisResult]):
        data = valid_result_payload()
        data["analysis_id"] = "analysis-from-factory"
        return data

    provider = MockModelProvider(response_factory=factory)
    result = provider.build_structured("动态分析", AnalysisResult)

    assert result.analysis_id == "analysis-from-factory"


def test_mock_provider_rejects_invalid_output() -> None:
    provider = MockModelProvider({"ip": "not-an-ip"})

    with pytest.raises(ModelProviderError, match="cannot be validated"):
        provider.build_structured("无效结果", AnalysisResult)


def test_mock_provider_rejects_two_response_sources() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        MockModelProvider({}, response_factory=lambda _prompt, _model: {})

