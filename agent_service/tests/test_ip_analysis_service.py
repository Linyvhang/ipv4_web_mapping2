from datetime import datetime

import pytest

from agent_service.models.analysis_schema import AnalysisResult
from agent_service.models.input_schema import AssetAnalysisInput, L3ServiceInput
from agent_service.providers.mock import MockModelProvider
from agent_service.services.ip_analysis import (
    SingleIPAnalysisService,
    UnsupportedAddressError,
    ipv4_to_uint32,
)


def make_asset() -> AssetAnalysisInput:
    return AssetAnalysisInput(
        ip="192.0.2.10",
        scan_round=1,
        active_host_id=7,
        alive_type=4,
        first_seen=datetime(2026, 10, 29),
        last_seen=datetime(2026, 10, 30),
        services=[
            L3ServiceInput(
                service_instance_id=12,
                active_host_id=7,
                port=443,
                transport_protocol="tcp",
                service_type="web",
                application_protocol="https",
                banner="Server: nginx/1.24.0",
                confidence=0.95,
                l2_scan_status=1,
            )
        ],
        limitations=["本次输入仅包含已有 L1/L2/L3 扫描数据"],
    )


def make_result() -> AnalysisResult:
    return AnalysisResult.model_validate(
        {
            "analysis_id": "analysis-service-001",
            "ip": "192.0.2.10",
            "scan_round": 1,
            "scan_time": "2026-10-30T00:00:00Z",
            "summary": {
                "primary_asset_type": "Web服务器",
                "risk_level": "info",
                "description": "根据现有证据完成分析",
                "confidence": 0.7,
            },
            "metadata": {
                "model_provider": "placeholder",
                "model_name": "placeholder",
                "prompt_version": "placeholder",
            },
        }
    )


class StubDataProvider:
    async def fetch_asset(self, *, ip_value: int, scan_round: int | None = None):
        return make_asset() if ip_value == ipv4_to_uint32("192.0.2.10") else None


def test_ipv4_to_uint32_and_ipv6_rejection() -> None:
    assert ipv4_to_uint32("192.0.2.10") == 0xC000020A
    with pytest.raises(UnsupportedAddressError):
        ipv4_to_uint32("2001:db8::1")


def test_build_prompt_contains_scope_and_serialized_asset() -> None:
    prompt = SingleIPAnalysisService.build_prompt(make_asset())

    assert "禁止主动扫描" in prompt
    assert "192.0.2.10" in prompt
    assert "nginx/1.24.0" in prompt
    assert "只覆盖指定常用端口" in prompt


def test_finalize_result_replaces_provider_metadata() -> None:
    provider = MockModelProvider(
        make_result(),
        provider="mock",
        model_name="mock-analysis",
        model_version="test-1",
    )
    service = SingleIPAnalysisService(
        data_provider=StubDataProvider(),
        model_provider=provider,
        prompt_version="1.2",
    )

    result = service.finalize_result(make_result(), make_asset())

    assert result.metadata.model_provider == "mock"
    assert result.metadata.model_name == "mock-analysis"
    assert result.metadata.model_version == "test-1"
    assert result.metadata.prompt_version == "1.2"


def test_finalize_result_rejects_target_mismatch() -> None:
    provider = MockModelProvider(make_result())
    service = SingleIPAnalysisService(
        data_provider=StubDataProvider(),
        model_provider=provider,
    )
    result = make_result().model_copy(update={"ip": "192.0.2.11"})

    with pytest.raises(ValueError, match="IP mismatch"):
        service.finalize_result(result, make_asset())

