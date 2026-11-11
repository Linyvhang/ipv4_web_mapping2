from datetime import datetime

import pytest

from agent_service.models.analysis_schema import ModelAnalysisPayload
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


def make_payload() -> ModelAnalysisPayload:
    return ModelAnalysisPayload.model_validate(
        {
            "summary": {
                "primary_asset_type": "Web服务器",
                "risk_level": "info",
                "description": "根据现有证据完成分析",
                "confidence": 0.7,
            },
            "limitations": ["模型证据有限"],
        }
    )


class StubDataProvider:
    async def fetch_asset(self, *, ip_value: int, scan_round: int | None = None):
        return make_asset() if ip_value == ipv4_to_uint32("192.0.2.10") else None


def run_immediate(coroutine):
    """运行只调用同步 Mock 的协程，避免依赖 Windows 事件循环。"""

    try:
        yielded = coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    coroutine.close()
    raise AssertionError(f"测试协程意外等待了异步对象: {yielded!r}")


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


def test_build_prompt_includes_validation_feedback_on_retry() -> None:
    prompt = SingleIPAnalysisService.build_prompt(
        make_asset(), ["风险 risk-1 缺少证据引用"]
    )

    assert "上一次输出未通过" in prompt
    assert "风险 risk-1 缺少证据引用" in prompt


def test_finalize_result_combines_program_facts_and_model_analysis() -> None:
    provider = MockModelProvider(
        make_payload(),
        provider="mock",
        model_name="mock-analysis",
        model_version="test-1",
    )
    service = SingleIPAnalysisService(
        data_provider=StubDataProvider(),
        model_provider=provider,
        prompt_version="1.2",
    )

    result = service.finalize_result(make_payload(), make_asset())

    assert result.analysis_id.startswith("analysis-")
    assert result.ip == "192.0.2.10"
    assert result.scan_round == 1
    assert result.scan_time == datetime(2026, 10, 30)
    assert result.services[0].service_instance_id == 12
    assert result.services[0].banner == "Server: nginx/1.24.0"
    assert result.limitations == [
        "本次输入仅包含已有 L1/L2/L3 扫描数据",
        "模型证据有限",
    ]
    assert result.metadata.model_provider == "mock"
    assert result.metadata.model_name == "mock-analysis"
    assert result.metadata.model_version == "test-1"
    assert result.metadata.prompt_version == "1.2"


def test_analyze_asset_requests_model_only_payload_schema() -> None:
    requested_models: list[type] = []

    def response_factory(_prompt: str, output_model: type) -> dict:
        requested_models.append(output_model)
        return make_payload().model_dump(mode="json")

    provider = MockModelProvider(response_factory=response_factory)
    service = SingleIPAnalysisService(
        data_provider=StubDataProvider(),
        model_provider=provider,
    )

    result = run_immediate(service.analyze_asset(make_asset()))

    assert requested_models == [ModelAnalysisPayload]
    assert result.ip == "192.0.2.10"

