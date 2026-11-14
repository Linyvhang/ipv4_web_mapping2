from datetime import datetime

import pytest

from agent_service.api.mock_app import _MockSessionFactory
from agent_service.models.analysis_schema import AnalysisResult, ProductFingerprint
from agent_service.models.input_schema import AssetAnalysisInput, L3ServiceInput
from agent_service.services.asset_change import (
    AssetChangeService,
    ComparedAssetNotFoundError,
    ScanRoundNotFoundError,
)


def service(port, service_type, product=None, version=None):
    fingerprint = None
    if product is not None:
        fingerprint = ProductFingerprint(
            normalized_product_name=product,
            normalized_version=version,
            normalization_confidence=0.9,
        )
    return L3ServiceInput(
        service_instance_id=port,
        active_host_id=1,
        port=port,
        transport_protocol="tcp",
        service_type=service_type,
        confidence=0.9,
        l2_scan_status=1,
        product=fingerprint,
    )


def asset(round_number, services):
    return AssetAnalysisInput(
        ip="192.0.2.10",
        scan_round=round_number,
        active_host_id=round_number,
        alive_type=4,
        last_seen=datetime(2026, 11, round_number),
        services=services,
        limitations=["仅扫描常用端口"],
    )


def result(round_number, level, title, *, attention=False):
    return AnalysisResult.model_validate(
        {
            "analysis_id": f"analysis-{round_number}",
            "ip": "192.0.2.10",
            "scan_round": round_number,
            "scan_time": f"2026-11-{round_number:02d}T00:00:00",
            "summary": {
                "risk_level": level,
                "description": "测试",
                "confidence": 0.8,
                "needs_attention": attention,
            },
            "risks": [
                {
                    "risk_id": f"risk-{round_number}",
                    "level": level,
                    "title": title,
                    "description": "需要核实",
                    "confidence": 0.7,
                }
            ],
            "metadata": {
                "model_provider": "mock",
                "model_name": "mock",
                "prompt_version": "1.0",
            },
        }
    )


def test_comparison_detects_service_product_and_risk_changes():
    comparison = AssetChangeService.build_comparison(
        ip="192.0.2.10",
        from_scan_round=1,
        to_scan_round=2,
        old_asset=asset(
            1,
            [
                service(22, "ssh", "OpenSSH", "8.9"),
                service(80, "web", "nginx", "1.20"),
            ],
        ),
        new_asset=asset(
            2,
            [
                service(22, "ssh", "OpenSSH", "9.2"),
                service(443, "web", "nginx", "1.24"),
            ],
        ),
        old_result=result(1, "low", "旧疑似风险"),
        new_result=result(2, "high", "新疑似风险", attention=True),
    )

    assert comparison.change_status == "changed"
    assert comparison.summary.added_service_count == 1
    assert comparison.summary.removed_service_count == 1
    assert comparison.service_changes.added[0].port == 443
    assert comparison.service_changes.removed[0].port == 80
    assert comparison.service_changes.unchanged_count == 1
    assert comparison.product_changes[0].change_type == "version_changed"
    assert comparison.product_changes[0].from_version == "8.9"
    assert comparison.product_changes[0].to_version == "9.2"
    assert comparison.risk_changes.direction == "increased"
    assert comparison.risk_changes.added[0].title == "新疑似风险"
    assert comparison.risk_changes.removed[0].title == "旧疑似风险"
    assert comparison.risk_changes.needs_attention_changed is True


def test_asset_added_and_missing_analysis_are_reported_without_failure():
    comparison = AssetChangeService.build_comparison(
        ip="192.0.2.10",
        from_scan_round=1,
        to_scan_round=2,
        old_asset=None,
        new_asset=asset(2, [service(443, "web", "nginx", "1.24")]),
        old_result=None,
        new_result=None,
    )

    assert comparison.change_status == "added"
    assert comparison.summary.added_service_count == 1
    assert comparison.risk_changes.available is False
    assert comparison.risk_changes.direction == "unavailable"
    assert any("无法比较风险变化" in item for item in comparison.limitations)


def test_identical_assets_and_results_are_unchanged():
    old_asset = asset(1, [service(22, "ssh", "OpenSSH", "9.2")])
    new_asset = asset(2, [service(22, "ssh", "OpenSSH", "9.2")])
    comparison = AssetChangeService.build_comparison(
        ip="192.0.2.10",
        from_scan_round=1,
        to_scan_round=2,
        old_asset=old_asset,
        new_asset=new_asset,
        old_result=result(1, "low", "同一风险"),
        new_result=result(2, "low", "同一风险"),
    )

    assert comparison.change_status == "unchanged"
    assert comparison.product_changes == []
    assert comparison.risk_changes.direction == "unchanged"


def test_removed_asset_and_decreased_risk_are_supported():
    removed = AssetChangeService.build_comparison(
        ip="192.0.2.10",
        from_scan_round=1,
        to_scan_round=2,
        old_asset=asset(1, [service(22, "ssh")]),
        new_asset=None,
        old_result=None,
        new_result=None,
    )
    decreased = AssetChangeService._compare_risks(
        result(1, "high", "风险"), result(2, "low", "风险")
    )

    assert removed.change_status == "removed"
    assert removed.summary.removed_service_count == 1
    assert decreased.direction == "decreased"


@pytest.mark.asyncio
async def test_compare_raises_when_ip_is_missing_from_both_rounds():
    class EmptyProvider:
        async def fetch_asset(self, **_kwargs):
            return None

    service_instance = AssetChangeService(
        session_factory=_MockSessionFactory(),
        data_provider_factory=lambda _session: EmptyProvider(),
        analysis_repository_factory=lambda _session: object(),
    )

    with pytest.raises(ComparedAssetNotFoundError):
        await service_instance.compare(
            "192.0.2.99", from_scan_round=1, to_scan_round=2
        )


@pytest.mark.asyncio
async def test_compare_rejects_a_scan_round_that_does_not_exist():
    class MissingRoundProvider:
        async def scan_round_exists(self, scan_round):
            return scan_round == 1

        async def fetch_asset(self, **_kwargs):
            raise AssertionError("批次预检失败后不应查询具体 IP")

    service_instance = AssetChangeService(
        session_factory=_MockSessionFactory(),
        data_provider_factory=lambda _session: MissingRoundProvider(),
        analysis_repository_factory=lambda _session: object(),
    )

    with pytest.raises(ScanRoundNotFoundError) as error:
        await service_instance.compare(
            "192.0.2.10", from_scan_round=1, to_scan_round=2
        )

    assert error.value.missing_rounds == [2]
