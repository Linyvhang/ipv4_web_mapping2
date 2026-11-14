from datetime import datetime
from ipaddress import IPv4Address
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from agent_service.api.asset_routes import create_asset_router
from agent_service.models.analysis_schema import AnalysisResult
from agent_service.models.input_schema import AssetAnalysisInput, L3ServiceInput
from agent_service.services.ip_analysis import AssetNotFoundError


def analysis_result():
    return AnalysisResult.model_validate({
        "analysis_id": "analysis-asset-api",
        "ip": "192.0.2.10",
        "scan_round": 3,
        "scan_time": "2026-11-14T00:00:00",
        "summary": {"risk_level": "info", "description": "测试结果", "confidence": 0.8},
        "metadata": {"model_provider": "mock", "model_name": "mock", "prompt_version": "1.0"},
    })


class FakeAnalysisRepository:
    def __init__(self, found=True):
        result = analysis_result()
        self.record = SimpleNamespace(
            analysis_id=result.analysis_id,
            ip=result.ip,
            scan_round=result.scan_round,
            result_json=result.model_dump(mode="json"),
            created_at=datetime(2026, 11, 14),
            updated_at=datetime(2026, 11, 14),
        ) if found else None
        self.calls = []

    async def get_cached_result(self, *, ip, scan_round):
        self.calls.append((ip, scan_round))
        return self.record


class FakeOrchestrator:
    def __init__(self, *, asset_found=True, analysis_found=True):
        self.asset_found = asset_found
        self.analysis_repository = FakeAnalysisRepository(analysis_found)
        self.load_calls = []

    async def load_asset(self, ip, *, scan_round=None):
        self.load_calls.append((ip, scan_round))
        if not self.asset_found:
            raise AssetNotFoundError(f"未找到 IP {ip} 的扫描数据")
        return AssetAnalysisInput(
            ip=ip,
            scan_round=scan_round or 3,
            active_host_id=7,
            alive_type=4,
            first_seen=datetime(2026, 11, 14),
            services=[L3ServiceInput(
                service_instance_id=8,
                active_host_id=7,
                port=22,
                transport_protocol="tcp",
                service_type="ssh",
                confidence=0.9,
                l2_scan_status=1,
                banner="SSH-2.0-OpenSSH_9.2",
            )],
        )


def endpoint(router, path):
    return next(route.endpoint for route in router.routes if route.path == path)


@pytest.mark.asyncio
async def test_scan_data_endpoint_returns_latest_database_facts_without_analysis():
    orchestrator = FakeOrchestrator()
    route = endpoint(create_asset_router(orchestrator), "/assets/{ip}/scan-data")

    response = await route(IPv4Address("192.0.2.10"), scan_round=None)

    assert response.scan_round == 3
    assert response.services[0].port == 22
    assert orchestrator.load_calls == [("192.0.2.10", None)]
    assert orchestrator.analysis_repository.calls == []


@pytest.mark.asyncio
async def test_saved_analysis_endpoint_uses_resolved_scan_round_and_never_reanalyzes():
    orchestrator = FakeOrchestrator()
    route = endpoint(create_asset_router(orchestrator), "/assets/{ip}/analysis")

    response = await route(IPv4Address("192.0.2.10"), scan_round=3)

    assert response.result.analysis_id == "analysis-asset-api"
    assert orchestrator.analysis_repository.calls == [("192.0.2.10", 3)]


@pytest.mark.asyncio
async def test_asset_endpoints_return_404_for_missing_scan_or_analysis():
    missing_asset = FakeOrchestrator(asset_found=False)
    scan_route = endpoint(create_asset_router(missing_asset), "/assets/{ip}/scan-data")
    with pytest.raises(HTTPException) as scan_error:
        await scan_route(IPv4Address("192.0.2.99"), scan_round=None)
    assert scan_error.value.status_code == 404

    missing_analysis = FakeOrchestrator(analysis_found=False)
    analysis_route = endpoint(create_asset_router(missing_analysis), "/assets/{ip}/analysis")
    with pytest.raises(HTTPException) as analysis_error:
        await analysis_route(IPv4Address("192.0.2.10"), scan_round=None)
    assert analysis_error.value.status_code == 404
    assert "尚无已保存" in analysis_error.value.detail
