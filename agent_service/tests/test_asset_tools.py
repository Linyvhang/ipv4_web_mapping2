from datetime import datetime
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agent_service.models.analysis_schema import (
    AnalysisMetadata,
    AnalysisResult,
    AnalysisSummary,
)
from agent_service.models.input_schema import AssetAnalysisInput, L3ServiceInput
from agent_service.services.ip_analysis import AssetNotFoundError
from agent_service.services.task_orchestrator import SingleIPExecution
from agent_service.tools.asset_tools import (
    AgentToolPermissionError,
    AssetAgentToolRegistry,
    UnknownAgentToolError,
)


def make_asset() -> AssetAnalysisInput:
    return AssetAnalysisInput(
        ip="192.0.2.10",
        scan_round=3,
        active_host_id=1,
        alive_type=1,
        services=[
            L3ServiceInput(
                service_instance_id=7,
                active_host_id=1,
                port=22,
                transport_protocol="tcp",
                service_type="ssh",
                banner="SSH-2.0-OpenSSH_9.2",
                confidence=0.9,
                l2_scan_status=1,
            )
        ],
        limitations=["仅包含已有扫描数据"],
    )


def make_result() -> AnalysisResult:
    return AnalysisResult(
        analysis_id="analysis-tool-test",
        ip="192.0.2.10",
        scan_round=3,
        scan_time=datetime(2026, 11, 12),
        summary=AnalysisSummary(
            risk_level="info", description="已完成分析", confidence=0.8
        ),
        metadata=AnalysisMetadata(
            model_provider="mock", model_name="mock", prompt_version="1.0"
        ),
    )


class FakeAnalysisRepository:
    def __init__(self, result: AnalysisResult | None = None) -> None:
        self.result = result
        self.queries: list[tuple[str, int]] = []

    async def get_cached_result(self, *, ip: str, scan_round: int):
        self.queries.append((ip, scan_round))
        if self.result is None:
            return None
        return SimpleNamespace(result_json=self.result.model_dump(mode="json"))


class FakeOrchestrator:
    def __init__(self, result: AnalysisResult | None = None) -> None:
        self.analysis_repository = FakeAnalysisRepository(result)
        self.load_calls: list[tuple[str, int | None]] = []

    async def load_asset(self, ip: str, *, scan_round: int | None = None):
        self.load_calls.append((ip, scan_round))
        if ip == "192.0.2.99":
            raise AssetNotFoundError("not found")
        return make_asset()


class FakeGraph:
    def __init__(self) -> None:
        self.states: list[dict] = []

    async def ainvoke(self, state: dict):
        self.states.append(state)
        return {
            "execution": SingleIPExecution(
                task_id=10,
                task_item_id=11,
                reused=False,
                result=make_result(),
            )
        }


class FakeSerializable:
    def __init__(self, payload):
        self.payload = payload

    def model_dump(self, **_kwargs):
        return self.payload


class FakeAssetChangeService:
    async def compare(self, ip, *, from_scan_round, to_scan_round):
        return FakeSerializable(
            {
                "ip": ip,
                "from_scan_round": from_scan_round,
                "to_scan_round": to_scan_round,
                "change_status": "changed",
            }
        )


class FakeBatchReportService:
    async def get_report(self, task_id):
        return SimpleNamespace(
            report_id=7,
            task_id=task_id,
            report=FakeSerializable(
                {"overview": {"analyzed_assets": 2, "total_services": 3}}
            ),
        )


def run_immediate(coroutine):
    try:
        yielded = coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    coroutine.close()
    raise AssertionError(f"测试协程意外等待了异步对象: {yielded!r}")


def make_registry(result: AnalysisResult | None = None):
    orchestrator = FakeOrchestrator(result)
    graph = FakeGraph()
    return AssetAgentToolRegistry(
        orchestrator=orchestrator,
        graph=graph,
        asset_change_service=FakeAssetChangeService(),
        batch_report_service=FakeBatchReportService(),
    ), orchestrator, graph


def test_registry_exposes_five_bounded_tools() -> None:
    registry, _, _ = make_registry()

    assert [definition.name for definition in registry.definitions] == [
        "get_ip_scan_data",
        "get_ip_analysis_result",
        "create_ip_analysis",
        "compare_ip_scan_rounds",
        "get_batch_report",
    ]
    assert [definition.read_only for definition in registry.definitions] == [
        True,
        True,
        False,
        True,
        True,
    ]
    assert registry.definitions[2].requires_explicit_request is True


def test_scan_tool_returns_existing_l3_fingerprints() -> None:
    registry, orchestrator, _ = make_registry()

    response = run_immediate(
        registry.execute("get_ip_scan_data", {"ip": "192.0.2.10"})
    )

    assert response.status == "success"
    assert response.data["asset"]["scan_round"] == 3
    assert response.data["asset"]["services"][0]["service_type"] == "ssh"
    assert orchestrator.load_calls == [("192.0.2.10", None)]


def test_analysis_result_tool_reuses_saved_result() -> None:
    registry, orchestrator, _ = make_registry(make_result())

    response = run_immediate(
        registry.execute(
            "get_ip_analysis_result", {"ip": "192.0.2.10", "scan_round": 3}
        )
    )

    assert response.status == "success"
    assert response.data["result"]["analysis_id"] == "analysis-tool-test"
    assert orchestrator.analysis_repository.queries == [("192.0.2.10", 3)]


def test_missing_scan_and_analysis_are_normal_not_found_results() -> None:
    registry, _, _ = make_registry()

    missing_scan = run_immediate(
        registry.execute("get_ip_scan_data", {"ip": "192.0.2.99"})
    )
    missing_analysis = run_immediate(
        registry.execute("get_ip_analysis_result", {"ip": "192.0.2.10"})
    )

    assert missing_scan.status == "not_found"
    assert missing_analysis.status == "not_found"
    assert missing_analysis.data["scan_round"] == 3


def test_create_analysis_requires_explicit_permission_and_uses_existing_graph() -> None:
    registry, _, graph = make_registry()
    arguments = {"ip": "192.0.2.10", "scan_round": 3, "save_result": True}

    with pytest.raises(AgentToolPermissionError):
        run_immediate(registry.execute("create_ip_analysis", arguments))

    response = run_immediate(
        registry.execute(
            "create_ip_analysis", arguments, allow_task_creation=True
        )
    )

    assert response.status == "success"
    assert response.data["task_id"] == 10
    assert response.data["reused"] is False
    assert graph.states[0]["ip"] == "192.0.2.10"
    assert graph.states[0]["max_retries"] == 1


def test_unknown_tool_and_invalid_ip_are_rejected_before_database_access() -> None:
    registry, orchestrator, _ = make_registry()

    with pytest.raises(UnknownAgentToolError):
        run_immediate(registry.execute("run_sql", {"sql": "SELECT 1"}))
    with pytest.raises(ValidationError):
        run_immediate(registry.execute("get_ip_scan_data", {"ip": "not-an-ip"}))

    assert orchestrator.load_calls == []


def test_history_comparison_and_batch_report_tools_are_read_only() -> None:
    registry, _, _ = make_registry()

    comparison = run_immediate(
        registry.execute(
            "compare_ip_scan_rounds",
            {
                "ip": "192.0.2.10",
                "from_scan_round": 1,
                "to_scan_round": 2,
            },
        )
    )
    report = run_immediate(registry.execute("get_batch_report", {"task_id": 11}))

    assert comparison.status == "success"
    assert comparison.data["comparison"]["change_status"] == "changed"
    assert report.status == "success"
    assert report.data["report_id"] == 7
    assert report.data["report"]["overview"]["analyzed_assets"] == 2
