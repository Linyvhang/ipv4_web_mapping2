import inspect
from datetime import datetime
from types import SimpleNamespace

import pytest

from agent_service.services.single_ip_graph import build_single_ip_graph, initial_state
from agent_service.services.task_orchestrator import SingleIPExecution
from agent_service.models.analysis_schema import (
    AnalysisMetadata,
    AnalysisResult,
    AnalysisSummary,
    EvidenceItem,
    RiskFinding,
    ServiceFingerprint,
)
from agent_service.models.input_schema import AssetAnalysisInput, L3ServiceInput


def make_asset(ip: str = "192.0.2.1") -> AssetAnalysisInput:
    return AssetAnalysisInput(
        ip=ip,
        scan_round=1,
        active_host_id=1,
        alive_type=1,
        services=[
            L3ServiceInput(
                service_instance_id=8,
                active_host_id=1,
                port=80,
                transport_protocol="tcp",
                service_type="web",
                confidence=0.9,
                l2_scan_status=1,
            )
        ],
    )


def make_result(*, valid: bool = True) -> AnalysisResult:
    evidence_id = "ev-1" if valid else "missing"
    return AnalysisResult(
        analysis_id="analysis-test",
        ip="192.0.2.1",
        scan_round=1,
        scan_time=datetime(2026, 11, 11),
        summary=AnalysisSummary(
            risk_level="low", description="测试结果", confidence=0.6
        ),
        services=[
            ServiceFingerprint(
                service_instance_id=8,
                port=80,
                transport_protocol="tcp",
                service_type="web",
            )
        ],
        risks=[
            RiskFinding(
                risk_id="risk-1",
                level="low",
                title="疑似风险",
                description="测试",
                confidence=0.5,
                evidence_ids=[evidence_id],
            )
        ],
        evidence=[
            EvidenceItem(
                evidence_id="ev-1",
                source_type="service",
                source="web",
                detail="80/tcp",
            )
        ],
        metadata=AnalysisMetadata(
            model_provider="mock", model_name="mock", prompt_version="1.0"
        ),
    )


class GraphOrchestrator:
    def __init__(
        self,
        cached: SingleIPExecution | None,
        results: list[AnalysisResult] | None = None,
    ) -> None:
        self.cached = cached
        self.results = results or [make_result()]
        self.validation_feedback: list[list[str] | None] = []
        self.analyze_calls = 0
        self.started = False
        self.completed = False
        self.failed = False

    async def load_asset(self, ip: str, *, scan_round: int | None = None):
        return make_asset(ip)

    async def get_cached_execution(self, _asset):
        return self.cached

    async def start_task(self, _asset, **_: object):
        self.started = True
        return 10, 11

    async def analyze_asset(self, asset, validation_errors=None):
        self.analyze_calls += 1
        self.validation_feedback.append(validation_errors)
        return self.results[min(self.analyze_calls - 1, len(self.results) - 1)]

    async def complete_task(self, *, result, **_: object):
        self.completed = True
        return SingleIPExecution(
            task_id=10,
            task_item_id=11,
            reused=False,
            result=result,
        )

    async def fail_task(self, **_: object):
        self.failed = True


def test_initial_state_defaults_to_saving_latest_scan_result() -> None:
    assert initial_state("192.0.2.1") == {
        "ip": "192.0.2.1",
        "scan_round": None,
        "save_result": True,
        "retry_count": 0,
        "max_retries": 1,
        "fallback_used": False,
    }


def test_initial_state_accepts_explicit_scan_round_and_temporary_mode() -> None:
    state = initial_state("192.0.2.1", scan_round=4, save_result=False)
    assert state["scan_round"] == 4
    assert state["save_result"] is False


def test_graph_compiles_with_asset_and_cache_nodes() -> None:
    graph = build_single_ip_graph(object())
    assert set(graph.get_graph().nodes) == {
        "__start__",
        "load_asset",
        "check_cache",
        "return_cached",
        "create_task",
        "analyze_asset",
        "validate_analysis",
        "prepare_retry",
        "build_fallback",
        "persist_result",
        "__end__",
    }


def test_data_nodes_are_async_and_have_expected_contract() -> None:
    graph = build_single_ip_graph(object())
    for node_name in (
        "load_asset",
        "check_cache",
        "create_task",
        "analyze_asset",
        "validate_analysis",
        "prepare_retry",
        "build_fallback",
        "persist_result",
    ):
        node = graph.get_graph().nodes[node_name]
        assert inspect.iscoroutinefunction(node.data.afunc)
    assert set(initial_state("192.0.2.1")) == {
        "ip",
        "scan_round",
        "save_result",
        "retry_count",
        "max_retries",
        "fallback_used",
    }


def test_graph_has_cached_and_analysis_routes() -> None:
    graph = build_single_ip_graph(object()).get_graph()
    destinations = {
        edge.target
        for edge in graph.edges
        if edge.source == "check_cache"
    }
    assert destinations == {"return_cached", "create_task"}


@pytest.mark.asyncio
async def test_cached_route_skips_analysis_node() -> None:
    cached = SingleIPExecution(
        task_id=None,
        task_item_id=None,
        reused=True,
        result=SimpleNamespace(ip="192.0.2.1"),
    )
    orchestrator = GraphOrchestrator(cached)

    state = await build_single_ip_graph(orchestrator).ainvoke(
        initial_state("192.0.2.1")
    )

    assert state["execution"] is cached
    assert orchestrator.started is False
    assert orchestrator.analyze_calls == 0


@pytest.mark.asyncio
async def test_cache_miss_routes_to_analysis_node() -> None:
    orchestrator = GraphOrchestrator(None)

    state = await build_single_ip_graph(orchestrator).ainvoke(
        initial_state("192.0.2.1")
    )

    assert state["execution"].reused is False
    assert orchestrator.started is True
    assert orchestrator.analyze_calls == 1
    assert orchestrator.completed is True
    assert orchestrator.failed is False


@pytest.mark.asyncio
async def test_invalid_result_is_retried_with_validation_feedback() -> None:
    orchestrator = GraphOrchestrator(None, [make_result(valid=False), make_result()])

    state = await build_single_ip_graph(orchestrator).ainvoke(
        initial_state("192.0.2.1")
    )

    assert orchestrator.analyze_calls == 2
    assert orchestrator.validation_feedback[0] is None
    assert "不存在的证据" in orchestrator.validation_feedback[1][0]
    assert state["retry_count"] == 1
    assert state["fallback_used"] is False
    assert state["execution"].result.risks


@pytest.mark.asyncio
async def test_repeated_invalid_result_uses_safe_fallback() -> None:
    orchestrator = GraphOrchestrator(None, [make_result(valid=False)])

    state = await build_single_ip_graph(orchestrator).ainvoke(
        initial_state("192.0.2.1")
    )

    assert orchestrator.analyze_calls == 2
    assert state["fallback_used"] is True
    assert state["execution"].result.risks == []
    assert "已降级" in state["execution"].result.limitations[-1]
