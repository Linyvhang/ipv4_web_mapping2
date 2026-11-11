import inspect
from types import SimpleNamespace

import pytest

from agent_service.services.single_ip_graph import build_single_ip_graph, initial_state
from agent_service.services.task_orchestrator import SingleIPExecution


class GraphOrchestrator:
    def __init__(self, cached: SingleIPExecution | None) -> None:
        self.cached = cached
        self.analyze_calls = 0
        self.started = False
        self.completed = False
        self.failed = False

    async def load_asset(self, ip: str, *, scan_round: int | None = None):
        return SimpleNamespace(ip=ip, scan_round=scan_round or 1)

    async def get_cached_execution(self, _asset):
        return self.cached

    async def start_task(self, _asset, **_: object):
        self.started = True
        return 10, 11

    async def analyze_asset(self, asset):
        self.analyze_calls += 1
        return SimpleNamespace(ip=asset.ip)

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
        "persist_result",
    ):
        node = graph.get_graph().nodes[node_name]
        assert inspect.iscoroutinefunction(node.data.afunc)
    assert set(initial_state("192.0.2.1")) == {
        "ip",
        "scan_round",
        "save_result",
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
