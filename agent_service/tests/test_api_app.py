from agent_service.api import create_app


class FakeOrchestrator:
    async def execute(self, ip: str, *, scan_round: int | None, save_result: bool):
        raise AssertionError("应用装配测试不应执行分析")


def test_create_app_mounts_analysis_and_chat_routes_and_metadata() -> None:
    app = create_app(
        FakeOrchestrator(), batch_service=object(), batch_report_service=object()
    )
    paths = {
        route.path
        for included in app.routes
        for route in getattr(
            getattr(included, "original_router", included), "routes", [included]
        )
        if hasattr(route, "path")
    }

    assert "/analysis/ip" in paths
    assert "/agent/chat" in paths
    assert "/assets/{ip}/scan-data" in paths
    assert "/assets/{ip}/analysis" in paths
    assert "/analysis/tasks/{task_id}" in paths
    assert "/analysis/tasks/{task_id}/result" in paths
    assert "/analysis/batch" in paths
    assert "/analysis/tasks/{task_id}/report" in paths
    assert "/chat" in paths
    assert app.title == "IPv4 Web Mapping Agent API"
    assert app.version == "0.1.0"
    assert app.state.single_ip_graph is not None
    assert app.state.agent_tool_registry is not None
    assert app.state.chat_agent_graph is not None

