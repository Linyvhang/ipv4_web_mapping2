from agent_service.api import create_app


class FakeOrchestrator:
    async def execute(self, ip: str, *, scan_round: int | None, save_result: bool):
        raise AssertionError("应用装配测试不应执行分析")


def test_create_app_mounts_single_ip_route_and_metadata() -> None:
    app = create_app(FakeOrchestrator())
    paths = {
        route.path
        for included in app.routes
        for route in getattr(
            getattr(included, "original_router", included), "routes", [included]
        )
        if hasattr(route, "path")
    }

    assert "/analysis/ip" in paths
    assert app.title == "IPv4 Web Mapping Agent API"
    assert app.version == "0.1.0"

