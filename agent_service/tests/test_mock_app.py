from agent_service.api import create_mock_app


def test_mock_app_exposes_single_ip_endpoint() -> None:
    app = create_mock_app()
    route_paths = {
        route.path
        for included in app.routes
        for route in getattr(
            getattr(included, "original_router", included), "routes", [included]
        )
        if hasattr(route, "path")
    }
    assert "/analysis/ip" in route_paths

