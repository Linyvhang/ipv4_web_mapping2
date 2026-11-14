from agent_service.api import create_mock_app
from fastapi.testclient import TestClient


def test_mock_app_exposes_analysis_and_chat_endpoints() -> None:
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
    assert "/agent/chat" in route_paths
    assert "/assets/{ip}/scan-data" in route_paths
    assert "/analysis/tasks/{task_id}" in route_paths


def test_mock_app_supports_visualization_integration_flow() -> None:
    app = create_mock_app()
    with TestClient(app) as client:
        scan = client.get("/assets/192.0.2.10/scan-data")
        analysis = client.post(
            "/analysis/ip",
            json={"ip": "192.0.2.10", "scan_round": None, "save_result": True},
        )
        task_id = analysis.json()["task_id"]
        status = client.get(f"/analysis/tasks/{task_id}")
        result = client.get(f"/analysis/tasks/{task_id}/result")
        saved = client.get("/assets/192.0.2.10/analysis")

    assert scan.status_code == 200
    assert analysis.status_code == 200
    assert status.status_code == 200
    assert status.json()["status"] == "success"
    assert result.status_code == 200
    assert result.json()["items"][0]["result"]["ip"] == "192.0.2.10"
    assert saved.status_code == 200

