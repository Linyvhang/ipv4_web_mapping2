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
    assert "/analysis/batch" in route_paths


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


def test_mock_app_supports_limited_batch_analysis_flow() -> None:
    app = create_mock_app()
    with TestClient(app) as client:
        created = client.post(
            "/analysis/batch",
            json={
                "ips": ["192.0.2.10", "192.0.2.11", "192.0.2.10"],
                "scan_round": None,
            },
        )
        task_id = created.json()["task_id"]
        task = client.get(f"/analysis/tasks/{task_id}")
        result = client.get(f"/analysis/tasks/{task_id}/result")

    assert created.status_code == 202
    assert created.json()["target_count"] == 2
    assert [target["ip"] for target in created.json()["targets"]] == [
        "192.0.2.10",
        "192.0.2.11",
    ]
    assert task.status_code == 200
    assert task.json()["status"] == "success"
    assert task.json()["success"] == 2
    assert result.status_code == 200
    assert len(result.json()["items"]) == 2
    assert all(item["result"] is not None for item in result.json()["items"])


def test_batch_request_validates_ipv4_and_minimum_count() -> None:
    with TestClient(create_mock_app()) as client:
        invalid = client.post(
            "/analysis/batch", json={"ips": ["not-an-ip", "192.0.2.1"]}
        )
        too_few = client.post(
            "/analysis/batch", json={"ips": ["192.0.2.1"]}
        )

    assert invalid.status_code == 422
    assert too_few.status_code == 422

