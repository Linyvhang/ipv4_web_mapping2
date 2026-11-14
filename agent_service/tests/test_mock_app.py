from agent_service.api import create_mock_app
from agent_service.api.app import _create_chat_checkpointer
from agent_service.models.chat_schema import (
    AgentEvidence,
    AgentWorkflowStep,
    PriorityAsset,
    QuestionUnderstanding,
    ToolCallRecord,
)
from fastapi.testclient import TestClient


def test_chat_checkpointer_only_allows_project_state_types() -> None:
    checkpointer = _create_chat_checkpointer()
    expected = {
        (model.__module__, model.__name__)
        for model in (
            QuestionUnderstanding,
            ToolCallRecord,
            AgentEvidence,
            PriorityAsset,
            AgentWorkflowStep,
        )
    }

    assert checkpointer.serde._allowed_msgpack_modules == expected


def test_mock_app_exposes_analysis_and_chat_endpoints() -> None:
    app = create_mock_app()
    all_route_paths = [
        route.path
        for included in app.routes
        for route in getattr(
            getattr(included, "original_router", included), "routes", [included]
        )
        if hasattr(route, "path")
    ]
    route_paths = set(all_route_paths)
    assert "/analysis/ip" in route_paths
    assert "/agent/chat" in route_paths
    assert "/assets/{ip}/scan-data" in route_paths
    assert "/analysis/tasks/{task_id}" in route_paths
    assert "/analysis/batch" in route_paths
    assert "/analysis/tasks/{task_id}/report" in route_paths
    assert "/assets/{ip}/changes" in route_paths
    assert "/api/health" in route_paths
    assert "/api/bootstrap" in route_paths
    assert "/api/search" in route_paths
    assert all_route_paths.count("/") == 1
    assert "/preview" in route_paths


def test_mock_app_serves_integrated_frontend_and_platform_bootstrap() -> None:
    with TestClient(create_mock_app()) as client:
        page = client.get("/")
        health = client.get("/api/health")
        bootstrap = client.get("/api/bootstrap")
        search = client.get("/api/search", params={"q": "port=22"})

    assert page.status_code == 200
    assert "NetScope" in page.text
    assert health.json() == {"ok": True, "db": "mock"}
    assert bootstrap.status_code == 200
    assert bootstrap.json()["overview"]["scan_round"] == 1
    assert bootstrap.json()["overview"]["host"] == 2
    assert bootstrap.json()["assets"][0]["ip"] == "192.0.2.10"
    assert search.status_code == 200
    assert search.json()["total"] == 1


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
        created_report = client.post(f"/analysis/tasks/{task_id}/report")
        reused_report = client.get(f"/analysis/tasks/{task_id}/report")

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
    assert created_report.status_code == 200
    assert created_report.json()["reused"] is False
    assert created_report.json()["report"]["overview"]["analyzed_assets"] == 2
    assert reused_report.status_code == 200
    assert reused_report.json()["reused"] is True
    assert reused_report.json()["report_id"] == created_report.json()["report_id"]


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


def test_mock_app_compares_two_scan_rounds_without_model_calls() -> None:
    with TestClient(create_mock_app()) as client:
        response = client.get(
            "/assets/192.0.2.10/changes",
            params={"from_scan_round": 1, "to_scan_round": 2},
        )
        invalid = client.get(
            "/assets/192.0.2.10/changes",
            params={"from_scan_round": 2, "to_scan_round": 2},
        )

    assert response.status_code == 200
    assert response.json()["change_status"] == "unchanged"
    assert response.json()["risk_changes"]["available"] is False
    assert invalid.status_code == 400


def test_mock_app_reuses_and_deletes_langgraph_conversation_checkpoint() -> None:
    with TestClient(create_mock_app()) as client:
        batch = client.post(
            "/analysis/batch",
            json={"ips": ["192.0.2.10", "192.0.2.11"], "scan_round": 1},
        ).json()
        client.post(f"/analysis/tasks/{batch['task_id']}/report")
        first = client.post(
            "/agent/chat",
            json={"question": f"查询批量任务 {batch['task_id']} 的统计报告"},
        )
        conversation_id = first.json()["conversation_id"]
        follow_up = client.post(
            "/agent/chat",
            json={
                "question": "哪个资产需要优先处理？",
                "conversation_id": conversation_id,
            },
        )
        explicit_new_target = client.post(
            "/agent/chat",
            json={
                "question": "查询 192.0.2.11 开放了哪些服务",
                "conversation_id": conversation_id,
            },
        )
        deleted = client.delete(f"/agent/conversations/{conversation_id}")
        after_delete = client.post(
            "/agent/chat",
            json={
                "question": "哪个资产需要优先处理？",
                "conversation_id": conversation_id,
            },
        )

    assert first.status_code == 200
    assert first.json()["intent"] == "query_batch_report"
    assert follow_up.status_code == 200
    assert follow_up.json()["intent"] == "query_batch_report"
    assert follow_up.json()["task_id"] == batch["task_id"]
    assert follow_up.json()["context_reused"] is True
    assert follow_up.json()["tools_used"][0]["name"] == "get_batch_report"
    assert explicit_new_target.status_code == 200
    assert explicit_new_target.json()["target_ip"] == "192.0.2.11"
    assert explicit_new_target.json()["context_reused"] is False
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True
    assert after_delete.status_code == 200
    assert after_delete.json()["status"] == "invalid_request"
    assert after_delete.json()["context_reused"] is False

