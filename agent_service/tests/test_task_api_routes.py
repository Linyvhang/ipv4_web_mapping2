from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import agent_service.api.task_routes as task_routes_module
from agent_service.api.task_routes import create_task_query_router
from agent_service.db.models import TaskStatus, TaskType
from agent_service.tests.test_asset_api_routes import analysis_result


class FakeTaskRepository:
    def __init__(self, task_status=TaskStatus.SUCCESS, found=True):
        now = datetime(2026, 11, 14)
        self.task = SimpleNamespace(
            id=10,
            task_type=TaskType.IP_ANALYSIS,
            status=task_status,
            save_result=True,
            target_count=1,
            error_message=("模型失败" if task_status == TaskStatus.FAILED else None),
            created_at=now,
            started_at=now,
            completed_at=(now if task_status not in {TaskStatus.PENDING, TaskStatus.RUNNING} else None),
        ) if found else None
        self.items = [] if not found else [SimpleNamespace(
            id=11,
            task_id=10,
            ip="192.0.2.10",
            scan_round=3,
            status=task_status,
            error_message=("模型失败" if task_status == TaskStatus.FAILED else None),
            created_at=now,
            started_at=now,
            completed_at=(now if task_status not in {TaskStatus.PENDING, TaskStatus.RUNNING} else None),
        )]

    async def get_task(self, task_id):
        return self.task if task_id == 10 else None

    async def get_task_items(self, task_id):
        return self.items if task_id == 10 else []


class FakeAnalysisRepository:
    def __init__(self, include_result=True):
        result = analysis_result()
        self.records = [SimpleNamespace(
            task_item_id=11,
            result_json=result.model_dump(mode="json"),
        )] if include_result else []

    async def get_by_task_item_ids(self, ids):
        assert list(ids) == [11]
        return self.records

    async def get_cached_result(self, *, ip, scan_round):
        if self.records:
            return self.records[0]
        return None


class FakeOrchestrator:
    def __init__(self, status=TaskStatus.SUCCESS, found=True, include_result=True):
        self.task_repository = FakeTaskRepository(status, found)
        self.analysis_repository = FakeAnalysisRepository(include_result)


def endpoint(router, path):
    return next(route.endpoint for route in router.routes if route.path == path)


@pytest.mark.asyncio
async def test_task_status_returns_item_counts_and_timestamps():
    route = endpoint(create_task_query_router(FakeOrchestrator()), "/analysis/tasks/{task_id}")
    response = await route(10)

    assert response.status == "success"
    assert response.total == 1
    assert response.success == 1
    assert response.items[0].task_item_id == 11


@pytest.mark.asyncio
async def test_completed_and_failed_task_results_are_queryable():
    success_route = endpoint(
        create_task_query_router(FakeOrchestrator()),
        "/analysis/tasks/{task_id}/result",
    )
    success = await success_route(10)
    assert success.items[0].result.analysis_id == "analysis-asset-api"

    failed_route = endpoint(
        create_task_query_router(FakeOrchestrator(TaskStatus.FAILED, include_result=False)),
        "/analysis/tasks/{task_id}/result",
    )
    failed = await failed_route(10)
    assert failed.status == "failed"
    assert failed.items[0].result is None
    assert failed.items[0].error_message == "模型失败"


@pytest.mark.asyncio
async def test_successful_reused_item_falls_back_to_cached_result():
    orchestrator = FakeOrchestrator(include_result=True)
    orchestrator.analysis_repository.records[0].task_item_id = 999
    route = endpoint(
        create_task_query_router(orchestrator),
        "/analysis/tasks/{task_id}/result",
    )

    response = await route(10)

    assert response.items[0].result.analysis_id == "analysis-asset-api"


@pytest.mark.asyncio
async def test_running_result_returns_409_and_missing_task_returns_404():
    running_route = endpoint(
        create_task_query_router(FakeOrchestrator(TaskStatus.RUNNING)),
        "/analysis/tasks/{task_id}/result",
    )
    with pytest.raises(HTTPException) as running_error:
        await running_route(10)
    assert running_error.value.status_code == 409

    missing_route = endpoint(
        create_task_query_router(FakeOrchestrator(found=False)),
        "/analysis/tasks/{task_id}",
    )
    with pytest.raises(HTTPException) as missing_error:
        await missing_route(99)
    assert missing_error.value.status_code == 404


@pytest.mark.asyncio
async def test_task_queries_use_a_fresh_session_when_factory_is_provided(monkeypatch):
    orchestrator = FakeOrchestrator()

    class SessionContext:
        async def __aenter__(self):
            return object()

        async def __aexit__(self, exc_type, exc, traceback):
            return False

    class SessionFactory:
        def __init__(self):
            self.calls = 0

        def __call__(self):
            self.calls += 1
            return SessionContext()

    factory = SessionFactory()
    monkeypatch.setattr(
        task_routes_module,
        "AgentTaskRepository",
        lambda _session: orchestrator.task_repository,
    )
    monkeypatch.setattr(
        task_routes_module,
        "AgentAnalysisRepository",
        lambda _session: orchestrator.analysis_repository,
    )
    router = create_task_query_router(orchestrator, session_factory=factory)

    await endpoint(router, "/analysis/tasks/{task_id}")(10)
    await endpoint(router, "/analysis/tasks/{task_id}/result")(10)

    assert factory.calls == 2
