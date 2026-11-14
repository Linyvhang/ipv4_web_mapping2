"""本地联调用 Mock FastAPI 应用。

该模块不访问数据库、不发起网络请求，仅用于前端和 API 契约联调。
"""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address
from types import SimpleNamespace

from agent_service.api.app import create_app
from agent_service.models.analysis_schema import ModelAnalysisPayload
from agent_service.models.input_schema import AssetAnalysisInput
from agent_service.db.models import TaskStatus
from agent_service.providers.mock import MockModelProvider
from agent_service.services.ip_analysis import SingleIPAnalysisService
from agent_service.services.task_orchestrator import SingleIPTaskOrchestrator
from agent_service.services.batch_analysis import BatchAnalysisService


class MockL3DataProvider:
    async def fetch_asset(self, *, ip_value: int, scan_round: int | None = None):
        ip = str(IPv4Address(ip_value))
        return AssetAnalysisInput(
            ip=ip,
            scan_round=scan_round or 1,
            active_host_id=1,
            alive_type=4,
            first_seen=datetime(2026, 1, 1),
            last_seen=datetime(2026, 1, 1),
            services=[],
            limitations=["Mock 数据，仅用于接口联调"],
        )


class MockTaskRepository:
    def __init__(self) -> None:
        self.next_id = 1
        self.tasks: dict[int, SimpleNamespace] = {}
        self.items: dict[int, SimpleNamespace] = {}

    async def create_task(self, **kwargs: object):
        now = datetime(2026, 1, 1)
        task = SimpleNamespace(
            id=self.next_id,
            task_type=kwargs["task_type"],
            status=TaskStatus.PENDING,
            save_result=kwargs.get("save_result", True),
            target_count=kwargs.get("target_count", 0),
            error_message=None,
            created_at=now,
            started_at=None,
            completed_at=None,
            completed_count=0,
            failed_count=0,
            summary_json=None,
        )
        self.tasks[task.id] = task
        self.next_id += 1
        return task

    async def create_items(self, *, task_id: int, targets: list[tuple[str, int]]):
        now = datetime(2026, 1, 1)
        created = []
        for ip, scan_round in targets:
            item = SimpleNamespace(
                id=self.next_id,
                task_id=task_id,
                ip=ip,
                scan_round=scan_round,
                status=TaskStatus.PENDING,
                error_message=None,
                created_at=now,
                started_at=None,
                completed_at=None,
            )
            self.items[item.id] = item
            self.next_id += 1
            created.append(item)
        return created

    async def update_task_status(self, task_id, status, **kwargs) -> None:
        task = self.tasks[task_id]
        task.status = status
        for name in ("error_message", "started_at", "completed_at"):
            if kwargs.get(name) is not None:
                setattr(task, name, kwargs[name])

    async def update_item_status(self, item_id, status, **kwargs) -> None:
        item = self.items[item_id]
        item.status = status
        for name in ("error_message", "started_at", "completed_at"):
            if kwargs.get(name) is not None:
                setattr(item, name, kwargs[name])

    async def update_task_progress(self, task_id, **kwargs) -> None:
        task = self.tasks[task_id]
        for name, value in kwargs.items():
            setattr(task, name, value)

    async def get_task(self, task_id: int):
        return self.tasks.get(task_id)

    async def get_task_items(self, task_id: int):
        return [item for item in self.items.values() if item.task_id == task_id]

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


class MockAnalysisRepository:
    def __init__(self) -> None:
        self.results: dict[tuple[str, int], SimpleNamespace] = {}

    async def get_cached_result(self, *, ip: str, scan_round: int):
        return self.results.get((ip, scan_round))

    async def create_result(self, **kwargs: object):
        now = datetime(2026, 1, 1)
        result = SimpleNamespace(
            **kwargs, id=len(self.results) + 1, created_at=now, updated_at=now
        )
        self.results[(str(kwargs["ip"]), int(kwargs["scan_round"]))] = result
        return result

    async def get_by_task_item_ids(self, task_item_ids):
        ids = set(task_item_ids)
        return [result for result in self.results.values() if result.task_item_id in ids]


class _MockSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class _MockSessionFactory:
    def __call__(self):
        return _MockSession()


def _mock_result_factory(
    _prompt: str, _output_model: type[ModelAnalysisPayload]
) -> dict:
    return {
        "summary": {
            "risk_level": "info",
            "description": "Mock 分析结果，仅用于接口联调",
            "confidence": 0.5,
        },
        "limitations": ["Mock 数据，仅用于接口联调"],
    }


def create_mock_app():
    """创建可供本地联调的 FastAPI 应用。"""

    model_provider = MockModelProvider(response_factory=_mock_result_factory)
    analysis_service = SingleIPAnalysisService(
        data_provider=MockL3DataProvider(), model_provider=model_provider
    )
    task_repository = MockTaskRepository()
    analysis_repository = MockAnalysisRepository()
    data_provider = MockL3DataProvider()
    orchestrator = SingleIPTaskOrchestrator(
        task_repository=task_repository,
        analysis_repository=analysis_repository,
        data_provider=data_provider,
        analysis_service=analysis_service,
    )
    batch_service = BatchAnalysisService(
        session_factory=_MockSessionFactory(),
        model_provider=model_provider,
        data_provider_factory=lambda _session: data_provider,
        task_repository_factory=lambda _session: task_repository,
        analysis_repository_factory=lambda _session: analysis_repository,
    )
    return create_app(orchestrator, batch_service=batch_service)

