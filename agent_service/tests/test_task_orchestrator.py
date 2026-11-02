from datetime import datetime
from types import SimpleNamespace

import pytest

from agent_service.db.models import TaskStatus
from agent_service.models.analysis_schema import (
    AnalysisMetadata,
    AnalysisResult,
    AnalysisSummary,
    Confidence,
)
from agent_service.services.task_orchestrator import SingleIPTaskOrchestrator
from agent_service.services.task_orchestrator import CachedModelConflictError
from agent_service.providers.base import ModelInfo


class TransactionTaskRepository:
    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0
        self.task_statuses: list[object] = []
        self.item_statuses: list[object] = []

    async def create_task(self, **_: object):
        return SimpleNamespace(id=10)

    async def create_items(self, **_: object):
        return [SimpleNamespace(id=11)]

    async def update_task_status(self, _task_id: int, status, **_: object) -> None:
        self.task_statuses.append(status)

    async def update_item_status(self, _item_id: int, status, **_: object) -> None:
        self.item_statuses.append(status)

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


class TransactionAnalysisRepository:
    async def get_cached_result(self, **_: object):
        return None

    async def create_result(self, **kwargs: object):
        return SimpleNamespace(**kwargs)


class TransactionDataProvider:
    async def fetch_asset(self, **_: object):
        return SimpleNamespace(ip="192.0.2.1", scan_round=1)


def make_transaction_result() -> AnalysisResult:
    return AnalysisResult(
        analysis_id="transaction-1",
        ip="192.0.2.1",
        scan_round=1,
        scan_time=datetime(2026, 1, 1),
        summary=AnalysisSummary(
            risk_level="info", description="事务测试", confidence=1.0
        ),
        metadata=AnalysisMetadata(
            model_provider="mock", model_name="mock", prompt_version="1.0"
        ),
    )


class SuccessfulAnalysisService:
    async def analyze_asset(self, _asset):
        return make_transaction_result()


class FailedAnalysisService:
    async def analyze_asset(self, _asset):
        raise RuntimeError("model failed")


def run_immediate(coroutine):
    """运行只等待立即完成 Fake 的协程，避免测试依赖平台事件循环。"""

    try:
        yielded = coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    coroutine.close()
    raise AssertionError(f"测试协程意外等待了异步对象: {yielded!r}")


def test_task_request_is_serializable_and_auditable() -> None:
    request = SingleIPTaskOrchestrator.build_task_request(
        "192.0.2.1", 3, True
    )
    assert request == {"ip": "192.0.2.1", "scan_round": 3, "save_result": True}


def test_result_record_kwargs_preserves_standard_result_and_metadata() -> None:
    result = AnalysisResult(
        analysis_id="a-1",
        ip="192.0.2.1",
        scan_round=1,
        scan_time=datetime(2026, 1, 1),
        summary=AnalysisSummary(
            risk_level="low",
            description="无明显风险",
            confidence=0.8,
        ),
        metadata=AnalysisMetadata(
            model_provider="mock",
            model_name="mock-model",
            prompt_version="1.0",
        ),
    )
    record = SingleIPTaskOrchestrator.result_record_kwargs(result, 9)
    assert record["task_item_id"] == 9
    assert record["result_json"]["analysis_id"] == "a-1"
    assert record["model_provider"] == "mock"


def test_execute_commits_running_and_success_transactions() -> None:
    task_repo = TransactionTaskRepository()
    orchestrator = SingleIPTaskOrchestrator(
        task_repository=task_repo,
        analysis_repository=TransactionAnalysisRepository(),
        data_provider=TransactionDataProvider(),
        analysis_service=SuccessfulAnalysisService(),
    )

    execution = run_immediate(orchestrator.execute("192.0.2.1"))

    assert execution.task_id == 10
    assert task_repo.commits == 2
    assert task_repo.rollbacks == 0
    assert task_repo.task_statuses == [TaskStatus.RUNNING, TaskStatus.SUCCESS]
    assert task_repo.item_statuses == [TaskStatus.RUNNING, TaskStatus.SUCCESS]


def test_execute_rolls_back_then_commits_failed_status() -> None:
    task_repo = TransactionTaskRepository()
    orchestrator = SingleIPTaskOrchestrator(
        task_repository=task_repo,
        analysis_repository=TransactionAnalysisRepository(),
        data_provider=TransactionDataProvider(),
        analysis_service=FailedAnalysisService(),
    )

    with pytest.raises(RuntimeError, match="model failed"):
        run_immediate(orchestrator.execute("192.0.2.1"))

    assert task_repo.commits == 2
    assert task_repo.rollbacks == 1
    assert task_repo.task_statuses == [TaskStatus.RUNNING, TaskStatus.FAILED]
    assert task_repo.item_statuses == [TaskStatus.RUNNING, TaskStatus.FAILED]


@pytest.mark.parametrize("provider,expected_conflict", [("mock", True), ("deepseek", False)])
def test_cached_results_require_matching_model(provider, expected_conflict):
    cached = SimpleNamespace(model_provider=provider, model_name="test-model", prompt_version="1.0")

    class CachedRepository:
        async def get_cached_result(self, **kwargs):
            return cached

    service = SimpleNamespace(model_provider=SimpleNamespace(info=ModelInfo("deepseek", "test-model")),
                              prompt_version="1.0")
    task_repo = TransactionTaskRepository()
    orchestrator = SingleIPTaskOrchestrator(task_repository=task_repo,
        analysis_repository=CachedRepository(), data_provider=TransactionDataProvider(),
        analysis_service=service)
    if expected_conflict:
        with pytest.raises(CachedModelConflictError):
            run_immediate(orchestrator.execute("192.0.2.1"))
    else:
        execution = run_immediate(orchestrator.execute("192.0.2.1"))
        assert execution.reused and execution.result is cached
    assert task_repo.commits == 0
