import asyncio
from datetime import datetime
from ipaddress import IPv4Address

import pytest

from agent_service.api.mock_app import (
    MockAnalysisRepository,
    MockL3DataProvider,
    MockTaskRepository,
    _MockSessionFactory,
)
from agent_service.db.models import TaskStatus
from agent_service.models.analysis_schema import ModelAnalysisPayload
from agent_service.models.input_schema import AssetAnalysisInput
from agent_service.providers.base import ModelInfo, ModelProviderError
from agent_service.services.batch_analysis import (
    BatchAnalysisService,
    BatchAssetsNotFoundError,
)


class TrackingProvider:
    def __init__(self, *, fail_ip: str | None = None) -> None:
        self._info = ModelInfo("test", "tracking-model", "1")
        self.fail_ip = fail_ip
        self.calls = 0
        self.active = 0
        self.max_active = 0

    @property
    def info(self):
        return self._info

    async def generate_structured(self, prompt, output_model):
        self.calls += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(0.01)
            if self.fail_ip and f'"ip": "{self.fail_ip}"' in prompt:
                raise ModelProviderError("模拟单项模型失败")
            return output_model.model_validate(
                {
                    "summary": {
                        "risk_level": "info",
                        "description": "批量 Mock 结果",
                        "confidence": 0.5,
                    }
                }
            )
        finally:
            self.active -= 1


class SelectiveDataProvider(MockL3DataProvider):
    def __init__(self, missing: set[str] | None = None) -> None:
        self.missing = missing or set()

    async def fetch_asset(self, *, ip_value: int, scan_round: int | None = None):
        ip = str(IPv4Address(ip_value))
        if ip in self.missing:
            return None
        return await super().fetch_asset(ip_value=ip_value, scan_round=scan_round)


def build_service(*, provider=None, data_provider=None, concurrency=3):
    task_repository = MockTaskRepository()
    analysis_repository = MockAnalysisRepository()
    data_provider = data_provider or SelectiveDataProvider()
    provider = provider or TrackingProvider()
    service = BatchAnalysisService(
        session_factory=_MockSessionFactory(),
        model_provider=provider,
        max_concurrency=concurrency,
        data_provider_factory=lambda _session: data_provider,
        task_repository_factory=lambda _session: task_repository,
        analysis_repository_factory=lambda _session: analysis_repository,
    )
    return service, task_repository, analysis_repository, provider


@pytest.mark.asyncio
async def test_batch_deduplicates_targets_and_limits_concurrency():
    service, tasks, _results, provider = build_service(concurrency=2)
    submission = await service.create_batch(
        ["192.0.2.1", "192.0.2.2", "192.0.2.1", "192.0.2.3"]
    )

    await service.run_batch(submission)

    assert [target["ip"] for target in submission.targets] == [
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.3",
    ]
    assert provider.max_active == 2
    assert tasks.tasks[submission.task_id].status == TaskStatus.SUCCESS
    assert tasks.tasks[submission.task_id].completed_count == 3
    assert tasks.tasks[submission.task_id].failed_count == 0


@pytest.mark.asyncio
async def test_preflight_rejects_entire_batch_when_any_asset_is_missing():
    service, tasks, _results, _provider = build_service(
        data_provider=SelectiveDataProvider({"192.0.2.2"})
    )

    with pytest.raises(BatchAssetsNotFoundError) as error:
        await service.create_batch(["192.0.2.1", "192.0.2.2"])

    assert error.value.missing_ips == ["192.0.2.2"]
    assert tasks.tasks == {}


@pytest.mark.asyncio
async def test_single_item_failure_does_not_stop_other_items():
    service, tasks, _results, _provider = build_service(
        provider=TrackingProvider(fail_ip="192.0.2.2")
    )
    submission = await service.create_batch(
        ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    )

    await service.run_batch(submission)

    statuses = [tasks.items[item.item_id].status for item in submission.items]
    assert statuses == [TaskStatus.SUCCESS, TaskStatus.FAILED, TaskStatus.SUCCESS]
    parent = tasks.tasks[submission.task_id]
    assert parent.status == TaskStatus.SUCCESS
    assert parent.failed_count == 1


@pytest.mark.asyncio
async def test_cached_result_is_reused_without_another_model_call():
    service, _tasks, _results, provider = build_service()
    first = await service.create_batch(["192.0.2.1", "192.0.2.2"])
    await service.run_batch(first)
    calls_after_first = provider.calls

    second = await service.create_batch(["192.0.2.1", "192.0.2.2"])
    await service.run_batch(second)

    assert provider.calls == calls_after_first


@pytest.mark.asyncio
async def test_batch_size_is_checked_after_deduplication():
    service, *_ = build_service()

    with pytest.raises(ValueError, match="去重后至少需要 2 个 IP"):
        await service.create_batch(["192.0.2.1", "192.0.2.1"])
