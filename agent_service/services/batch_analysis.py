"""有限批量 IP 分析编排。

批量任务只读取已有扫描数据。每个子任务使用独立数据库 Session，并通过信号量
限制并发，避免 SQLAlchemy AsyncSession 被多个协程共享。
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from collections.abc import Callable
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agent_service.db.l3_data import L3DataProvider
from agent_service.db.models import TaskStatus, TaskType
from agent_service.db.repositories import AgentAnalysisRepository, AgentTaskRepository
from agent_service.models.analysis_schema import AnalysisResult
from agent_service.models.input_schema import AssetAnalysisInput
from agent_service.providers.base import ModelProvider
from agent_service.services.analysis_validation import (
    build_safe_fallback_result,
    validate_analysis_result,
)
from agent_service.services.ip_analysis import (
    AssetNotFoundError,
    SingleIPAnalysisService,
    ipv4_to_uint32,
)
from agent_service.services.task_orchestrator import (
    CachedModelConflictError,
    SingleIPTaskOrchestrator,
)


class BatchAssetsNotFoundError(LookupError):
    """预检发现一个或多个 IP 没有扫描数据。"""

    def __init__(self, missing_ips: list[str]) -> None:
        self.missing_ips = missing_ips
        super().__init__("以下 IP 未找到扫描数据: " + ", ".join(missing_ips))


@dataclass(frozen=True)
class BatchWorkItem:
    item_id: int
    asset: AssetAnalysisInput


@dataclass(frozen=True)
class BatchSubmission:
    task_id: int
    items: tuple[BatchWorkItem, ...]

    @property
    def targets(self) -> list[dict[str, object]]:
        return [
            {"ip": item.asset.ip, "scan_round": item.asset.scan_round}
            for item in self.items
        ]


class BatchAnalysisService:
    """创建批量任务，并在后台并发分析其中的 IP。"""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        model_provider: ModelProvider,
        max_concurrency: int = 3,
        max_ips: int = 50,
        prompt_version: str = "1.0",
        data_provider_factory: Callable[[Any], Any] = L3DataProvider,
        task_repository_factory: Callable[[Any], Any] = AgentTaskRepository,
        analysis_repository_factory: Callable[[Any], Any] = AgentAnalysisRepository,
    ) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency 必须至少为 1")
        if max_ips < 2:
            raise ValueError("max_ips 必须至少为 2")
        self.session_factory = session_factory
        self.model_provider = model_provider
        self.max_concurrency = max_concurrency
        self.max_ips = max_ips
        self.prompt_version = prompt_version
        self.data_provider_factory = data_provider_factory
        self.task_repository_factory = task_repository_factory
        self.analysis_repository_factory = analysis_repository_factory

    async def create_batch(
        self, ips: list[str], *, scan_round: int | None = None
    ) -> BatchSubmission:
        """预检全部 IP；全部存在时才创建父任务和子任务。"""

        unique_ips = list(dict.fromkeys(ips))
        if len(unique_ips) < 2:
            raise ValueError("批量分析去重后至少需要 2 个 IP")
        if len(unique_ips) > self.max_ips:
            raise ValueError(f"批量分析最多允许 {self.max_ips} 个 IP")

        async with self.session_factory() as session:
            provider = self.data_provider_factory(session)
            assets: list[AssetAnalysisInput] = []
            missing: list[str] = []
            for ip in unique_ips:
                asset = await provider.fetch_asset(
                    ip_value=ipv4_to_uint32(ip), scan_round=scan_round
                )
                if asset is None:
                    missing.append(ip)
                else:
                    assets.append(asset)
            if missing:
                raise BatchAssetsNotFoundError(missing)

            repository = self.task_repository_factory(session)
            task = await repository.create_task(
                task_type=TaskType.BATCH_ANALYSIS,
                target_count=len(assets),
                save_result=True,
                request_json={
                    "ips": unique_ips,
                    "scan_round": scan_round,
                    "save_result": True,
                },
            )
            rows = await repository.create_items(
                task_id=task.id,
                targets=[(asset.ip, asset.scan_round) for asset in assets],
            )
            await repository.commit()
            return BatchSubmission(
                task_id=task.id,
                items=tuple(
                    BatchWorkItem(item_id=row.id, asset=asset)
                    for row, asset in zip(rows, assets, strict=True)
                ),
            )

    async def run_batch(self, submission: BatchSubmission) -> None:
        """后台执行批量任务；单项失败不会中断其他项。"""

        try:
            await self._start_parent(submission.task_id)
            semaphore = asyncio.Semaphore(self.max_concurrency)

            async def guarded(item: BatchWorkItem) -> bool:
                async with semaphore:
                    return await self._run_item(item)

            outcomes = await asyncio.gather(
                *(guarded(item) for item in submission.items),
                return_exceptions=True,
            )
            failed = sum(outcome is False or isinstance(outcome, BaseException) for outcome in outcomes)
            await self._finish_parent(
                submission.task_id,
                completed=len(outcomes),
                failed=failed,
            )
        except Exception as exc:  # 父任务级故障，不能留在 running
            await self._fail_parent(submission.task_id, exc)

    async def _start_parent(self, task_id: int) -> None:
        async with self.session_factory() as session:
            repository = self.task_repository_factory(session)
            await repository.update_task_status(
                task_id, TaskStatus.RUNNING, started_at=datetime.utcnow()
            )
            await repository.commit()

    async def _run_item(self, work: BatchWorkItem) -> bool:
        async with self.session_factory() as session:
            task_repository = self.task_repository_factory(session)
            analysis_repository = self.analysis_repository_factory(session)
            data_provider = self.data_provider_factory(session)
            analysis_service = SingleIPAnalysisService(
                data_provider=data_provider,
                model_provider=self.model_provider,
                prompt_version=self.prompt_version,
            )
            orchestrator = SingleIPTaskOrchestrator(
                task_repository=task_repository,
                analysis_repository=analysis_repository,
                data_provider=data_provider,
                analysis_service=analysis_service,
            )
            try:
                await task_repository.update_item_status(
                    work.item_id, TaskStatus.RUNNING, started_at=datetime.utcnow()
                )
                await task_repository.commit()

                cached = await orchestrator.get_cached_execution(work.asset)
                if cached is None:
                    result = await self._analyze_with_validation(orchestrator, work.asset)
                    await analysis_repository.create_result(
                        **orchestrator.result_record_kwargs(result, work.item_id)
                    )
                await task_repository.update_item_status(
                    work.item_id,
                    TaskStatus.SUCCESS,
                    completed_at=datetime.utcnow(),
                )
                await task_repository.commit()
                return True
            except Exception as exc:
                await task_repository.rollback()
                await task_repository.update_item_status(
                    work.item_id,
                    TaskStatus.FAILED,
                    error_message=str(exc),
                    completed_at=datetime.utcnow(),
                )
                await task_repository.commit()
                return False

    async def _analyze_with_validation(
        self,
        orchestrator: SingleIPTaskOrchestrator,
        asset: AssetAnalysisInput,
    ) -> AnalysisResult:
        result = await orchestrator.analyze_asset(asset)
        validation = validate_analysis_result(result, asset)
        if not validation.errors:
            return result
        retry = await orchestrator.analyze_asset(asset, list(validation.errors))
        retry_validation = validate_analysis_result(retry, asset)
        if not retry_validation.errors:
            return retry
        return build_safe_fallback_result(retry, retry_validation.errors)

    async def _finish_parent(self, task_id: int, *, completed: int, failed: int) -> None:
        async with self.session_factory() as session:
            repository = self.task_repository_factory(session)
            await repository.update_task_progress(
                task_id,
                completed_count=completed,
                failed_count=failed,
                summary_json={
                    "completed": completed,
                    "success": completed - failed,
                    "failed": failed,
                },
            )
            await repository.update_task_status(
                task_id, TaskStatus.SUCCESS, completed_at=datetime.utcnow()
            )
            await repository.commit()

    async def _fail_parent(self, task_id: int, error: Exception) -> None:
        async with self.session_factory() as session:
            repository = self.task_repository_factory(session)
            await repository.update_task_status(
                task_id,
                TaskStatus.FAILED,
                error_message=str(error),
                completed_at=datetime.utcnow(),
            )
            await repository.commit()
