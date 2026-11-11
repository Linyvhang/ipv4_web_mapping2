"""单 IP 分析任务的创建、执行、状态流转和结果持久化。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from agent_service.db.models import AgentAnalysisResult, TaskStatus, TaskType
from agent_service.db.repositories import AgentAnalysisRepository, AgentTaskRepository
from agent_service.models.analysis_schema import AnalysisResult
from agent_service.models.input_schema import AssetAnalysisInput
from agent_service.services.ip_analysis import (
    AssetNotFoundError,
    SingleIPAnalysisService,
    ipv4_to_uint32,
)


class CachedModelConflictError(ValueError):
    """现有结果与当前模型配置不一致，不能静默复用或覆盖。"""


@dataclass(frozen=True)
class SingleIPExecution:
    """一次编排执行的返回值；reused 表示命中了已有分析结果。"""

    task_id: int | None
    task_item_id: int | None
    reused: bool
    result: AnalysisResult | AgentAnalysisResult


class SingleIPTaskOrchestrator:
    """连接任务 Repository、L3 数据层和单 IP 分析 Service。"""

    def __init__(
        self,
        *,
        task_repository: AgentTaskRepository,
        analysis_repository: AgentAnalysisRepository,
        data_provider: Any,
        analysis_service: SingleIPAnalysisService,
    ) -> None:
        self.task_repository = task_repository
        self.analysis_repository = analysis_repository
        self.data_provider = data_provider
        self.analysis_service = analysis_service

    @staticmethod
    def build_task_request(ip: str, scan_round: int | None, save_result: bool) -> dict:
        """生成可审计的任务请求快照，不包含秘密或模型调用信息。"""

        return {"ip": ip, "scan_round": scan_round, "save_result": save_result}

    @staticmethod
    def result_record_kwargs(result: AnalysisResult, task_item_id: int) -> dict:
        """将标准结果转换成 Analysis Repository 所需的字段。"""

        metadata = result.metadata
        return {
            "analysis_id": result.analysis_id,
            "task_item_id": task_item_id,
            "ip": result.ip,
            "scan_round": result.scan_round,
            "schema_version": result.schema_version,
            "result_json": result.model_dump(mode="json"),
            "model_provider": metadata.model_provider,
            "model_name": metadata.model_name,
            "model_version": metadata.model_version,
            "prompt_version": metadata.prompt_version,
        }

    async def execute(
        self,
        ip: str,
        *,
        scan_round: int | None = None,
        save_result: bool = True,
    ) -> SingleIPExecution:
        """执行一次单 IP 分析；相同 IP/扫描轮次已有结果时直接复用。"""

        asset = await self.load_asset(ip, scan_round=scan_round)
        cached_execution = await self.get_cached_execution(asset)
        if cached_execution is not None:
            return cached_execution

        task_id, item_id = await self.start_task(
            asset,
            requested_ip=ip,
            requested_scan_round=scan_round,
            save_result=save_result,
        )
        try:
            result = await self.analyze_asset(asset)
            return await self.complete_task(
                task_id=task_id,
                item_id=item_id,
                result=result,
                save_result=save_result,
            )
        except Exception as exc:
            await self.fail_task(task_id=task_id, item_id=item_id, error=exc)
            raise

    async def start_task(
        self,
        asset: AssetAnalysisInput,
        *,
        requested_ip: str,
        requested_scan_round: int | None,
        save_result: bool,
    ) -> tuple[int, int]:
        """创建任务和任务条目，并持久化 running 状态。"""

        task = await self.task_repository.create_task(
            task_type=TaskType.IP_ANALYSIS,
            target_count=1,
            save_result=save_result,
            request_json=self.build_task_request(
                requested_ip, requested_scan_round, save_result
            ),
        )
        items = await self.task_repository.create_items(
            task_id=task.id, targets=[(asset.ip, asset.scan_round)]
        )
        item = items[0]
        started_at = datetime.utcnow()
        await self.task_repository.update_task_status(
            task.id, TaskStatus.RUNNING, started_at=started_at
        )
        await self.task_repository.update_item_status(
            item.id, TaskStatus.RUNNING, started_at=started_at
        )
        # 先持久化任务和 running 状态。模型调用失败时仍能保留可追踪的任务。
        await self.task_repository.commit()
        return task.id, item.id

    async def analyze_asset(
        self,
        asset: AssetAnalysisInput,
        validation_errors: list[str] | tuple[str, ...] | None = None,
    ) -> AnalysisResult:
        """调用单 IP 分析 Service，不重复查询扫描数据。"""

        if validation_errors:
            return await self.analysis_service.analyze_asset(asset, validation_errors)
        return await self.analysis_service.analyze_asset(asset)

    async def complete_task(
        self,
        *,
        task_id: int,
        item_id: int,
        result: AnalysisResult,
        save_result: bool,
    ) -> SingleIPExecution:
        """按保存策略持久化结果，并完成任务状态。"""

        returned: AnalysisResult | AgentAnalysisResult = result
        if save_result:
            returned = await self.analysis_repository.create_result(
                **self.result_record_kwargs(result, item_id)
            )
        completed_at = datetime.utcnow()
        await self.task_repository.update_item_status(
            item_id, TaskStatus.SUCCESS, completed_at=completed_at
        )
        await self.task_repository.update_task_status(
            task_id, TaskStatus.SUCCESS, completed_at=completed_at
        )
        # Task、Item 和 AnalysisRepository 共用同一个 Session；一次提交即可
        # 原子地保存分析结果和最终成功状态。
        await self.task_repository.commit()
        return SingleIPExecution(task_id, item_id, False, returned)

    async def fail_task(
        self,
        *,
        task_id: int,
        item_id: int,
        error: Exception,
    ) -> None:
        """回滚失败事务并单独保存失败状态。"""

        await self.task_repository.rollback()
        completed_at = datetime.utcnow()
        await self.task_repository.update_item_status(
            item_id,
            TaskStatus.FAILED,
            error_message=str(error),
            completed_at=completed_at,
        )
        await self.task_repository.update_task_status(
            task_id,
            TaskStatus.FAILED,
            error_message=str(error),
            completed_at=completed_at,
        )
        await self.task_repository.commit()

    async def load_asset(
        self,
        ip: str,
        *,
        scan_round: int | None = None,
    ) -> AssetAnalysisInput:
        """校验 IP 并读取指定批次或最近一次扫描资产。"""

        asset = await self.data_provider.fetch_asset(
            ip_value=ipv4_to_uint32(ip), scan_round=scan_round
        )
        if asset is None:
            raise AssetNotFoundError(f"未找到 IP {ip} 的扫描数据")
        return asset

    async def get_cached_execution(
        self,
        asset: AssetAnalysisInput,
    ) -> SingleIPExecution | None:
        """返回模型配置一致的缓存结果；没有缓存时返回 ``None``。"""

        cached = await self.analysis_repository.get_cached_result(
            ip=asset.ip, scan_round=asset.scan_round
        )
        if cached is None:
            return None

        info = self.analysis_service.model_provider.info
        if (
            cached.model_provider != info.provider
            or cached.model_name != info.name
            or cached.prompt_version != self.analysis_service.prompt_version
        ):
            raise CachedModelConflictError(
                "该 IP/扫描批次已有其他模型或 Prompt 的结果。当前数据库仅允许一份结果，"
                "请选择尚未分析的 IP；历史结果已保留。"
            )
        return SingleIPExecution(None, None, True, cached)
