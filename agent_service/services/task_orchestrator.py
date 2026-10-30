"""单 IP 分析任务的创建、执行、状态流转和结果持久化。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from agent_service.db.models import AgentAnalysisResult, TaskStatus, TaskType
from agent_service.db.repositories import AgentAnalysisRepository, AgentTaskRepository
from agent_service.models.analysis_schema import AnalysisResult
from agent_service.services.ip_analysis import (
    AssetNotFoundError,
    SingleIPAnalysisService,
    ipv4_to_uint32,
)


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

        ip_value = ipv4_to_uint32(ip)
        asset = await self.data_provider.fetch_asset(
            ip_value=ip_value, scan_round=scan_round
        )
        if asset is None:
            raise AssetNotFoundError(f"未找到 IP {ip} 的扫描数据")

        cached = await self.analysis_repository.get_cached_result(
            ip=asset.ip, scan_round=asset.scan_round
        )
        if cached is not None:
            return SingleIPExecution(None, None, True, cached)

        task = await self.task_repository.create_task(
            task_type=TaskType.IP_ANALYSIS,
            target_count=1,
            save_result=save_result,
            request_json=self.build_task_request(ip, scan_round, save_result),
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
        try:
            result = await self.analysis_service.analyze_asset(asset)
            returned: AnalysisResult | AgentAnalysisResult = result
            if save_result:
                returned = await self.analysis_repository.create_result(
                    **self.result_record_kwargs(result, item.id)
                )
            completed_at = datetime.utcnow()
            await self.task_repository.update_item_status(
                item.id, TaskStatus.SUCCESS, completed_at=completed_at
            )
            await self.task_repository.update_task_status(
                task.id, TaskStatus.SUCCESS, completed_at=completed_at
            )
            return SingleIPExecution(task.id, item.id, False, returned)
        except Exception as exc:
            completed_at = datetime.utcnow()
            await self.task_repository.update_item_status(
                item.id,
                TaskStatus.FAILED,
                error_message=str(exc),
                completed_at=completed_at,
            )
            await self.task_repository.update_task_status(
                task.id,
                TaskStatus.FAILED,
                error_message=str(exc),
                completed_at=completed_at,
            )
            raise
