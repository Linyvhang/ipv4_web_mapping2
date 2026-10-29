"""Agent 数据访问层。

Repository 只负责数据库读写，不负责调用模型、执行业务编排或提供 HTTP API。
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    AgentAnalysisResult,
    AgentReport,
    AgentTask,
    AgentTaskItem,
    ReportFormat,
    ReportType,
    TaskStatus,
    TaskType,
)


class AgentTaskRepository:
    """父任务和 IP 子任务的数据访问。"""

    def __init__(self, session: AsyncSession):
        self.session = session

    @staticmethod
    def build_task_query(task_id: int):
        return select(AgentTask).where(AgentTask.id == task_id)

    @staticmethod
    def build_item_query(item_id: int):
        return select(AgentTaskItem).where(AgentTaskItem.id == item_id)

    @staticmethod
    def build_update_task_status(
        task_id: int,
        status: TaskStatus,
        *,
        error_message: str | None = None,
        completed_at: datetime | None = None,
        cancelled_at: datetime | None = None,
    ):
        values: dict[str, object] = {"status": status}
        if error_message is not None:
            values["error_message"] = error_message
        if completed_at is not None:
            values["completed_at"] = completed_at
        if cancelled_at is not None:
            values["cancelled_at"] = cancelled_at
        return update(AgentTask).where(AgentTask.id == task_id).values(**values)

    @staticmethod
    def build_update_item_status(
        item_id: int,
        status: TaskStatus,
        *,
        error_message: str | None = None,
        completed_at: datetime | None = None,
    ):
        values: dict[str, object] = {"status": status}
        if error_message is not None:
            values["error_message"] = error_message
        if completed_at is not None:
            values["completed_at"] = completed_at
        return update(AgentTaskItem).where(AgentTaskItem.id == item_id).values(**values)

    async def create_task(
        self,
        *,
        task_type: TaskType,
        target_count: int = 0,
        save_result: bool = True,
        request_json: dict | None = None,
    ) -> AgentTask:
        task = AgentTask(
            task_type=task_type,
            status=TaskStatus.PENDING,
            target_count=target_count,
            save_result=save_result,
            request_json=request_json,
        )
        self.session.add(task)
        await self.session.flush()
        return task

    async def create_items(
        self,
        *,
        task_id: int,
        targets: Iterable[tuple[str, int]],
    ) -> list[AgentTaskItem]:
        items = [
            AgentTaskItem(task_id=task_id, ip=ip, scan_round=scan_round)
            for ip, scan_round in targets
        ]
        self.session.add_all(items)
        await self.session.flush()
        return items

    async def get_task(self, task_id: int) -> AgentTask | None:
        result = await self.session.execute(self.build_task_query(task_id))
        return result.scalar_one_or_none()

    async def get_item(self, item_id: int) -> AgentTaskItem | None:
        result = await self.session.execute(self.build_item_query(item_id))
        return result.scalar_one_or_none()

    async def update_task_status(
        self,
        task_id: int,
        status: TaskStatus,
        *,
        error_message: str | None = None,
        completed_at: datetime | None = None,
        cancelled_at: datetime | None = None,
    ) -> None:
        await self.session.execute(
            self.build_update_task_status(
                task_id,
                status,
                error_message=error_message,
                completed_at=completed_at,
                cancelled_at=cancelled_at,
            )
        )

    async def update_item_status(
        self,
        item_id: int,
        status: TaskStatus,
        *,
        error_message: str | None = None,
        completed_at: datetime | None = None,
    ) -> None:
        await self.session.execute(
            self.build_update_item_status(
                item_id,
                status,
                error_message=error_message,
                completed_at=completed_at,
            )
        )


class AgentAnalysisRepository:
    """标准分析结果的数据访问和结果复用查询。"""

    def __init__(self, session: AsyncSession):
        self.session = session

    @staticmethod
    def build_cached_result_query(ip: str, scan_round: int):
        return select(AgentAnalysisResult).where(
            AgentAnalysisResult.ip == ip,
            AgentAnalysisResult.scan_round == scan_round,
        )

    @staticmethod
    def build_analysis_id_query(analysis_id: str):
        return select(AgentAnalysisResult).where(
            AgentAnalysisResult.analysis_id == analysis_id
        )

    async def get_cached_result(
        self,
        *,
        ip: str,
        scan_round: int,
    ) -> AgentAnalysisResult | None:
        result = await self.session.execute(
            self.build_cached_result_query(ip, scan_round)
        )
        return result.scalar_one_or_none()

    async def create_result(
        self,
        *,
        analysis_id: str,
        task_item_id: int,
        ip: str,
        scan_round: int,
        schema_version: str,
        result_json: dict,
        model_provider: str,
        model_name: str,
        model_version: str | None,
        prompt_version: str,
    ) -> AgentAnalysisResult:
        result = AgentAnalysisResult(
            analysis_id=analysis_id,
            task_item_id=task_item_id,
            ip=ip,
            scan_round=scan_round,
            schema_version=schema_version,
            result_json=result_json,
            model_provider=model_provider,
            model_name=model_name,
            model_version=model_version,
            prompt_version=prompt_version,
        )
        self.session.add(result)
        await self.session.flush()
        return result

    async def get_by_analysis_id(self, analysis_id: str) -> AgentAnalysisResult | None:
        result = await self.session.execute(self.build_analysis_id_query(analysis_id))
        return result.scalar_one_or_none()


class AgentReportRepository:
    """IP 报告和批量汇总报告的数据访问。"""

    def __init__(self, session: AsyncSession):
        self.session = session

    @staticmethod
    def build_report_query(report_id: int):
        return select(AgentReport).where(AgentReport.id == report_id)

    async def create_report(
        self,
        *,
        task_id: int,
        report_type: ReportType,
        report_format: ReportFormat,
        task_item_id: int | None = None,
        analysis_result_id: int | None = None,
        content_json: dict | None = None,
        content_text: str | None = None,
    ) -> AgentReport:
        report = AgentReport(
            task_id=task_id,
            task_item_id=task_item_id,
            analysis_result_id=analysis_result_id,
            report_type=report_type,
            report_format=report_format,
            content_json=content_json,
            content_text=content_text,
        )
        self.session.add(report)
        await self.session.flush()
        return report

    async def get_report(self, report_id: int) -> AgentReport | None:
        result = await self.session.execute(self.build_report_query(report_id))
        return result.scalar_one_or_none()

