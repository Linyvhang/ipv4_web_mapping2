"""分析任务状态和保存结果查询接口。"""

from __future__ import annotations

from contextlib import asynccontextmanager
from enum import Enum
from typing import Any

from fastapi import APIRouter, HTTPException, status

from agent_service.db.models import TaskStatus
from agent_service.db.repositories import AgentAnalysisRepository, AgentTaskRepository
from agent_service.models.analysis_schema import AnalysisResult
from agent_service.services.task_orchestrator import SingleIPTaskOrchestrator

from .asset_schemas import (
    TaskItemStatusResponse,
    TaskResultItemResponse,
    TaskResultResponse,
    TaskStatusResponse,
)


def _value(value):
    return value.value if isinstance(value, Enum) else str(value)


async def _load_task(task_repository: Any, task_id: int):
    task = await task_repository.get_task(task_id)
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"未找到分析任务 {task_id}",
        )
    items = await task_repository.get_task_items(task_id)
    return task, items


@asynccontextmanager
async def _query_repositories(orchestrator, session_factory=None):
    """查询接口使用短生命周期 Session，避免 MySQL 旧事务快照。"""

    if session_factory is None:
        yield orchestrator.task_repository, orchestrator.analysis_repository
        return
    async with session_factory() as session:
        yield AgentTaskRepository(session), AgentAnalysisRepository(session)


def create_task_query_router(
    orchestrator: SingleIPTaskOrchestrator,
    *,
    session_factory: Any | None = None,
) -> APIRouter:
    """创建只读取既有任务与结果的路由。"""

    router = APIRouter(prefix="/analysis/tasks", tags=["tasks"])

    @router.get("/{task_id}", response_model=TaskStatusResponse)
    async def get_task_status(task_id: int) -> TaskStatusResponse:
        async with _query_repositories(orchestrator, session_factory) as repositories:
            task_repository, _analysis_repository = repositories
            task, items = await _load_task(task_repository, task_id)
            counts = {name: 0 for name in TaskStatus._value2member_map_}
            item_responses = []
            for item in items:
                item_status = _value(item.status)
                counts[item_status] += 1
                item_responses.append(
                    TaskItemStatusResponse(
                        task_item_id=item.id,
                        ip=item.ip,
                        scan_round=item.scan_round,
                        status=item_status,
                        error_message=item.error_message,
                        created_at=item.created_at,
                        started_at=item.started_at,
                        completed_at=item.completed_at,
                    )
                )
            return TaskStatusResponse(
                task_id=task.id,
                task_type=_value(task.task_type),
                status=_value(task.status),
                save_result=task.save_result,
                total=max(task.target_count, len(items)),
                pending=counts["pending"],
                running=counts["running"],
                success=counts["success"],
                failed=counts["failed"],
                cancelled=counts["cancelled"],
                error_message=task.error_message,
                created_at=task.created_at,
                started_at=task.started_at,
                completed_at=task.completed_at,
                items=item_responses,
            )

    @router.get("/{task_id}/result", response_model=TaskResultResponse)
    async def get_task_result(task_id: int) -> TaskResultResponse:
        async with _query_repositories(orchestrator, session_factory) as repositories:
            task_repository, analysis_repository = repositories
            task, items = await _load_task(task_repository, task_id)
            task_status = _value(task.status)
            if task_status in {"pending", "running"}:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"分析任务 {task_id} 尚未完成，当前状态为 {task_status}",
                )
            records = await analysis_repository.get_by_task_item_ids(
                item.id for item in items
            )
            by_item = {record.task_item_id: record for record in records}
            result_items = []
            for item in items:
                record = by_item.get(item.id)
                # 批量任务命中缓存时，新子任务不会重复写入唯一的分析结果；
                # 按 IP 和扫描批次回查即可把原结果返回给可视化模块。
                if record is None and _value(item.status) == "success":
                    record = await analysis_repository.get_cached_result(
                        ip=item.ip, scan_round=item.scan_round
                    )
                result_items.append(
                    TaskResultItemResponse(
                        task_item_id=item.id,
                        ip=item.ip,
                        scan_round=item.scan_round,
                        status=_value(item.status),
                        error_message=item.error_message,
                        result=(
                            AnalysisResult.model_validate(record.result_json)
                            if record is not None
                            else None
                        ),
                    )
                )
            return TaskResultResponse(
                task_id=task.id,
                task_type=_value(task.task_type),
                status=task_status,
                error_message=task.error_message,
                items=result_items,
            )

    return router
