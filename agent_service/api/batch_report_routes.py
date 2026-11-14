"""批量统计 JSON 报告接口。"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from agent_service.models.batch_report_schema import SavedBatchReportResponse
from agent_service.services.batch_report import (
    BatchReportNotFoundError,
    BatchReportService,
    BatchReportTaskNotCompletedError,
    BatchReportTaskNotFoundError,
    BatchReportTaskTypeError,
)


def create_batch_report_router(service: BatchReportService) -> APIRouter:
    router = APIRouter(prefix="/analysis/tasks", tags=["reports"])

    @router.post("/{task_id}/report", response_model=SavedBatchReportResponse)
    async def generate_batch_report(task_id: int) -> SavedBatchReportResponse:
        try:
            return await service.generate_report(task_id)
        except BatchReportTaskNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except BatchReportTaskTypeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except BatchReportTaskNotCompletedError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=str(exc)
            ) from exc

    @router.get("/{task_id}/report", response_model=SavedBatchReportResponse)
    async def get_batch_report(task_id: int) -> SavedBatchReportResponse:
        try:
            return await service.get_report(task_id)
        except BatchReportNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    return router
