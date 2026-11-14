"""有限批量 IP 分析路由。"""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, HTTPException, status

from agent_service.services.batch_analysis import (
    BatchAnalysisService,
    BatchAssetsNotFoundError,
)
from agent_service.services.ip_analysis import UnsupportedAddressError

from .batch_schemas import BatchAnalysisRequest, BatchAnalysisResponse


def create_batch_analysis_router(service: BatchAnalysisService) -> APIRouter:
    router = APIRouter(prefix="/analysis", tags=["analysis"])

    @router.post(
        "/batch",
        response_model=BatchAnalysisResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def analyze_batch(
        request: BatchAnalysisRequest, background_tasks: BackgroundTasks
    ) -> BatchAnalysisResponse:
        try:
            submission = await service.create_batch(
                [str(ip) for ip in request.ips], scan_round=request.scan_round
            )
        except BatchAssetsNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "message": "部分 IP 未找到扫描数据，未创建批量任务",
                    "missing_ips": exc.missing_ips,
                },
            ) from exc
        except (ValueError, UnsupportedAddressError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc

        background_tasks.add_task(service.run_batch, submission)
        return BatchAnalysisResponse(
            task_id=submission.task_id,
            status="pending",
            target_count=len(submission.items),
            targets=submission.targets,
        )

    return router
