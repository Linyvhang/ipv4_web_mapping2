"""供可视化模块读取扫描事实和已保存分析结果的接口。"""

from __future__ import annotations

from ipaddress import IPv4Address

from fastapi import APIRouter, HTTPException, Query, status

from agent_service.models.analysis_schema import AnalysisResult
from agent_service.services.ip_analysis import AssetNotFoundError
from agent_service.services.task_orchestrator import SingleIPTaskOrchestrator

from .asset_schemas import AssetScanDataResponse, SavedAnalysisResponse


def create_asset_router(orchestrator: SingleIPTaskOrchestrator) -> APIRouter:
    """创建不调用模型、不触发扫描的只读资产路由。"""

    router = APIRouter(prefix="/assets", tags=["assets"])

    @router.get("/{ip}/scan-data", response_model=AssetScanDataResponse)
    async def get_scan_data(
        ip: IPv4Address,
        scan_round: int | None = Query(default=None, ge=1),
    ) -> AssetScanDataResponse:
        try:
            asset = await orchestrator.load_asset(str(ip), scan_round=scan_round)
        except AssetNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        return AssetScanDataResponse.model_validate(asset.model_dump(mode="python"))

    @router.get("/{ip}/analysis", response_model=SavedAnalysisResponse)
    async def get_saved_analysis(
        ip: IPv4Address,
        scan_round: int | None = Query(default=None, ge=1),
    ) -> SavedAnalysisResponse:
        try:
            asset = await orchestrator.load_asset(str(ip), scan_round=scan_round)
        except AssetNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        record = await orchestrator.analysis_repository.get_cached_result(
            ip=asset.ip, scan_round=asset.scan_round
        )
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"IP {asset.ip} 的扫描批次 {asset.scan_round} 尚无已保存分析结果",
            )
        return SavedAnalysisResponse(
            analysis_id=record.analysis_id,
            ip=record.ip,
            scan_round=record.scan_round,
            result=AnalysisResult.model_validate(record.result_json),
            created_at=record.created_at,
            updated_at=record.updated_at,
        )

    return router
