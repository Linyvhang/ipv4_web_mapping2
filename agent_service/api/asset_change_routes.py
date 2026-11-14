"""单 IP 跨扫描批次变化查询接口。"""

from __future__ import annotations

from ipaddress import IPv4Address

from fastapi import APIRouter, HTTPException, Query

from agent_service.models.asset_change_schema import AssetChangeResponse
from agent_service.services.asset_change import (
    AssetChangeService,
    ComparedAssetNotFoundError,
    InvalidScanRoundComparisonError,
    ScanRoundNotFoundError,
)


def create_asset_change_router(service: AssetChangeService) -> APIRouter:
    router = APIRouter(prefix="/assets", tags=["assets"])

    @router.get("/{ip}/changes", response_model=AssetChangeResponse)
    async def compare_asset_changes(
        ip: IPv4Address,
        from_scan_round: int = Query(ge=1),
        to_scan_round: int = Query(ge=1),
    ) -> AssetChangeResponse:
        try:
            return await service.compare(
                str(ip),
                from_scan_round=from_scan_round,
                to_scan_round=to_scan_round,
            )
        except InvalidScanRoundComparisonError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except ComparedAssetNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ScanRoundNotFoundError as exc:
            raise HTTPException(
                status_code=404,
                detail={
                    "message": str(exc),
                    "missing_scan_rounds": exc.missing_rounds,
                },
            ) from exc

    return router
