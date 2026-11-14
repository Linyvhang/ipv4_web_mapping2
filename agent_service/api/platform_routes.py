"""NetScope 前端静态入口和平台初始化 API。"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import FileResponse

from agent_service.models.platform_schema import (
    PlatformBootstrapResponse,
    PlatformHealthResponse,
    PlatformReportRequest,
    PlatformReportResponse,
    PlatformSearchResponse,
)
from agent_service.services.platform_dashboard import PlatformDashboardService


def create_platform_router(
    service: PlatformDashboardService,
    *,
    frontend_file: Path | None = None,
) -> APIRouter:
    router = APIRouter(tags=["platform"])

    @router.get("/api/health", response_model=PlatformHealthResponse)
    async def platform_health() -> PlatformHealthResponse:
        return await service.health()

    @router.get("/api/bootstrap", response_model=PlatformBootstrapResponse)
    async def platform_bootstrap() -> PlatformBootstrapResponse:
        return await service.bootstrap()

    @router.get("/api/search", response_model=PlatformSearchResponse)
    async def platform_search(
        q: str = "",
        page: int = 1,
    ) -> PlatformSearchResponse:
        if page < 1:
            raise HTTPException(status_code=400, detail="page 必须是正整数")
        try:
            return await service.search(q, page)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @router.post("/api/report", response_model=PlatformReportResponse)
    async def platform_report(
        request: PlatformReportRequest = Body(default_factory=PlatformReportRequest),
    ) -> PlatformReportResponse:
        # 当前契约的两个字段都是受限 Literal；保留 request 以固定前后端接口。
        del request
        return await service.generate_report()

    if frontend_file is not None:
        resolved = frontend_file.resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"前端入口不存在: {resolved}")

        @router.get("/", include_in_schema=False)
        async def platform_index() -> FileResponse:
            return FileResponse(resolved, media_type="text/html; charset=utf-8")

    return router
