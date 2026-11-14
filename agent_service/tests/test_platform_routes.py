from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_service.api.platform_routes import create_platform_router
from agent_service.models.platform_schema import (
    PlatformBootstrapResponse,
    PlatformHealthResponse,
    PlatformOverview,
    PlatformRiskSubnet,
    PlatformStats,
    PlatformTrend,
    PlatformSearchResponse,
    PlatformReportResponse,
    PlatformReportSection,
    PlatformReportStatistics,
)
from datetime import UTC, datetime


class FakePlatformService:
    async def health(self):
        return PlatformHealthResponse(ok=True, db="ipv4scan")

    async def bootstrap(self):
        return PlatformBootstrapResponse(
            overview=PlatformOverview(
                host=0,
                port=0,
                tcp=0,
                udp=0,
                svcTypes=0,
                riskHigh=0,
                newToday=0,
                tcpPct=0,
                privPct=0,
            ),
            stats=PlatformStats(
                portTop10=[],
                svcDist=[],
                trend=PlatformTrend(days=[], hosts=[], ports=[]),
                riskSubnet=PlatformRiskSubnet(subnets=[], high=[], mid=[], low=[]),
                provinces=[],
                highList=[],
            ),
            assets=[],
        )

    async def search(self, query, page):
        if query == "bad":
            raise ValueError("检索条件必须使用 key=value 格式")
        return PlatformSearchResponse(total=0, ms=0.1, rows=[], list=[])

    async def generate_report(self):
        return PlatformReportResponse(
            scan_round=1,
            generated_at=datetime.now(UTC),
            engine="template",
            sections=[PlatformReportSection(t="p", txt="测试报告", src="模板降级")],
            statistics=PlatformReportStatistics(
                host_count=0,
                service_count=0,
                tcp_count=0,
                udp_count=0,
                risk_counts={
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "unknown": 0,
                },
                top_ports=[],
            ),
        )


def test_platform_router_serves_health_bootstrap_and_frontend(tmp_path: Path) -> None:
    frontend = tmp_path / "index.html"
    frontend.write_text("<h1>NetScope</h1>", encoding="utf-8")
    app = FastAPI()
    app.include_router(create_platform_router(FakePlatformService(), frontend_file=frontend))

    with TestClient(app) as client:
        health = client.get("/api/health")
        bootstrap = client.get("/api/bootstrap")
        search = client.get("/api/search", params={"q": "port=22", "page": 1})
        report = client.post("/api/report", json={})
        invalid_report = client.post("/api/report", json={"scope": "all_history"})
        invalid = client.get("/api/search", params={"q": "bad", "page": 1})
        invalid_page = client.get("/api/search", params={"page": 0})
        page = client.get("/")

    assert health.status_code == 200
    assert health.json() == {"ok": True, "db": "ipv4scan"}
    assert bootstrap.status_code == 200
    assert bootstrap.json()["overview"]["host"] == 0
    assert search.status_code == 200
    assert search.json()["total"] == 0
    assert report.status_code == 200
    assert report.json()["engine"] == "template"
    assert report.json()["scan_round"] == 1
    assert invalid_report.status_code == 422
    assert invalid.status_code == 400
    assert invalid_page.status_code == 400
    assert page.status_code == 200
    assert "NetScope" in page.text
