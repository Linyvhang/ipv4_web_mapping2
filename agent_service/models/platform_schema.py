"""NetScope 单文件前端使用的平台概览接口 Schema。"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .analysis_schema import SchemaModel


PlatformRisk = Literal["critical", "high", "medium", "low", "info", "unknown"]


class PlatformHealthResponse(SchemaModel):
    ok: bool
    db: str


class PlatformAssetRow(SchemaModel):
    ip: str
    port: int = Field(ge=1, le=65535)
    proto: str
    service: str
    risk: PlatformRisk = "unknown"
    subnet: str
    loc: str
    ttl: int | None = None
    banner: str | None = None
    last: str | None = None
    first: str | None = None
    conf: float = Field(ge=0, le=1)


class PlatformOverview(SchemaModel):
    scan_round: int | None = Field(default=None, ge=1)
    host: int = Field(ge=0)
    port: int = Field(ge=0)
    tcp: int = Field(ge=0)
    udp: int = Field(ge=0)
    svcTypes: int = Field(ge=0)
    riskHigh: int = Field(ge=0)
    newToday: int = Field(ge=0)
    tcpPct: float = Field(ge=0, le=100)
    privPct: float = Field(ge=0, le=100)


class PlatformTrend(SchemaModel):
    days: list[str]
    hosts: list[int]
    ports: list[int]


class PlatformRiskSubnet(SchemaModel):
    subnets: list[str]
    high: list[int]
    mid: list[int]
    low: list[int]


class PlatformHighRiskItem(SchemaModel):
    ip: str
    port: int = Field(ge=1, le=65535)
    proto: str
    service: str
    risk: PlatformRisk


class PlatformStats(SchemaModel):
    portTop10: list[tuple[str, int]]
    svcDist: list[dict[str, str | int]]
    trend: PlatformTrend
    riskSubnet: PlatformRiskSubnet
    provinces: list[tuple[str, int]]
    highList: list[PlatformHighRiskItem]


class PlatformBootstrapResponse(SchemaModel):
    overview: PlatformOverview
    stats: PlatformStats
    assets: list[PlatformAssetRow]
    limitations: list[str] = Field(default_factory=list)


class PlatformSearchResponse(SchemaModel):
    total: int = Field(ge=0)
    ms: float = Field(ge=0)
    rows: list[PlatformAssetRow]
    list: list[PlatformAssetRow]
