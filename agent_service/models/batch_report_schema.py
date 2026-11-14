"""面向可视化模块的批量统计 JSON 报告 Schema。"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from .analysis_schema import RiskLevel, SchemaModel


class NamedCount(SchemaModel):
    name: str
    count: int = Field(ge=0)
    percentage: float = Field(ge=0.0, le=100.0)


class RiskLevelCount(SchemaModel):
    level: RiskLevel
    count: int = Field(ge=0)
    percentage: float = Field(ge=0.0, le=100.0)


class ProductStatistics(SchemaModel):
    product: str
    version: str | None = None
    service_count: int = Field(ge=1)
    asset_count: int = Field(ge=1)
    ips: list[str]


class PortStatistics(SchemaModel):
    port: int = Field(ge=1, le=65535)
    transport_protocol: str
    service_type: str
    service_count: int = Field(ge=1)
    asset_count: int = Field(ge=1)
    ips: list[str]


class FailedAssetItem(SchemaModel):
    ip: str
    scan_round: int = Field(ge=1)
    error_message: str | None = None


class AttentionAssetItem(SchemaModel):
    ip: str
    scan_round: int = Field(ge=1)
    risk_level: RiskLevel
    risk_count: int = Field(ge=0)
    risk_titles: list[str]


class BatchReportOverview(SchemaModel):
    target_count: int = Field(ge=0)
    successful_assets: int = Field(ge=0)
    failed_assets: int = Field(ge=0)
    analyzed_assets: int = Field(ge=0)
    total_services: int = Field(ge=0)
    total_risks: int = Field(ge=0)
    attention_assets: int = Field(ge=0)
    missing_results: int = Field(ge=0)


class BatchStatisticsReport(SchemaModel):
    schema_version: Literal["1.0"] = "1.0"
    task_id: int = Field(ge=1)
    generated_at: datetime
    overview: BatchReportOverview
    asset_type_distribution: list[NamedCount]
    asset_risk_distribution: list[RiskLevelCount]
    finding_risk_distribution: list[RiskLevelCount]
    products: list[ProductStatistics]
    ports: list[PortStatistics]
    failed_items: list[FailedAssetItem]
    attention_items: list[AttentionAssetItem]
    missing_result_ips: list[str]
    limitation_distribution: list[NamedCount]


class SavedBatchReportResponse(SchemaModel):
    report_id: int = Field(ge=1)
    task_id: int = Field(ge=1)
    reused: bool
    report: BatchStatisticsReport
    created_at: datetime
    updated_at: datetime
