"""单 IP 跨扫描批次变化对比 Schema。"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from .analysis_schema import ProductFingerprint, RiskLevel, SchemaModel


class ComparedService(SchemaModel):
    port: int = Field(ge=1, le=65535)
    transport_protocol: str
    service_type: str
    application_protocol: str | None = None
    product: ProductFingerprint | None = None


class ServiceChanges(SchemaModel):
    added: list[ComparedService]
    removed: list[ComparedService]
    unchanged_count: int = Field(ge=0)


class ProductChange(SchemaModel):
    port: int = Field(ge=1, le=65535)
    transport_protocol: str
    service_type: str
    change_type: Literal[
        "detected", "lost", "product_changed", "version_changed"
    ]
    from_product: str | None = None
    from_version: str | None = None
    to_product: str | None = None
    to_version: str | None = None


class ComparedRisk(SchemaModel):
    title: str
    level: RiskLevel


class RiskChanges(SchemaModel):
    available: bool
    direction: Literal["increased", "decreased", "unchanged", "unavailable"]
    from_level: RiskLevel | None = None
    to_level: RiskLevel | None = None
    added: list[ComparedRisk]
    removed: list[ComparedRisk]
    needs_attention_changed: bool | None = None


class AssetChangeSummary(SchemaModel):
    added_service_count: int = Field(ge=0)
    removed_service_count: int = Field(ge=0)
    product_change_count: int = Field(ge=0)
    added_risk_count: int = Field(ge=0)
    removed_risk_count: int = Field(ge=0)


class AssetChangeResponse(SchemaModel):
    schema_version: Literal["1.0"] = "1.0"
    ip: str
    from_scan_round: int = Field(ge=1)
    to_scan_round: int = Field(ge=1)
    from_scan_time: datetime | None = None
    to_scan_time: datetime | None = None
    change_status: Literal["added", "removed", "changed", "unchanged"]
    summary: AssetChangeSummary
    service_changes: ServiceChanges
    product_changes: list[ProductChange]
    risk_changes: RiskChanges
    limitations: list[str]
