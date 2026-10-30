"""提供给 Agent 的统一 L3 输入对象。"""

from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address

from pydantic import Field, field_validator

from .analysis_schema import ProductFingerprint, SchemaModel


class L3ServiceInput(SchemaModel):
    """从 L2 服务实例和对应 L3 detail 表归并后的服务对象。"""

    service_instance_id: int = Field(ge=1)
    active_host_id: int = Field(ge=1)
    port: int = Field(ge=1, le=65535)
    transport_protocol: str
    service_type: str
    application_protocol: str | None = None
    banner: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    l2_scan_status: int
    l2_scan_time: datetime | None = None
    l3_scan_status: int | None = None
    l3_scan_time: datetime | None = None
    detail_table: str | None = None
    detail: dict[str, object] = Field(default_factory=dict)
    product: ProductFingerprint | None = None


class AssetAnalysisInput(SchemaModel):
    """单个 IP 的统一 Agent 输入对象。"""

    ip: str
    scan_round: int = Field(ge=1)
    active_host_id: int = Field(ge=1)
    alive_type: int
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    scanner_node: str | None = None
    services: list[L3ServiceInput] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        try:
            ip_address(value)
        except ValueError as exc:
            raise ValueError("ip must be a valid IPv4 or IPv6 address") from exc
        return value

