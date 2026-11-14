"""有限批量 IP 分析 API 契约。"""

from __future__ import annotations

from ipaddress import IPv4Address

from pydantic import Field

from agent_service.models.analysis_schema import SchemaModel


class BatchAnalysisRequest(SchemaModel):
    ips: list[IPv4Address] = Field(min_length=2, max_length=50)
    scan_round: int | None = Field(default=None, ge=1)


class BatchTargetResponse(SchemaModel):
    ip: str
    scan_round: int = Field(ge=1)


class BatchAnalysisResponse(SchemaModel):
    task_id: int = Field(ge=1)
    status: str
    target_count: int = Field(ge=2)
    targets: list[BatchTargetResponse]
