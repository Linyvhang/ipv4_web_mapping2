"""单 IP 分析 API 的请求和响应 Schema。"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class IPAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: IPvAnyAddress
    scan_round: int | None = Field(default=None, ge=1)
    save_result: bool = True

    @field_validator("ip")
    @classmethod
    def require_ipv4(cls, value: IPvAnyAddress) -> IPvAnyAddress:
        if value.version != 4:
            raise ValueError("当前单 IP 分析接口仅支持 IPv4")
        return value


class IPAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: int | None
    task_item_id: int | None
    reused: bool
    result: dict[str, Any]

