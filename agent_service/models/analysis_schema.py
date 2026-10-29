"""标准的单 IP 资产分析结果 Schema。

该模块只定义数据结构和基础校验，不调用模型、不访问数据库，也不提供 API。
"""

from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


RiskLevel = Literal["info", "low", "medium", "high", "critical"]
Confidence = Annotated[float, Field(ge=0.0, le=1.0)]


class SchemaModel(BaseModel):
    """所有输出模型共享的严格配置。"""

    model_config = ConfigDict(extra="forbid")


class ProductFingerprint(SchemaModel):
    """服务产品的原始值和归一化值。"""

    raw_product_name: str | None = None
    raw_version: str | None = None
    normalized_product_name: str | None = None
    normalized_version: str | None = None
    normalization_confidence: Confidence | None = None
    normalization_evidence: list[str] = Field(default_factory=list)


class ServiceFingerprint(SchemaModel):
    """一个 IP 上已观测到的服务及其指纹。"""

    service_instance_id: int | None = Field(default=None, ge=1)
    port: int = Field(ge=1, le=65535)
    transport_protocol: str
    service_type: str
    application_protocol: str | None = None
    product: ProductFingerprint | None = None
    banner: str | None = None
    fields: dict[str, object] = Field(default_factory=dict)


class AssetTypeAssessment(SchemaModel):
    """对资产类型的推断结果。一个 IP 可以有多个类型。"""

    asset_type: str
    confidence: Confidence
    evidence: list[str] = Field(default_factory=list)


class EvidenceItem(SchemaModel):
    """风险或资产判断引用的原始证据。"""

    evidence_id: str
    source_type: str
    source: str
    detail: str
    confidence: Confidence | None = None


class Recommendation(SchemaModel):
    """面向用户的处置建议。"""

    title: str
    description: str
    priority: Literal["low", "medium", "high"] = "medium"


class RiskFinding(SchemaModel):
    """基于被动指纹的疑似风险，不代表漏洞已经验证。"""

    risk_id: str
    level: RiskLevel
    title: str
    description: str
    confidence: Confidence
    evidence_ids: list[str] = Field(default_factory=list)
    recommendation_ids: list[str] = Field(default_factory=list)
    suspected: bool = True


class AnalysisSummary(SchemaModel):
    """面向普通用户的报告摘要。"""

    primary_asset_type: str | None = None
    risk_level: RiskLevel
    description: str
    confidence: Confidence
    needs_attention: bool = False


class AnalysisMetadata(SchemaModel):
    """本次分析使用的运行元信息。"""

    model_provider: str
    model_name: str
    model_version: str | None = None
    prompt_version: str


class AnalysisResult(SchemaModel):
    """单个 IP 的完整标准分析结果。"""

    schema_version: Literal["1.0"] = "1.0"
    analysis_id: str
    ip: str
    scan_round: int = Field(ge=1)
    scan_time: datetime
    summary: AnalysisSummary
    asset_types: list[AssetTypeAssessment] = Field(default_factory=list)
    services: list[ServiceFingerprint] = Field(default_factory=list)
    risks: list[RiskFinding] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    metadata: AnalysisMetadata

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        """只接受合法的 IPv4 或 IPv6 地址，并保留字符串格式输出。"""

        try:
            ip_address(value)
        except ValueError as exc:
            raise ValueError("ip must be a valid IPv4 or IPv6 address") from exc
        return value

