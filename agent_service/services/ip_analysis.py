"""单个 IP 资产分析 Service。"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from ipaddress import IPv4Address, ip_address
from uuid import uuid4

from agent_service.db.l3_data import L3DataProvider
from agent_service.models.analysis_schema import (
    AnalysisMetadata,
    AnalysisResult,
    ModelAnalysisPayload,
    ServiceFingerprint,
)
from agent_service.models.input_schema import AssetAnalysisInput
from agent_service.providers.base import ModelProvider


class AssetNotFoundError(LookupError):
    """扫描数据中不存在目标 IP。"""


class UnsupportedAddressError(ValueError):
    """当前 active_host 表只支持 IPv4 整数地址。"""


def ipv4_to_uint32(value: str) -> int:
    address = ip_address(value)
    if not isinstance(address, IPv4Address):
        raise UnsupportedAddressError("当前扫描数据层仅支持 IPv4 地址")
    return int(address)


class SingleIPAnalysisService:
    """读取一个 IP 的 L3 数据并生成标准分析结果。

    Service 不负责保存数据库结果，也不负责 HTTP API；持久化和接口由后续层实现。
    """

    def __init__(
        self,
        *,
        data_provider: L3DataProvider,
        model_provider: ModelProvider,
        prompt_version: str = "1.0",
    ) -> None:
        self.data_provider = data_provider
        self.model_provider = model_provider
        self.prompt_version = prompt_version

    @staticmethod
    def build_prompt(asset: AssetAnalysisInput) -> str:
        """生成只允许基于已有扫描证据分析的 Prompt。"""

        payload = json.dumps(
            asset.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
        )
        return (
            "你是 IPv4 网络资产分析助手。\n"
            "请只根据下面已有的 L1/L2/L3 被动测绘数据进行分析。\n"
            "禁止主动扫描、漏洞利用、弱口令测试或编造不存在的证据。\n"
            "请输出面向普通用户的摘要、资产类型、疑似风险、证据和处置建议。\n"
            "IP、扫描批次、扫描时间、服务列表和模型元信息由程序生成，不要在结果中重复这些字段。\n"
            "风险只能表达为疑似风险；证据不足时必须写‘信息不足，无法判断’。\n"
            "当前扫描只覆盖指定常用端口，报告必须说明这一限制。\n\n"
            "待分析数据：\n"
            f"{payload}"
        )

    def finalize_result(
        self,
        payload: ModelAnalysisPayload,
        asset: AssetAnalysisInput,
    ) -> AnalysisResult:
        """把模型判断与程序掌握的扫描事实组合为标准结果。"""

        info = self.model_provider.info
        metadata = AnalysisMetadata(
            model_provider=info.provider,
            model_name=info.name,
            model_version=info.version,
            prompt_version=self.prompt_version,
        )
        services = [
            ServiceFingerprint(
                service_instance_id=service.service_instance_id,
                port=service.port,
                transport_protocol=service.transport_protocol,
                service_type=service.service_type,
                application_protocol=service.application_protocol,
                product=service.product,
                banner=service.banner,
                fields=dict(service.detail),
            )
            for service in asset.services
        ]
        limitations = list(
            dict.fromkeys([*asset.limitations, *payload.limitations])
        )
        scan_time = (
            asset.last_seen
            or asset.first_seen
            or datetime.now(timezone.utc)
        )
        return AnalysisResult(
            analysis_id=f"analysis-{uuid4().hex}",
            ip=asset.ip,
            scan_round=asset.scan_round,
            scan_time=scan_time,
            summary=payload.summary,
            asset_types=payload.asset_types,
            services=services,
            risks=payload.risks,
            evidence=payload.evidence,
            recommendations=payload.recommendations,
            limitations=limitations,
            metadata=metadata,
        )

    async def analyze(
        self,
        ip: str,
        *,
        scan_round: int | None = None,
    ) -> AnalysisResult:
        """分析指定 IP，返回标准结果。"""

        asset = await self.data_provider.fetch_asset(
            ip_value=ipv4_to_uint32(ip),
            scan_round=scan_round,
        )
        if asset is None:
            raise AssetNotFoundError(f"未找到 IP {ip} 的扫描数据")

        return await self.analyze_asset(asset)

    async def analyze_asset(self, asset: AssetAnalysisInput) -> AnalysisResult:
        """分析已由编排层加载的资产，避免重复查询 L3 数据。"""

        prompt = self.build_prompt(asset)
        payload = await self.model_provider.generate_structured(
            prompt, ModelAnalysisPayload
        )
        return self.finalize_result(payload, asset)

