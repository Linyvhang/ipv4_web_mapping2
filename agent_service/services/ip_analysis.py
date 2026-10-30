"""单个 IP 资产分析 Service。"""

from __future__ import annotations

import json
from ipaddress import IPv4Address, ip_address
from typing import Any

from agent_service.db.l3_data import L3DataProvider
from agent_service.models.analysis_schema import AnalysisMetadata, AnalysisResult
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
            "请输出资产画像、资产类型、服务说明、疑似风险、证据和处置建议。\n"
            "风险只能表达为疑似风险；证据不足时必须写‘信息不足，无法判断’。\n"
            "当前扫描只覆盖指定常用端口，报告必须说明这一限制。\n\n"
            "待分析数据：\n"
            f"{payload}"
        )

    def finalize_result(
        self,
        result: AnalysisResult,
        asset: AssetAnalysisInput,
    ) -> AnalysisResult:
        """校验模型结果与输入目标一致，并统一写入 Provider 元信息。"""

        if result.ip != asset.ip:
            raise ValueError(
                f"model result IP mismatch: expected {asset.ip}, got {result.ip}"
            )
        if result.scan_round != asset.scan_round:
            raise ValueError(
                "model result scan_round mismatch: "
                f"expected {asset.scan_round}, got {result.scan_round}"
            )

        info = self.model_provider.info
        metadata = AnalysisMetadata(
            model_provider=info.provider,
            model_name=info.name,
            model_version=info.version,
            prompt_version=self.prompt_version,
        )
        return result.model_copy(update={"metadata": metadata})

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

        prompt = self.build_prompt(asset)
        result = await self.model_provider.generate_structured(prompt, AnalysisResult)
        return self.finalize_result(result, asset)

