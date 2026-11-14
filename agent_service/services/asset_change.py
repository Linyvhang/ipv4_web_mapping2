"""单 IP 不同扫描批次的确定性变化对比。"""

from __future__ import annotations

from typing import Any

from agent_service.db.l3_data import L3DataProvider
from agent_service.db.repositories import AgentAnalysisRepository
from agent_service.models.analysis_schema import AnalysisResult, ProductFingerprint
from agent_service.models.asset_change_schema import (
    AssetChangeResponse,
    AssetChangeSummary,
    ComparedRisk,
    ComparedService,
    ProductChange,
    RiskChanges,
    ServiceChanges,
)
from agent_service.models.input_schema import AssetAnalysisInput, L3ServiceInput
from agent_service.services.ip_analysis import ipv4_to_uint32


class ComparedAssetNotFoundError(LookupError):
    pass


class InvalidScanRoundComparisonError(ValueError):
    pass


class ScanRoundNotFoundError(LookupError):
    def __init__(self, missing_rounds: list[int]) -> None:
        self.missing_rounds = missing_rounds
        super().__init__(
            "以下扫描批次不存在: " + ", ".join(map(str, missing_rounds))
        )


RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _service_key(service: L3ServiceInput) -> tuple[int, str, str]:
    return (
        service.port,
        service.transport_protocol.strip().lower(),
        service.service_type.strip().lower(),
    )


def _product_values(
    product: ProductFingerprint | None,
) -> tuple[str | None, str | None]:
    if product is None:
        return None, None
    return (
        product.normalized_product_name or product.raw_product_name,
        product.normalized_version or product.raw_version,
    )


def _service_snapshot(service: L3ServiceInput) -> ComparedService:
    return ComparedService(
        port=service.port,
        transport_protocol=service.transport_protocol,
        service_type=service.service_type,
        application_protocol=service.application_protocol,
        product=service.product,
    )


class AssetChangeService:
    def __init__(
        self,
        *,
        session_factory: Any,
        data_provider_factory=L3DataProvider,
        analysis_repository_factory=AgentAnalysisRepository,
    ) -> None:
        self.session_factory = session_factory
        self.data_provider_factory = data_provider_factory
        self.analysis_repository_factory = analysis_repository_factory

    async def compare(
        self,
        ip: str,
        *,
        from_scan_round: int,
        to_scan_round: int,
    ) -> AssetChangeResponse:
        if from_scan_round == to_scan_round:
            raise InvalidScanRoundComparisonError("两个扫描批次不能相同")
        ip_value = ipv4_to_uint32(ip)
        async with self.session_factory() as session:
            provider = self.data_provider_factory(session)
            repository = self.analysis_repository_factory(session)
            if hasattr(provider, "scan_round_exists"):
                missing_rounds = [
                    scan_round
                    for scan_round in (from_scan_round, to_scan_round)
                    if not await provider.scan_round_exists(scan_round)
                ]
                if missing_rounds:
                    raise ScanRoundNotFoundError(missing_rounds)
            old_asset = await provider.fetch_asset(
                ip_value=ip_value, scan_round=from_scan_round
            )
            new_asset = await provider.fetch_asset(
                ip_value=ip_value, scan_round=to_scan_round
            )
            if old_asset is None and new_asset is None:
                raise ComparedAssetNotFoundError(
                    f"IP {ip} 在扫描批次 {from_scan_round} 和 {to_scan_round} 中均不存在"
                )
            old_result = await self._load_result(repository, old_asset)
            new_result = await self._load_result(repository, new_asset)
            return self.build_comparison(
                ip=ip,
                from_scan_round=from_scan_round,
                to_scan_round=to_scan_round,
                old_asset=old_asset,
                new_asset=new_asset,
                old_result=old_result,
                new_result=new_result,
            )

    @staticmethod
    async def _load_result(repository, asset):
        if asset is None:
            return None
        record = await repository.get_cached_result(
            ip=asset.ip, scan_round=asset.scan_round
        )
        if record is None:
            return None
        return AnalysisResult.model_validate(record.result_json)

    @staticmethod
    def build_comparison(
        *,
        ip: str,
        from_scan_round: int,
        to_scan_round: int,
        old_asset: AssetAnalysisInput | None,
        new_asset: AssetAnalysisInput | None,
        old_result: AnalysisResult | None,
        new_result: AnalysisResult | None,
    ) -> AssetChangeResponse:
        old_services = {
            _service_key(service): service
            for service in (old_asset.services if old_asset else [])
        }
        new_services = {
            _service_key(service): service
            for service in (new_asset.services if new_asset else [])
        }
        old_keys = set(old_services)
        new_keys = set(new_services)
        added = [
            _service_snapshot(new_services[key]) for key in sorted(new_keys - old_keys)
        ]
        removed = [
            _service_snapshot(old_services[key]) for key in sorted(old_keys - new_keys)
        ]
        shared_keys = sorted(old_keys & new_keys)
        product_changes = []
        for key in shared_keys:
            old_product, old_version = _product_values(old_services[key].product)
            new_product, new_version = _product_values(new_services[key].product)
            if (old_product, old_version) == (new_product, new_version):
                continue
            if old_product is None and new_product is not None:
                change_type = "detected"
            elif old_product is not None and new_product is None:
                change_type = "lost"
            elif old_product != new_product:
                change_type = "product_changed"
            else:
                change_type = "version_changed"
            port, protocol, service_type = key
            product_changes.append(
                ProductChange(
                    port=port,
                    transport_protocol=protocol,
                    service_type=service_type,
                    change_type=change_type,
                    from_product=old_product,
                    from_version=old_version,
                    to_product=new_product,
                    to_version=new_version,
                )
            )

        risk_changes = AssetChangeService._compare_risks(old_result, new_result)
        limitations = list(
            dict.fromkeys(
                [
                    *(old_asset.limitations if old_asset else []),
                    *(new_asset.limitations if new_asset else []),
                ]
            )
        )
        if old_result is None or new_result is None:
            limitations.append("至少一个扫描批次没有已保存分析结果，无法比较风险变化")

        if old_asset is None:
            status = "added"
        elif new_asset is None:
            status = "removed"
        elif added or removed or product_changes or risk_changes.direction not in {
            "unchanged",
            "unavailable",
        } or risk_changes.added or risk_changes.removed or risk_changes.needs_attention_changed:
            status = "changed"
        else:
            status = "unchanged"

        return AssetChangeResponse(
            ip=ip,
            from_scan_round=from_scan_round,
            to_scan_round=to_scan_round,
            from_scan_time=(old_asset.last_seen or old_asset.first_seen) if old_asset else None,
            to_scan_time=(new_asset.last_seen or new_asset.first_seen) if new_asset else None,
            change_status=status,
            summary=AssetChangeSummary(
                added_service_count=len(added),
                removed_service_count=len(removed),
                product_change_count=len(product_changes),
                added_risk_count=len(risk_changes.added),
                removed_risk_count=len(risk_changes.removed),
            ),
            service_changes=ServiceChanges(
                added=added,
                removed=removed,
                unchanged_count=len(shared_keys),
            ),
            product_changes=product_changes,
            risk_changes=risk_changes,
            limitations=limitations,
        )

    @staticmethod
    def _compare_risks(
        old_result: AnalysisResult | None,
        new_result: AnalysisResult | None,
    ) -> RiskChanges:
        if old_result is None or new_result is None:
            return RiskChanges(
                available=False,
                direction="unavailable",
                added=[],
                removed=[],
            )
        old_level = old_result.summary.risk_level
        new_level = new_result.summary.risk_level
        delta = RISK_ORDER[new_level] - RISK_ORDER[old_level]
        direction = "increased" if delta > 0 else "decreased" if delta < 0 else "unchanged"
        old_risks = {
            risk.title.strip().casefold(): ComparedRisk(title=risk.title, level=risk.level)
            for risk in old_result.risks
        }
        new_risks = {
            risk.title.strip().casefold(): ComparedRisk(title=risk.title, level=risk.level)
            for risk in new_result.risks
        }
        return RiskChanges(
            available=True,
            direction=direction,
            from_level=old_level,
            to_level=new_level,
            added=[new_risks[key] for key in sorted(set(new_risks) - set(old_risks))],
            removed=[old_risks[key] for key in sorted(set(old_risks) - set(new_risks))],
            needs_attention_changed=(
                old_result.summary.needs_attention
                != new_result.summary.needs_attention
            ),
        )
