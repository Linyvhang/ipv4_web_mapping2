"""单 IP 分析结果的确定性校验和安全降级。"""

from __future__ import annotations

from dataclasses import dataclass

from agent_service.models.analysis_schema import AnalysisResult, AnalysisSummary
from agent_service.models.input_schema import AssetAnalysisInput


@dataclass(frozen=True)
class AnalysisValidation:
    """分析结果校验结论。"""

    valid: bool
    errors: tuple[str, ...] = ()


def validate_analysis_result(
    result: AnalysisResult,
    asset: AssetAnalysisInput,
) -> AnalysisValidation:
    """验证模型结论没有改写扫描事实，且风险都有有效证据引用。"""

    errors: list[str] = []
    if result.ip != asset.ip:
        errors.append("结果 IP 与扫描输入不一致")
    if result.scan_round != asset.scan_round:
        errors.append("结果扫描批次与扫描输入不一致")

    expected_services = {
        (
            service.service_instance_id,
            service.port,
            service.transport_protocol,
            service.service_type,
        )
        for service in asset.services
    }
    actual_services = {
        (
            service.service_instance_id,
            service.port,
            service.transport_protocol,
            service.service_type,
        )
        for service in result.services
    }
    if actual_services != expected_services:
        errors.append("结果服务列表与已有扫描指纹不一致")

    evidence_ids = [item.evidence_id for item in result.evidence]
    if len(evidence_ids) != len(set(evidence_ids)):
        errors.append("证据 ID 存在重复")
    known_evidence_ids = set(evidence_ids)
    for risk in result.risks:
        if not risk.suspected:
            errors.append(f"风险 {risk.risk_id} 不能表述为已确认漏洞")
        if not risk.evidence_ids:
            errors.append(f"风险 {risk.risk_id} 缺少证据引用")
            continue
        unknown_ids = set(risk.evidence_ids) - known_evidence_ids
        if unknown_ids:
            errors.append(
                f"风险 {risk.risk_id} 引用了不存在的证据: "
                + ", ".join(sorted(unknown_ids))
            )

    return AnalysisValidation(valid=not errors, errors=tuple(errors))


def build_safe_fallback_result(
    result: AnalysisResult,
    validation_errors: list[str] | tuple[str, ...],
) -> AnalysisResult:
    """连续校验失败后保留扫描事实，并移除未经验证的模型结论。"""

    limitation = "模型结果重试后仍未通过证据校验，已降级为仅展示扫描事实的报告"
    if validation_errors:
        limitation += "（" + "；".join(validation_errors) + "）"
    return result.model_copy(
        update={
            "summary": AnalysisSummary(
                primary_asset_type=None,
                risk_level="info",
                description="已读取该 IP 的扫描指纹；模型结论未通过校验，因此未展示资产推断和风险判断。",
                confidence=0.0,
                needs_attention=False,
            ),
            "asset_types": [],
            "risks": [],
            "evidence": [],
            "recommendations": [],
            "limitations": list(dict.fromkeys([*result.limitations, limitation])),
        }
    )
