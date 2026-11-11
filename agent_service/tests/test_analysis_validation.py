from datetime import datetime

from agent_service.models.analysis_schema import (
    AnalysisMetadata,
    AnalysisResult,
    AnalysisSummary,
    EvidenceItem,
    RiskFinding,
    ServiceFingerprint,
)
from agent_service.models.input_schema import AssetAnalysisInput, L3ServiceInput
from agent_service.services.analysis_validation import (
    build_safe_fallback_result,
    validate_analysis_result,
)


def make_asset() -> AssetAnalysisInput:
    return AssetAnalysisInput(
        ip="192.0.2.10",
        scan_round=2,
        active_host_id=1,
        alive_type=1,
        services=[
            L3ServiceInput(
                service_instance_id=9,
                active_host_id=1,
                port=22,
                transport_protocol="tcp",
                service_type="ssh",
                confidence=0.9,
                l2_scan_status=1,
            )
        ],
        limitations=["仅扫描常用端口"],
    )


def make_result(*, evidence_id: str = "ev-1", suspected: bool = True) -> AnalysisResult:
    return AnalysisResult(
        analysis_id="analysis-test",
        ip="192.0.2.10",
        scan_round=2,
        scan_time=datetime(2026, 11, 11),
        summary=AnalysisSummary(
            primary_asset_type="服务器",
            risk_level="low",
            description="发现 SSH 服务",
            confidence=0.7,
        ),
        services=[
            ServiceFingerprint(
                service_instance_id=9,
                port=22,
                transport_protocol="tcp",
                service_type="ssh",
            )
        ],
        risks=[
            RiskFinding(
                risk_id="risk-1",
                level="low",
                title="疑似版本风险",
                description="需要进一步核实",
                confidence=0.6,
                evidence_ids=[evidence_id],
                suspected=suspected,
            )
        ],
        evidence=[
            EvidenceItem(
                evidence_id="ev-1",
                source_type="banner",
                source="ssh",
                detail="OpenSSH banner",
            )
        ],
        limitations=["仅扫描常用端口"],
        metadata=AnalysisMetadata(
            model_provider="mock",
            model_name="mock",
            prompt_version="1.0",
        ),
    )


def test_valid_result_passes_deterministic_validation() -> None:
    validation = validate_analysis_result(make_result(), make_asset())

    assert validation.valid is True
    assert validation.errors == ()


def test_unknown_evidence_and_confirmed_vulnerability_are_rejected() -> None:
    validation = validate_analysis_result(
        make_result(evidence_id="missing", suspected=False), make_asset()
    )

    assert validation.valid is False
    assert any("不能表述为已确认漏洞" in error for error in validation.errors)
    assert any("不存在的证据" in error for error in validation.errors)


def test_fallback_preserves_scan_facts_and_removes_unverified_claims() -> None:
    fallback = build_safe_fallback_result(make_result(), ["证据引用无效"])

    assert fallback.services[0].port == 22
    assert fallback.metadata.model_name == "mock"
    assert fallback.summary.risk_level == "info"
    assert fallback.summary.confidence == 0.0
    assert fallback.asset_types == []
    assert fallback.risks == []
    assert fallback.evidence == []
    assert "已降级" in fallback.limitations[-1]
