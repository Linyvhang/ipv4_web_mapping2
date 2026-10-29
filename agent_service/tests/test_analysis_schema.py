from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from agent_service.models.analysis_schema import AnalysisResult


def make_valid_result() -> dict:
    return {
        "schema_version": "1.0",
        "analysis_id": "analysis-001",
        "ip": "192.0.2.10",
        "scan_round": 1,
        "scan_time": datetime(2026, 10, 29, tzinfo=timezone.utc),
        "summary": {
            "primary_asset_type": "Web服务器",
            "risk_level": "medium",
            "description": "发现 Web 服务，存在需要进一步关注的版本风险。",
            "confidence": 0.86,
            "needs_attention": True,
        },
        "asset_types": [
            {
                "asset_type": "Web服务器",
                "confidence": 0.91,
                "evidence": ["开放 443 端口", "检测到 HTTPS 服务"],
            }
        ],
        "services": [
            {
                "service_instance_id": 1,
                "port": 443,
                "transport_protocol": "tcp",
                "service_type": "web",
                "application_protocol": "https",
                "product": {
                    "raw_product_name": "nginx/1.24.0",
                    "raw_version": "1.24.0",
                    "normalized_product_name": "nginx",
                    "normalized_version": "1.24.0",
                    "normalization_confidence": 0.99,
                    "normalization_evidence": ["Server header"],
                },
                "banner": "Server: nginx/1.24.0",
                "fields": {"http_status": 200},
            }
        ],
        "risks": [
            {
                "risk_id": "risk-001",
                "level": "medium",
                "title": "版本存在潜在风险",
                "description": "当前指纹显示的版本可能存在需要进一步确认的安全风险。",
                "confidence": 0.72,
                "evidence_ids": ["evidence-001"],
                "recommendation_ids": ["recommendation-001"],
                "suspected": True,
            }
        ],
        "evidence": [
            {
                "evidence_id": "evidence-001",
                "source_type": "http_header",
                "source": "web_service_detail.server_header",
                "detail": "Server: nginx/1.24.0",
                "confidence": 0.99,
            }
        ],
        "recommendations": [
            {
                "title": "进一步确认版本风险",
                "description": "在授权环境中结合漏洞知识库进行人工确认。",
                "priority": "medium",
            }
        ],
        "limitations": ["本次仅分析指定常用端口", "未执行主动漏洞验证"],
        "metadata": {
            "model_provider": "暂定",
            "model_name": "暂定通义千问",
            "model_version": None,
            "prompt_version": "1.0",
        },
    }


def test_valid_analysis_result_can_be_serialized() -> None:
    result = AnalysisResult.model_validate(make_valid_result())

    payload = result.model_dump(mode="json")

    assert payload["schema_version"] == "1.0"
    assert payload["ip"] == "192.0.2.10"
    assert payload["services"][0]["product"]["normalized_product_name"] == "nginx"
    assert payload["risks"][0]["suspected"] is True


def test_invalid_ip_is_rejected() -> None:
    data = make_valid_result()
    data["ip"] = "not-an-ip"

    with pytest.raises(ValidationError, match="valid IPv4 or IPv6"):
        AnalysisResult.model_validate(data)


def test_invalid_risk_level_is_rejected() -> None:
    data = make_valid_result()
    data["summary"]["risk_level"] = "urgent"

    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(data)


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_confidence_must_be_between_zero_and_one(confidence: float) -> None:
    data = make_valid_result()
    data["summary"]["confidence"] = confidence

    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(data)


def test_unknown_fields_are_rejected() -> None:
    data = make_valid_result()
    data["unexpected_field"] = "should fail"

    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(data)


def test_insufficient_data_can_be_explicitly_returned() -> None:
    data = make_valid_result()
    data["summary"] = {
        "primary_asset_type": None,
        "risk_level": "info",
        "description": "信息不足，无法判断",
        "confidence": 0.2,
        "needs_attention": False,
    }
    data["services"] = []
    data["risks"] = []
    data["limitations"] = ["当前扫描数据不足，未发现可分析服务"]

    result = AnalysisResult.model_validate(data)

    assert result.summary.description == "信息不足，无法判断"
    assert result.risks == []

