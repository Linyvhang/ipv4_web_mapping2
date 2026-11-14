from datetime import datetime
from types import SimpleNamespace

from agent_service.db.models import TaskStatus
from agent_service.models.analysis_schema import AnalysisResult
from agent_service.services.batch_report import BatchReportService


def make_result(ip: str, *, risk_level: str, port: int, attention: bool = False):
    return AnalysisResult.model_validate(
        {
            "analysis_id": f"analysis-{ip}",
            "ip": ip,
            "scan_round": 1,
            "scan_time": "2026-11-14T00:00:00",
            "summary": {
                "primary_asset_type": "服务器",
                "risk_level": risk_level,
                "description": "测试资产",
                "confidence": 0.8,
                "needs_attention": attention,
            },
            "services": [
                {
                    "port": port,
                    "transport_protocol": "tcp",
                    "service_type": "web" if port == 80 else "ssh",
                    "product": {
                        "normalized_product_name": "nginx" if port == 80 else "OpenSSH",
                        "normalized_version": "1.24" if port == 80 else "9.2",
                        "normalization_confidence": 0.9,
                    },
                }
            ],
            "risks": [
                {
                    "risk_id": f"risk-{ip}",
                    "level": risk_level,
                    "title": "疑似配置风险",
                    "description": "需要人工核实",
                    "confidence": 0.7,
                }
            ],
            "limitations": ["仅扫描常用端口"],
            "metadata": {
                "model_provider": "mock",
                "model_name": "mock",
                "prompt_version": "1.0",
            },
        }
    )


def test_build_batch_report_aggregates_visualization_dimensions():
    items = [
        SimpleNamespace(
            ip="192.0.2.1",
            scan_round=1,
            status=TaskStatus.SUCCESS,
            error_message=None,
        ),
        SimpleNamespace(
            ip="192.0.2.2",
            scan_round=1,
            status=TaskStatus.SUCCESS,
            error_message=None,
        ),
        SimpleNamespace(
            ip="192.0.2.3",
            scan_round=1,
            status=TaskStatus.FAILED,
            error_message="模型超时",
        ),
    ]

    report = BatchReportService.build_report(
        task_id=10,
        target_count=3,
        items=items,
        results=[
            make_result("192.0.2.1", risk_level="low", port=80),
            make_result(
                "192.0.2.2", risk_level="high", port=22, attention=True
            ),
        ],
        missing_result_ips=[],
    )

    assert report.overview.target_count == 3
    assert report.overview.successful_assets == 2
    assert report.overview.failed_assets == 1
    assert report.overview.total_services == 2
    assert report.overview.total_risks == 2
    assert report.asset_type_distribution[0].name == "服务器"
    assert report.asset_type_distribution[0].percentage == 100.0
    assert next(row for row in report.asset_risk_distribution if row.level == "high").count == 1
    assert {row.product for row in report.products} == {"nginx", "OpenSSH"}
    assert {row.port for row in report.ports} == {22, 80}
    assert report.failed_items[0].error_message == "模型超时"
    assert report.attention_items[0].ip == "192.0.2.2"
    assert report.limitation_distribution[0].count == 2


def test_build_report_exposes_missing_saved_results_as_anomaly():
    items = [
        SimpleNamespace(
            ip="192.0.2.9",
            scan_round=1,
            status=TaskStatus.SUCCESS,
            error_message=None,
        )
    ]

    report = BatchReportService.build_report(
        task_id=11,
        target_count=1,
        items=items,
        results=[],
        missing_result_ips=["192.0.2.9"],
    )

    assert report.overview.successful_assets == 1
    assert report.overview.analyzed_assets == 0
    assert report.overview.missing_results == 1
    assert report.missing_result_ips == ["192.0.2.9"]
