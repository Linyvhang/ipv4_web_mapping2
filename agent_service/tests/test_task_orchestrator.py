from datetime import datetime

from agent_service.models.analysis_schema import (
    AnalysisMetadata,
    AnalysisResult,
    AnalysisSummary,
    Confidence,
)
from agent_service.services.task_orchestrator import SingleIPTaskOrchestrator


def test_task_request_is_serializable_and_auditable() -> None:
    request = SingleIPTaskOrchestrator.build_task_request(
        "192.0.2.1", 3, True
    )
    assert request == {"ip": "192.0.2.1", "scan_round": 3, "save_result": True}


def test_result_record_kwargs_preserves_standard_result_and_metadata() -> None:
    result = AnalysisResult(
        analysis_id="a-1",
        ip="192.0.2.1",
        scan_round=1,
        scan_time=datetime(2026, 1, 1),
        summary=AnalysisSummary(
            risk_level="low",
            description="无明显风险",
            confidence=0.8,
        ),
        metadata=AnalysisMetadata(
            model_provider="mock",
            model_name="mock-model",
            prompt_version="1.0",
        ),
    )
    record = SingleIPTaskOrchestrator.result_record_kwargs(result, 9)
    assert record["task_item_id"] == 9
    assert record["result_json"]["analysis_id"] == "a-1"
    assert record["model_provider"] == "mock"
