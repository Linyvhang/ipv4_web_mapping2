from sqlalchemy.dialects import mysql

from agent_service.db.models import (
    AgentReport,
    AgentTask,
    AgentTaskItem,
    ReportFormat,
    ReportType,
    TaskStatus,
    TaskType,
)
from agent_service.db.repositories import (
    AgentAnalysisRepository,
    AgentReportRepository,
    AgentTaskRepository,
)


def compile_mysql(statement) -> str:
    return str(statement.compile(dialect=mysql.dialect()))


def test_task_query_and_update_statements_are_scoped() -> None:
    task_query = AgentTaskRepository.build_task_query(7)
    item_query = AgentTaskRepository.build_item_query(8)
    task_update = AgentTaskRepository.build_update_task_status(
        7,
        TaskStatus.FAILED,
        error_message="model timeout",
    )

    assert "agent_task.id" in compile_mysql(task_query)
    assert "agent_task_item.id" in compile_mysql(item_query)
    assert "SET status=%s" in compile_mysql(task_update)
    assert "error_message=%s" in compile_mysql(task_update)


def test_cached_result_query_uses_ip_and_scan_round() -> None:
    statement = AgentAnalysisRepository.build_cached_result_query("192.0.2.1", 1)
    compiled = compile_mysql(statement)

    assert "agent_analysis_result.ip" in compiled
    assert "agent_analysis_result.scan_round" in compiled
    assert set(statement.compile(dialect=mysql.dialect()).params) == {
        "ip_1",
        "scan_round_1",
    }


def test_analysis_and_report_queries_use_unique_identifiers() -> None:
    analysis_query = AgentAnalysisRepository.build_analysis_id_query("analysis-001")
    report_query = AgentReportRepository.build_report_query(10)

    assert "agent_analysis_result.analysis_id" in compile_mysql(analysis_query)
    assert "agent_report.id" in compile_mysql(report_query)


def test_task_and_report_models_construct_expected_defaults() -> None:
    task = AgentTask(task_type=TaskType.IP_ANALYSIS)
    item = AgentTaskItem(task_id=1, ip="192.0.2.1", scan_round=1)
    report = AgentReport(
        task_id=1,
        report_type=ReportType.IP,
        report_format=ReportFormat.JSON,
    )

    assert task.status is None  # SQLAlchemy applies this default at flush time.
    assert item.status is None
    assert report.task_item_id is None

