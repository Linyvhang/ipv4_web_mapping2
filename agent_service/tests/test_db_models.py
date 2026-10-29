from sqlalchemy import inspect

from agent_service.db.models import (
    AgentAnalysisResult,
    AgentReport,
    AgentTask,
    AgentTaskItem,
    Base,
)


def test_agent_tables_are_registered() -> None:
    assert set(Base.metadata.tables) == {
        "agent_task",
        "agent_task_item",
        "agent_analysis_result",
        "agent_report",
    }


def test_task_table_contains_status_and_lifecycle_fields() -> None:
    columns = AgentTask.__table__.c

    assert {"task_type", "status", "save_result", "request_json", "summary_json"} <= set(
        columns.keys()
    )
    assert {"created_at", "started_at", "completed_at", "cancelled_at"} <= set(
        columns.keys()
    )
    assert columns["status"].nullable is False


def test_task_item_has_target_reuse_constraint() -> None:
    constraints = {
        constraint.name
        for constraint in AgentTaskItem.__table__.constraints
        if constraint.name
    }

    assert "uq_task_item_target" in constraints
    assert {"task_id", "ip", "scan_round"} <= set(
        next(
            constraint
            for constraint in AgentTaskItem.__table__.constraints
            if constraint.name == "uq_task_item_target"
        ).columns.keys()
    )


def test_analysis_result_has_ip_scan_round_reuse_constraint() -> None:
    constraints = {
        constraint.name
        for constraint in AgentAnalysisResult.__table__.constraints
        if constraint.name
    }

    assert "uq_analysis_ip_scan_round" in constraints
    assert "uq_analysis_task_item" in constraints
    assert AgentAnalysisResult.__table__.c.result_json.nullable is False


def test_report_supports_ip_and_batch_outputs() -> None:
    report_type = AgentReport.__table__.c.report_type.type
    report_format = AgentReport.__table__.c.report_format.type

    assert set(report_type.enums) == {"ip", "batch"}
    assert set(report_format.enums) == {"json", "markdown", "html"}
    assert AgentReport.__table__.c.task_item_id.nullable is True


def test_foreign_keys_and_indexes_are_defined() -> None:
    inspector = inspect(AgentAnalysisResult.__table__)

    foreign_key_targets = {
        fk.target_fullname for fk in inspector.foreign_key_constraints for fk in fk.elements
    }
    assert "agent_task_item.id" in foreign_key_targets

    index_names = {index.name for index in AgentAnalysisResult.__table__.indexes}
    assert "idx_analysis_scan_round" in index_names

