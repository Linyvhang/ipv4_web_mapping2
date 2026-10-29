"""create Agent task, result and report tables

Revision ID: 0001_create_agent_tables
Revises:
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql


revision = "0001_create_agent_tables"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    task_status = sa.Enum(
        "pending", "running", "success", "failed", "cancelled",
        native_enum=False, length=16,
    )
    task_type = sa.Enum(
        "ip_analysis", "batch_analysis", "chat_analysis",
        native_enum=False, length=32,
    )

    op.create_table(
        "agent_task",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("task_type", task_type, nullable=False),
        sa.Column("status", task_status, nullable=False, server_default="pending"),
        sa.Column("save_result", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("target_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("request_json", sa.JSON(), nullable=True),
        sa.Column("summary_json", sa.JSON(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        comment="Agent 分析父任务",
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
    )
    op.create_index("idx_agent_task_status_created", "agent_task", ["status", "created_at"])

    op.create_table(
        "agent_task_item",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("task_id", sa.BigInteger(), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("scan_round", sa.Integer(), nullable=False),
        sa.Column("status", task_status, nullable=False, server_default="pending"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["task_id"], ["agent_task.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id", "ip", "scan_round", name="uq_task_item_target"),
        comment="Agent IP 分析子任务",
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
    )
    op.create_index("idx_agent_task_item_status", "agent_task_item", ["status"])
    op.create_index("idx_agent_task_item_ip_scan", "agent_task_item", ["ip", "scan_round"])

    op.create_table(
        "agent_analysis_result",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("analysis_id", sa.String(length=64), nullable=False),
        sa.Column("task_item_id", sa.BigInteger(), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("scan_round", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False, server_default="1.0"),
        sa.Column("result_json", sa.JSON(), nullable=False),
        sa.Column("model_provider", sa.String(length=64), nullable=False),
        sa.Column("model_name", sa.String(length=128), nullable=False),
        sa.Column("model_version", sa.String(length=64), nullable=True),
        sa.Column("prompt_version", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["task_item_id"], ["agent_task_item.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("analysis_id"),
        sa.UniqueConstraint("task_item_id", name="uq_analysis_task_item"),
        sa.UniqueConstraint("ip", "scan_round", name="uq_analysis_ip_scan_round"),
        comment="Agent 标准分析结果",
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
    )
    op.create_index("idx_analysis_scan_round", "agent_analysis_result", ["scan_round"])

    op.create_table(
        "agent_report",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("task_id", sa.BigInteger(), nullable=False),
        sa.Column("task_item_id", sa.BigInteger(), nullable=True),
        sa.Column("analysis_result_id", sa.BigInteger(), nullable=True),
        sa.Column("report_type", sa.Enum("ip", "batch", native_enum=False, length=16), nullable=False),
        sa.Column("report_format", sa.Enum("json", "markdown", "html", native_enum=False, length=16), nullable=False),
        sa.Column("content_json", sa.JSON(), nullable=True),
        sa.Column("content_text", mysql.LONGTEXT(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["analysis_result_id"], ["agent_analysis_result.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["task_id"], ["agent_task.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["task_item_id"], ["agent_task_item.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        comment="Agent 报告内容",
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
    )
    op.create_index("idx_agent_report_task", "agent_report", ["task_id"])
    op.create_index("idx_agent_report_type", "agent_report", ["report_type"])


def downgrade() -> None:
    op.drop_index("idx_agent_report_type", table_name="agent_report")
    op.drop_index("idx_agent_report_task", table_name="agent_report")
    op.drop_table("agent_report")
    op.drop_index("idx_analysis_scan_round", table_name="agent_analysis_result")
    op.drop_table("agent_analysis_result")
    op.drop_index("idx_agent_task_item_ip_scan", table_name="agent_task_item")
    op.drop_index("idx_agent_task_item_status", table_name="agent_task_item")
    op.drop_table("agent_task_item")
    op.drop_index("idx_agent_task_status_created", table_name="agent_task")
    op.drop_table("agent_task")

