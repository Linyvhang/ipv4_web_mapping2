"""SQLAlchemy 数据模型。

本模块只声明表结构和约束，不连接数据库，也不执行建表操作。
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class TaskType(str, Enum):
    IP_ANALYSIS = "ip_analysis"
    BATCH_ANALYSIS = "batch_analysis"
    CHAT_ANALYSIS = "chat_analysis"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReportType(str, Enum):
    IP = "ip"
    BATCH = "batch"


class ReportFormat(str, Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"


def utc_now() -> datetime:
    """返回 UTC 时间，供 SQLAlchemy 默认值使用。"""

    return datetime.utcnow()


class Base(DeclarativeBase):
    pass


def enum_type(enum_cls: type[Enum], length: int) -> SAEnum:
    """让 MySQL 枚举列保存 Enum.value，而不是 Python 成员名。"""

    return SAEnum(
        enum_cls,
        native_enum=False,
        length=length,
        values_callable=lambda members: [member.value for member in members],
    )


class AgentTask(Base):
    """父任务：单 IP、批量分析或自然语言触发的临时分析。"""

    __tablename__ = "agent_task"
    __table_args__ = (
        Index("idx_agent_task_status_created", "status", "created_at"),
        {"comment": "Agent 分析父任务"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    task_type: Mapped[TaskType] = mapped_column(
        enum_type(TaskType, 32), nullable=False
    )
    status: Mapped[TaskStatus] = mapped_column(
        enum_type(TaskStatus, 16),
        nullable=False,
        default=TaskStatus.PENDING,
    )
    save_result: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    target_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    request_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    summary_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AgentTaskItem(Base):
    """子任务：批量任务中的一个 IP 分析项。"""

    __tablename__ = "agent_task_item"
    __table_args__ = (
        UniqueConstraint("task_id", "ip", "scan_round", name="uq_task_item_target"),
        Index("idx_agent_task_item_status", "status"),
        Index("idx_agent_task_item_ip_scan", "ip", "scan_round"),
        {"comment": "Agent IP 分析子任务"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("agent_task.id", ondelete="CASCADE"),
        nullable=False,
    )
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    scan_round: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[TaskStatus] = mapped_column(
        enum_type(TaskStatus, 16),
        nullable=False,
        default=TaskStatus.PENDING,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AgentAnalysisResult(Base):
    """经过 Schema 校验的单 IP 分析结果。"""

    __tablename__ = "agent_analysis_result"
    __table_args__ = (
        UniqueConstraint("task_item_id", name="uq_analysis_task_item"),
        UniqueConstraint("ip", "scan_round", name="uq_analysis_ip_scan_round"),
        Index("idx_analysis_scan_round", "scan_round"),
        {"comment": "Agent 标准分析结果"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    task_item_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("agent_task_item.id", ondelete="CASCADE"),
        nullable=False,
    )
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    scan_round: Mapped[int] = mapped_column(Integer, nullable=False)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    result_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    model_provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prompt_version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utc_now, onupdate=utc_now
    )


class AgentReport(Base):
    """IP 报告或批量汇总报告。"""

    __tablename__ = "agent_report"
    __table_args__ = (
        Index("idx_agent_report_task", "task_id"),
        Index("idx_agent_report_type", "report_type"),
        {"comment": "Agent 报告内容"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("agent_task.id", ondelete="CASCADE"),
        nullable=False,
    )
    task_item_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("agent_task_item.id", ondelete="CASCADE"),
        nullable=True,
    )
    analysis_result_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("agent_analysis_result.id", ondelete="SET NULL"),
        nullable=True,
    )
    report_type: Mapped[ReportType] = mapped_column(
        enum_type(ReportType, 16), nullable=False
    )
    report_format: Mapped[ReportFormat] = mapped_column(
        enum_type(ReportFormat, 16), nullable=False
    )
    content_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    content_text: Mapped[str | None] = mapped_column(LONGTEXT, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utc_now, onupdate=utc_now
    )

