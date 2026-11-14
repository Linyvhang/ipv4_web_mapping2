"""可视化模块使用的只读资产、任务状态和任务结果契约。"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from agent_service.models.analysis_schema import AnalysisResult, SchemaModel
from agent_service.models.input_schema import AssetAnalysisInput


TaskStatusValue = Literal["pending", "running", "success", "failed", "cancelled"]
TaskTypeValue = Literal["ip_analysis", "batch_analysis", "chat_analysis"]


class AssetScanDataResponse(AssetAnalysisInput):
    """数据库中已有的单 IP 扫描事实，不包含模型生成内容。"""


class SavedAnalysisResponse(SchemaModel):
    """已经保存且通过 Schema 校验的分析结果。"""

    analysis_id: str
    ip: str
    scan_round: int = Field(ge=1)
    result: AnalysisResult
    created_at: datetime
    updated_at: datetime


class TaskItemStatusResponse(SchemaModel):
    task_item_id: int = Field(ge=1)
    ip: str
    scan_round: int = Field(ge=1)
    status: TaskStatusValue
    error_message: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class TaskStatusResponse(SchemaModel):
    task_id: int = Field(ge=1)
    task_type: TaskTypeValue
    status: TaskStatusValue
    save_result: bool
    total: int = Field(ge=0)
    pending: int = Field(ge=0)
    running: int = Field(ge=0)
    success: int = Field(ge=0)
    failed: int = Field(ge=0)
    cancelled: int = Field(ge=0)
    error_message: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    items: list[TaskItemStatusResponse] = Field(default_factory=list)


class TaskResultItemResponse(SchemaModel):
    task_item_id: int = Field(ge=1)
    ip: str
    scan_round: int = Field(ge=1)
    status: TaskStatusValue
    error_message: str | None = None
    result: AnalysisResult | None = None


class TaskResultResponse(SchemaModel):
    task_id: int = Field(ge=1)
    task_type: TaskTypeValue
    status: TaskStatusValue
    error_message: str | None = None
    items: list[TaskResultItemResponse] = Field(default_factory=list)
