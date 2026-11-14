"""网络资产 Agent 的受控工具层。

工具只复用既有 Service、Repository 和 LangGraph，不接受 SQL，也不允许模型
指定数据库表。后续自然语言 Agent 只能通过 ``AssetAgentToolRegistry`` 的白名单
选择工具。
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address
from typing import Any, Literal

from pydantic import Field, field_validator

from agent_service.models.analysis_schema import AnalysisResult, SchemaModel
from agent_service.models.chat_schema import AgentToolName
from agent_service.services.ip_analysis import AssetNotFoundError
from agent_service.services.single_ip_graph import initial_state
from agent_service.services.task_orchestrator import (
    SingleIPExecution,
    SingleIPTaskOrchestrator,
)
from agent_service.services.asset_change import (
    AssetChangeService,
    ComparedAssetNotFoundError,
    ScanRoundNotFoundError,
)
from agent_service.services.batch_report import (
    BatchReportNotFoundError,
    BatchReportService,
)


class IPLookupInput(SchemaModel):
    """查询指定 IPv4 和可选扫描批次。"""

    ip: str
    scan_round: int | None = Field(default=None, ge=1)

    @field_validator("ip")
    @classmethod
    def validate_ipv4(cls, value: str) -> str:
        try:
            address = ip_address(value)
        except ValueError as exc:
            raise ValueError("ip must be a valid IPv4 address") from exc
        if not isinstance(address, IPv4Address):
            raise ValueError("ip must be a valid IPv4 address")
        return str(address)


class CreateIPAnalysisInput(IPLookupInput):
    """创建受控分析任务；不会触发主动扫描。"""

    save_result: bool = True


class CompareScanRoundsInput(SchemaModel):
    ip: str
    from_scan_round: int = Field(ge=1)
    to_scan_round: int = Field(ge=1)

    @field_validator("ip")
    @classmethod
    def validate_ipv4(cls, value: str) -> str:
        try:
            address = ip_address(value)
        except ValueError as exc:
            raise ValueError("ip must be a valid IPv4 address") from exc
        if not isinstance(address, IPv4Address):
            raise ValueError("ip must be a valid IPv4 address")
        return str(address)


class GetBatchReportInput(SchemaModel):
    task_id: int = Field(ge=1)


class AgentToolResult(SchemaModel):
    """所有工具共享的可序列化返回结构。"""

    tool_name: AgentToolName
    status: Literal["success", "not_found"]
    message: str
    data: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class AgentToolDefinition:
    """暴露给后续模型决策节点的工具元数据。"""

    name: AgentToolName
    description: str
    input_schema: type[SchemaModel]
    read_only: bool
    requires_explicit_request: bool = False


class UnknownAgentToolError(ValueError):
    """模型请求了白名单之外的工具。"""


class AgentToolPermissionError(PermissionError):
    """没有用户明确授权时尝试创建分析任务。"""


class AssetAgentToolRegistry:
    """资产查询和分析任务创建工具的白名单注册表。"""

    DEFINITIONS: tuple[AgentToolDefinition, ...] = (
        AgentToolDefinition(
            name="get_ip_scan_data",
            description="查询指定 IP 已有的扫描批次、服务和 L3 指纹，不执行新扫描。",
            input_schema=IPLookupInput,
            read_only=True,
        ),
        AgentToolDefinition(
            name="get_ip_analysis_result",
            description="查询指定 IP 已保存且经过校验的标准分析结果，不重新调用模型。",
            input_schema=IPLookupInput,
            read_only=True,
        ),
        AgentToolDefinition(
            name="create_ip_analysis",
            description="基于已有扫描数据创建单 IP 分析任务，不执行主动扫描或测试。",
            input_schema=CreateIPAnalysisInput,
            read_only=False,
            requires_explicit_request=True,
        ),
        AgentToolDefinition(
            name="compare_ip_scan_rounds",
            description="只读比较同一 IP 两个已有扫描批次的服务、产品版本和风险变化。",
            input_schema=CompareScanRoundsInput,
            read_only=True,
        ),
        AgentToolDefinition(
            name="get_batch_report",
            description="按批量任务 ID 查询已经保存的批量统计 JSON 报告，不生成新报告。",
            input_schema=GetBatchReportInput,
            read_only=True,
        ),
    )

    def __init__(
        self,
        *,
        orchestrator: SingleIPTaskOrchestrator,
        graph: Any,
        asset_change_service: AssetChangeService | None = None,
        batch_report_service: BatchReportService | None = None,
    ) -> None:
        self.orchestrator = orchestrator
        self.graph = graph
        self.asset_change_service = asset_change_service
        self.batch_report_service = batch_report_service
        self._definitions = {definition.name: definition for definition in self.DEFINITIONS}

    @property
    def definitions(self) -> tuple[AgentToolDefinition, ...]:
        """返回固定顺序的工具定义，供模型绑定和界面展示。"""

        return self.DEFINITIONS

    async def execute(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        allow_task_creation: bool = False,
    ) -> AgentToolResult:
        """校验参数并执行白名单工具。"""

        definition = self._definitions.get(name)
        if definition is None:
            raise UnknownAgentToolError(f"未注册的 Agent 工具: {name}")
        if definition.requires_explicit_request and not allow_task_creation:
            raise AgentToolPermissionError(
                "create_ip_analysis 需要用户明确要求创建分析任务"
            )

        parsed = definition.input_schema.model_validate(arguments)
        if name == "get_ip_scan_data":
            return await self._get_ip_scan_data(parsed)
        if name == "get_ip_analysis_result":
            return await self._get_ip_analysis_result(parsed)
        if name == "create_ip_analysis":
            return await self._create_ip_analysis(parsed)
        if name == "compare_ip_scan_rounds":
            return await self._compare_scan_rounds(parsed)
        if name == "get_batch_report":
            return await self._get_batch_report(parsed)
        raise UnknownAgentToolError(f"未注册的 Agent 工具: {name}")  # pragma: no cover

    async def _load_asset(self, request: IPLookupInput):
        return await self.orchestrator.load_asset(
            request.ip, scan_round=request.scan_round
        )

    @staticmethod
    def _not_found(name: AgentToolName, request: IPLookupInput, message: str):
        return AgentToolResult(
            tool_name=name,
            status="not_found",
            message=message,
            data={"found": False, "ip": request.ip, "scan_round": request.scan_round},
        )

    async def _get_ip_scan_data(self, request: IPLookupInput) -> AgentToolResult:
        try:
            asset = await self._load_asset(request)
        except AssetNotFoundError:
            return self._not_found(
                "get_ip_scan_data", request, "未找到该 IP 的已有扫描数据"
            )
        return AgentToolResult(
            tool_name="get_ip_scan_data",
            status="success",
            message="已读取该 IP 的已有扫描数据",
            data={"found": True, "asset": asset.model_dump(mode="json")},
        )

    async def _get_ip_analysis_result(
        self, request: IPLookupInput
    ) -> AgentToolResult:
        try:
            asset = await self._load_asset(request)
        except AssetNotFoundError:
            return self._not_found(
                "get_ip_analysis_result", request, "未找到该 IP 的已有扫描数据"
            )

        record = await self.orchestrator.analysis_repository.get_cached_result(
            ip=asset.ip, scan_round=asset.scan_round
        )
        if record is None:
            return AgentToolResult(
                tool_name="get_ip_analysis_result",
                status="not_found",
                message="该 IP 和扫描批次尚无已保存的分析结果",
                data={"found": False, "ip": asset.ip, "scan_round": asset.scan_round},
            )

        result_json = record.result_json
        result = AnalysisResult.model_validate(result_json)
        return AgentToolResult(
            tool_name="get_ip_analysis_result",
            status="success",
            message="已读取保存的分析结果",
            data={"found": True, "result": result.model_dump(mode="json")},
        )

    async def _create_ip_analysis(
        self, request: CreateIPAnalysisInput
    ) -> AgentToolResult:
        state = await self.graph.ainvoke(
            initial_state(
                request.ip,
                scan_round=request.scan_round,
                save_result=request.save_result,
            )
        )
        execution: SingleIPExecution = state["execution"]
        result = execution.result
        result_json = (
            result.model_dump(mode="json")
            if isinstance(result, AnalysisResult)
            else result.result_json
        )
        return AgentToolResult(
            tool_name="create_ip_analysis",
            status="success",
            message="已复用现有分析结果" if execution.reused else "已完成新的分析任务",
            data={
                "found": True,
                "task_id": execution.task_id,
                "task_item_id": execution.task_item_id,
                "reused": execution.reused,
                "result": result_json,
            },
        )

    async def _compare_scan_rounds(
        self, request: CompareScanRoundsInput
    ) -> AgentToolResult:
        if self.asset_change_service is None:
            raise ValueError("历史变化对比工具尚未配置")
        try:
            comparison = await self.asset_change_service.compare(
                request.ip,
                from_scan_round=request.from_scan_round,
                to_scan_round=request.to_scan_round,
            )
        except (ComparedAssetNotFoundError, ScanRoundNotFoundError) as exc:
            return AgentToolResult(
                tool_name="compare_ip_scan_rounds",
                status="not_found",
                message=str(exc),
                data={
                    "found": False,
                    "ip": request.ip,
                    "from_scan_round": request.from_scan_round,
                    "to_scan_round": request.to_scan_round,
                },
            )
        return AgentToolResult(
            tool_name="compare_ip_scan_rounds",
            status="success",
            message="已比较两个扫描批次的资产变化",
            data={"found": True, "comparison": comparison.model_dump(mode="json")},
        )

    async def _get_batch_report(
        self, request: GetBatchReportInput
    ) -> AgentToolResult:
        if self.batch_report_service is None:
            raise ValueError("批量报告查询工具尚未配置")
        try:
            response = await self.batch_report_service.get_report(request.task_id)
        except BatchReportNotFoundError as exc:
            return AgentToolResult(
                tool_name="get_batch_report",
                status="not_found",
                message=str(exc),
                data={"found": False, "task_id": request.task_id},
            )
        return AgentToolResult(
            tool_name="get_batch_report",
            status="success",
            message="已读取保存的批量统计报告",
            data={
                "found": True,
                "report_id": response.report_id,
                "task_id": response.task_id,
                "report": response.report.model_dump(mode="json"),
            },
        )
