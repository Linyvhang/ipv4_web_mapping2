"""从批量任务的标准分析结果生成确定性 JSON 汇总报告。"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from agent_service.db.models import ReportFormat, ReportType, TaskStatus, TaskType
from agent_service.db.repositories import (
    AgentAnalysisRepository,
    AgentReportRepository,
    AgentTaskRepository,
)
from agent_service.models.analysis_schema import AnalysisResult
from agent_service.models.batch_report_schema import (
    AttentionAssetItem,
    BatchReportOverview,
    BatchStatisticsReport,
    FailedAssetItem,
    NamedCount,
    PortStatistics,
    ProductStatistics,
    RiskLevelCount,
    SavedBatchReportResponse,
)


class BatchReportTaskNotFoundError(LookupError):
    pass


class BatchReportNotFoundError(LookupError):
    pass


class BatchReportTaskTypeError(ValueError):
    pass


class BatchReportTaskNotCompletedError(RuntimeError):
    pass


RISK_LEVELS = ("info", "low", "medium", "high", "critical")


def _enum_value(value: Any) -> str:
    return getattr(value, "value", str(value))


def _percentage(count: int, total: int) -> float:
    return round((count / total * 100.0) if total else 0.0, 2)


class BatchReportService:
    def __init__(
        self,
        *,
        session_factory: Any,
        task_repository_factory=AgentTaskRepository,
        analysis_repository_factory=AgentAnalysisRepository,
        report_repository_factory=AgentReportRepository,
    ) -> None:
        self.session_factory = session_factory
        self.task_repository_factory = task_repository_factory
        self.analysis_repository_factory = analysis_repository_factory
        self.report_repository_factory = report_repository_factory

    async def get_report(self, task_id: int) -> SavedBatchReportResponse:
        async with self.session_factory() as session:
            repository = self.report_repository_factory(session)
            record = await repository.get_task_report(
                task_id,
                report_type=ReportType.BATCH,
                report_format=ReportFormat.JSON,
            )
            if record is None:
                raise BatchReportNotFoundError(
                    f"批量任务 {task_id} 尚未生成 JSON 汇总报告"
                )
            return self._response(record, reused=True)

    async def generate_report(self, task_id: int) -> SavedBatchReportResponse:
        async with self.session_factory() as session:
            task_repository = self.task_repository_factory(session)
            analysis_repository = self.analysis_repository_factory(session)
            report_repository = self.report_repository_factory(session)

            task = await task_repository.get_task(task_id)
            if task is None:
                raise BatchReportTaskNotFoundError(f"未找到分析任务 {task_id}")
            if _enum_value(task.task_type) != TaskType.BATCH_ANALYSIS.value:
                raise BatchReportTaskTypeError("只有批量分析任务可以生成批量统计报告")
            if _enum_value(task.status) in {
                TaskStatus.PENDING.value,
                TaskStatus.RUNNING.value,
            }:
                raise BatchReportTaskNotCompletedError(
                    f"批量任务 {task_id} 尚未完成"
                )

            existing = await report_repository.get_task_report(
                task_id,
                report_type=ReportType.BATCH,
                report_format=ReportFormat.JSON,
            )
            if existing is not None:
                return self._response(existing, reused=True)

            items = await task_repository.get_task_items(task_id)
            records = await analysis_repository.get_by_task_item_ids(
                item.id for item in items
            )
            by_item = {record.task_item_id: record for record in records}
            results: list[AnalysisResult] = []
            missing_result_ips: list[str] = []
            for item in items:
                if _enum_value(item.status) != TaskStatus.SUCCESS.value:
                    continue
                record = by_item.get(item.id)
                if record is None:
                    record = await analysis_repository.get_cached_result(
                        ip=item.ip, scan_round=item.scan_round
                    )
                if record is None:
                    missing_result_ips.append(item.ip)
                else:
                    results.append(AnalysisResult.model_validate(record.result_json))

            report = self.build_report(
                task_id=task_id,
                target_count=max(task.target_count, len(items)),
                items=items,
                results=results,
                missing_result_ips=missing_result_ips,
            )
            record = await report_repository.create_report(
                task_id=task_id,
                report_type=ReportType.BATCH,
                report_format=ReportFormat.JSON,
                content_json=report.model_dump(mode="json"),
            )
            await session.commit()
            return self._response(record, reused=False)

    @staticmethod
    def build_report(
        *,
        task_id: int,
        target_count: int,
        items: list[Any],
        results: list[AnalysisResult],
        missing_result_ips: list[str],
    ) -> BatchStatisticsReport:
        asset_types: Counter[str] = Counter()
        asset_risks: Counter[str] = Counter()
        finding_risks: Counter[str] = Counter()
        limitations: Counter[str] = Counter()
        product_groups: dict[tuple[str, str | None], dict[str, Any]] = defaultdict(
            lambda: {"services": 0, "ips": set()}
        )
        port_groups: dict[tuple[int, str, str], dict[str, Any]] = defaultdict(
            lambda: {"services": 0, "ips": set()}
        )
        attention_items: list[AttentionAssetItem] = []

        for result in results:
            asset_type = result.summary.primary_asset_type or "未知"
            asset_types[asset_type] += 1
            asset_risks[result.summary.risk_level] += 1
            # 同一资产内相同限制只计一次，不同资产之间继续累计出现次数。
            limitations.update(set(result.limitations))
            finding_risks.update(risk.level for risk in result.risks)
            if result.summary.needs_attention or result.summary.risk_level in {
                "high",
                "critical",
            }:
                attention_items.append(
                    AttentionAssetItem(
                        ip=result.ip,
                        scan_round=result.scan_round,
                        risk_level=result.summary.risk_level,
                        risk_count=len(result.risks),
                        risk_titles=[risk.title for risk in result.risks],
                    )
                )
            for service in result.services:
                product = service.product
                product_name = "未知产品"
                version = None
                if product is not None:
                    product_name = (
                        product.normalized_product_name
                        or product.raw_product_name
                        or product_name
                    )
                    version = product.normalized_version or product.raw_version
                product_group = product_groups[(product_name, version)]
                product_group["services"] += 1
                product_group["ips"].add(result.ip)

                port_group = port_groups[
                    (service.port, service.transport_protocol, service.service_type)
                ]
                port_group["services"] += 1
                port_group["ips"].add(result.ip)

        failed_items = [
            FailedAssetItem(
                ip=item.ip,
                scan_round=item.scan_round,
                error_message=item.error_message,
            )
            for item in items
            if _enum_value(item.status) == TaskStatus.FAILED.value
        ]
        successful_assets = sum(
            _enum_value(item.status) == TaskStatus.SUCCESS.value for item in items
        )
        total_services = sum(len(result.services) for result in results)
        total_risks = sum(len(result.risks) for result in results)

        return BatchStatisticsReport(
            task_id=task_id,
            generated_at=datetime.utcnow(),
            overview=BatchReportOverview(
                target_count=target_count,
                successful_assets=successful_assets,
                failed_assets=len(failed_items),
                analyzed_assets=len(results),
                total_services=total_services,
                total_risks=total_risks,
                attention_assets=len(attention_items),
                missing_results=len(missing_result_ips),
            ),
            asset_type_distribution=[
                NamedCount(
                    name=name,
                    count=count,
                    percentage=_percentage(count, len(results)),
                )
                for name, count in sorted(
                    asset_types.items(), key=lambda pair: (-pair[1], pair[0])
                )
            ],
            asset_risk_distribution=[
                RiskLevelCount(
                    level=level,
                    count=asset_risks[level],
                    percentage=_percentage(asset_risks[level], len(results)),
                )
                for level in RISK_LEVELS
            ],
            finding_risk_distribution=[
                RiskLevelCount(
                    level=level,
                    count=finding_risks[level],
                    percentage=_percentage(finding_risks[level], total_risks),
                )
                for level in RISK_LEVELS
            ],
            products=[
                ProductStatistics(
                    product=name,
                    version=version,
                    service_count=data["services"],
                    asset_count=len(data["ips"]),
                    ips=sorted(data["ips"]),
                )
                for (name, version), data in sorted(
                    product_groups.items(),
                    key=lambda pair: (-pair[1]["services"], pair[0][0], pair[0][1] or ""),
                )
            ],
            ports=[
                PortStatistics(
                    port=port,
                    transport_protocol=protocol,
                    service_type=service_type,
                    service_count=data["services"],
                    asset_count=len(data["ips"]),
                    ips=sorted(data["ips"]),
                )
                for (port, protocol, service_type), data in sorted(
                    port_groups.items(), key=lambda pair: (pair[0][0], pair[0][1], pair[0][2])
                )
            ],
            failed_items=failed_items,
            attention_items=sorted(attention_items, key=lambda item: item.ip),
            missing_result_ips=sorted(missing_result_ips),
            limitation_distribution=[
                NamedCount(
                    name=name,
                    count=count,
                    percentage=_percentage(count, len(results)),
                )
                for name, count in sorted(
                    limitations.items(), key=lambda pair: (-pair[1], pair[0])
                )
            ],
        )

    @staticmethod
    def _response(record: Any, *, reused: bool) -> SavedBatchReportResponse:
        return SavedBatchReportResponse(
            report_id=record.id,
            task_id=record.task_id,
            reused=reused,
            report=BatchStatisticsReport.model_validate(record.content_json),
            created_at=record.created_at,
            updated_at=record.updated_at,
        )
