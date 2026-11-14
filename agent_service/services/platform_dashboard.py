"""从现有 MySQL 扫描表生成 NetScope 前端初始化数据。"""

from __future__ import annotations

from collections import Counter, defaultdict
import json
from datetime import UTC, date, datetime
from ipaddress import IPv4Address, ip_network
from time import perf_counter
from typing import Any

from sqlalchemy import func, select, text

from agent_service.db.models import AgentAnalysisResult
from agent_service.db.scan_tables import active_host, service_instance_l2
from agent_service.models.input_normalizer import uint32_to_ip
from agent_service.models.platform_schema import (
    PlatformAssetRow,
    PlatformBootstrapResponse,
    PlatformHealthResponse,
    PlatformHighRiskItem,
    PlatformOverview,
    PlatformRiskSubnet,
    PlatformStats,
    PlatformSearchResponse,
    PlatformReportNarrative,
    PlatformReportResponse,
    PlatformReportSection,
    PlatformReportStatistics,
    PlatformTrend,
)
from agent_service.providers.base import ModelProvider, ModelProviderError


RISK_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}


def _format_time(value: datetime | None) -> str | None:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else None


def _risk_from_result(payload: dict[str, Any] | None) -> str:
    value = str((payload or {}).get("summary", {}).get("risk_level") or "unknown").lower()
    return value if value in RISK_ORDER else "unknown"


def _service_category(service_type: str) -> str:
    normalized = service_type.lower()
    if normalized == "web":
        return "Web 服务"
    if normalized == "db":
        return "数据库"
    if normalized in {"ssh", "rdp"}:
        return "远程管理"
    if normalized in {"dns", "snmp"}:
        return "DNS/SNMP"
    return "其他"


class PlatformDashboardService:
    """平台接口适配层；只执行读取和确定性聚合。"""

    def __init__(
        self,
        *,
        session_factory,
        db_name: str,
        model_provider: ModelProvider | None = None,
    ):
        self.session_factory = session_factory
        self.db_name = db_name
        self.model_provider = model_provider

    async def health(self) -> PlatformHealthResponse:
        async with self.session_factory() as session:
            await session.execute(text("SELECT 1"))
        return PlatformHealthResponse(ok=True, db=self.db_name)

    async def bootstrap(self) -> PlatformBootstrapResponse:
        async with self.session_factory() as session:
            latest_round = await session.scalar(select(func.max(active_host.c.scan_round)))
            if latest_round is None:
                return self.build_bootstrap(scan_round=None, hosts=[], services=[], analyses=[])

            host_rows = (
                await session.execute(
                    select(active_host).where(active_host.c.scan_round == latest_round)
                )
            ).mappings().all()
            service_rows = (
                await session.execute(
                    select(
                        service_instance_l2,
                        active_host.c.first_seen.label("host_first_seen"),
                        active_host.c.last_seen.label("host_last_seen"),
                    )
                    .join(active_host, active_host.c.id == service_instance_l2.c.active_host_id)
                    .where(
                        active_host.c.scan_round == latest_round,
                        service_instance_l2.c.scan_status == 1,
                    )
                    .order_by(service_instance_l2.c.ip_address, service_instance_l2.c.port)
                )
            ).mappings().all()
            analysis_rows = (
                await session.execute(
                    select(AgentAnalysisResult.ip, AgentAnalysisResult.result_json).where(
                        AgentAnalysisResult.scan_round == latest_round
                    )
                )
            ).all()
        return self.build_bootstrap(
            scan_round=int(latest_round),
            hosts=[dict(row) for row in host_rows],
            services=[dict(row) for row in service_rows],
            analyses=[{"ip": row.ip, "result_json": row.result_json} for row in analysis_rows],
        )

    async def search(self, query: str, page: int) -> PlatformSearchResponse:
        """使用稳定白名单语法过滤最新批次资产，不接受任意 SQL。"""

        if page < 1:
            raise ValueError("page 必须是正整数")
        started = perf_counter()
        bootstrap = await self.bootstrap()
        conditions = self._parse_search_query(query)
        matches = [
            asset
            for asset in bootstrap.assets
            if self._matches_conditions(asset, conditions)
        ]
        start = (page - 1) * 15
        return PlatformSearchResponse(
            total=len(matches),
            ms=round(max((perf_counter() - started) * 1000, 0), 2),
            rows=matches[start : start + 15],
            list=matches,
        )

    async def generate_report(self) -> PlatformReportResponse:
        """聚合最新批次事实，并让模型只基于无 IP 的汇总数字撰写段落。"""

        bootstrap = await self.bootstrap()
        statistics = self._build_report_statistics(bootstrap)
        narrative: PlatformReportNarrative | None = None
        if self.model_provider is not None:
            prompt = self._build_report_prompt(
                scan_round=bootstrap.overview.scan_round,
                statistics=statistics,
                limitations=bootstrap.limitations,
            )
            try:
                narrative = await self.model_provider.generate_structured(
                    prompt, PlatformReportNarrative
                )
            except ModelProviderError:
                narrative = None

        engine = "llm" if narrative is not None else "template"
        sections = self._build_report_sections(
            statistics=statistics,
            limitations=bootstrap.limitations,
            narrative=narrative,
        )
        return PlatformReportResponse(
            scan_round=bootstrap.overview.scan_round,
            generated_at=datetime.now(UTC),
            engine=engine,
            sections=sections,
            statistics=statistics,
            limitations=bootstrap.limitations,
        )

    @staticmethod
    def _build_report_statistics(
        bootstrap: PlatformBootstrapResponse,
    ) -> PlatformReportStatistics:
        risk_by_ip: dict[str, str] = {}
        for asset in bootstrap.assets:
            current = risk_by_ip.get(asset.ip, "unknown")
            if RISK_ORDER[asset.risk] > RISK_ORDER[current]:
                risk_by_ip[asset.ip] = asset.risk
            else:
                risk_by_ip.setdefault(asset.ip, current)
        risk_counts = {risk: 0 for risk in RISK_ORDER}
        for risk in risk_by_ip.values():
            risk_counts[risk] += 1
        return PlatformReportStatistics(
            host_count=len(risk_by_ip),
            service_count=len(bootstrap.assets),
            tcp_count=sum(asset.proto == "tcp" for asset in bootstrap.assets),
            udp_count=sum(asset.proto == "udp" for asset in bootstrap.assets),
            risk_counts=risk_counts,
            top_ports=bootstrap.stats.portTop10,
        )

    @staticmethod
    def _build_report_prompt(
        *,
        scan_round: int | None,
        statistics: PlatformReportStatistics,
        limitations: list[str],
    ) -> str:
        context = {
            "scan_round": scan_round,
            "scope": "最新扫描批次中已发现服务的全部资产",
            "statistics": statistics.model_dump(mode="json"),
            "limitations": limitations,
        }
        return (
            "请根据以下聚合统计撰写面向普通用户的资产摘要、风险观察和1至5条处置建议。"
            "不得推断具体漏洞，不得声称风险已经验证，不得补充输入中没有的资产、产品或版本。"
            "unknown 表示尚无已保存的智能体风险分析。输入不包含 IP、Banner 或原始指纹。\n"
            + json.dumps(context, ensure_ascii=False, separators=(",", ":"))
        )

    @staticmethod
    def _build_report_sections(
        *,
        statistics: PlatformReportStatistics,
        limitations: list[str],
        narrative: PlatformReportNarrative | None,
    ) -> list[PlatformReportSection]:
        top_ports = "、".join(
            f"{port}端口 {count} 项" for port, count in statistics.top_ports[:5]
        ) or "暂无端口统计"
        high_count = statistics.risk_counts["critical"] + statistics.risk_counts["high"]
        unknown_count = statistics.risk_counts["unknown"]
        if narrative is None:
            summary = (
                f"本报告覆盖 {statistics.host_count} 个已发现服务的资产，共记录 "
                f"{statistics.service_count} 项服务；TCP {statistics.tcp_count} 项，"
                f"UDP {statistics.udp_count} 项。"
            )
            risk_observation = (
                f"代码统计发现 {high_count} 个资产处于高或严重风险等级，"
                f"另有 {unknown_count} 个资产尚无已保存的智能体风险分析。"
            )
            recommendations = [
                "优先复核高或严重风险资产对应的扫描证据。",
                "对风险未知的资产分批创建分析任务，补齐风险画像。",
                "结合后续扫描批次持续观察服务和产品变化。",
            ]
            narrative_source = "模板降级"
        else:
            summary = narrative.executive_summary
            risk_observation = narrative.risk_observation
            recommendations = narrative.recommendations
            narrative_source = "DeepSeek"

        sections = [
            PlatformReportSection(t="h", txt="一、执行摘要"),
            PlatformReportSection(t="p", txt=summary, src=narrative_source),
            PlatformReportSection(t="h", txt="二、服务暴露统计"),
            PlatformReportSection(
                t="p",
                txt=f"端口分布前列：{top_ports}。所有数值均由后端代码从数据库聚合。",
                src="代码统计",
            ),
            PlatformReportSection(t="h", txt="三、风险观察"),
            PlatformReportSection(t="p", txt=risk_observation, src=narrative_source),
            PlatformReportSection(t="h", txt="四、处置建议"),
        ]
        sections.extend(
            PlatformReportSection(t="p", txt=item, src=narrative_source)
            for item in recommendations
        )
        sections.extend(
            [
                PlatformReportSection(t="h", txt="五、数据范围与限制"),
                PlatformReportSection(
                    t="p",
                    txt="；".join(limitations) or "当前没有额外限制说明。",
                    src="系统说明",
                ),
            ]
        )
        return sections

    @staticmethod
    def _parse_search_query(query: str) -> list[tuple[str, str]]:
        normalized = query.strip()
        if not normalized:
            return []
        allowed = {"loc", "port", "proto", "risk", "service", "subnet"}
        conditions: list[tuple[str, str]] = []
        for expression in normalized.split("&&"):
            if "=" not in expression:
                raise ValueError("检索条件必须使用 key=value 格式")
            key, value = (part.strip() for part in expression.split("=", 1))
            if key not in allowed:
                names = "/".join(sorted(allowed))
                raise ValueError(f"不支持的字段：{key}（可用：{names}）")
            if not value:
                raise ValueError(f"字段 {key} 的值不能为空")
            if key == "port":
                try:
                    port = int(value)
                except ValueError as exc:
                    raise ValueError("port 必须是 1 到 65535 的整数") from exc
                if not 1 <= port <= 65535:
                    raise ValueError("port 必须是 1 到 65535 的整数")
            conditions.append((key, value))
        return conditions

    @staticmethod
    def _matches_conditions(
        asset: PlatformAssetRow,
        conditions: list[tuple[str, str]],
    ) -> bool:
        for key, expected in conditions:
            actual = str(getattr(asset, key))
            if key in {"service", "loc"}:
                if expected.casefold() not in actual.casefold():
                    return False
            elif key == "risk":
                normalized = "medium" if expected.casefold() == "mid" else expected.casefold()
                if actual.casefold() != normalized:
                    return False
            elif actual.casefold() != expected.casefold():
                return False
        return True

    @staticmethod
    def build_bootstrap(
        *,
        scan_round: int | None,
        hosts: list[dict[str, Any]],
        services: list[dict[str, Any]],
        analyses: list[dict[str, Any]],
    ) -> PlatformBootstrapResponse:
        risk_by_ip = {
            str(row["ip"]): _risk_from_result(row.get("result_json")) for row in analyses
        }
        host_by_id = {int(row["id"]): row for row in hosts}
        assets: list[PlatformAssetRow] = []
        category_counts: Counter[str] = Counter()
        port_counts: Counter[int] = Counter()
        risk_subnets: dict[str, Counter[str]] = defaultdict(Counter)

        for row in services:
            ip = uint32_to_ip(int(row["ip_address"]))
            address = IPv4Address(ip)
            host = host_by_id.get(int(row["active_host_id"]), {})
            first_seen = row.get("host_first_seen") or host.get("first_seen")
            last_seen = row.get("host_last_seen") or host.get("last_seen")
            service_type = str(row.get("service_type") or "unknown")
            application = str(row.get("application_proto") or "").strip()
            banner = str(row.get("banner") or "").strip() or None
            service = application or service_type
            if banner and banner.lower() not in service.lower():
                service = f"{service} · {banner}"
            risk = risk_by_ip.get(ip, "unknown")
            subnet = str(ip_network(f"{ip}/24", strict=False)) if address.is_private else "公网"
            loc = "内网" if address.is_private else "未知"
            asset = PlatformAssetRow(
                ip=ip,
                port=int(row["port"]),
                proto=str(row.get("transport_protocol") or "tcp").lower(),
                service=service,
                risk=risk,
                subnet=subnet,
                loc=loc,
                ttl=None,
                banner=banner,
                last=_format_time(last_seen),
                first=_format_time(first_seen),
                conf=float(row.get("confidence") or 0),
            )
            assets.append(asset)
            port_counts[asset.port] += 1
            category_counts[_service_category(service_type)] += 1
            if address.is_private:
                bucket = "high" if risk in {"critical", "high"} else "mid" if risk == "medium" else "low"
                risk_subnets[subnet][bucket] += 1

        tcp = sum(asset.proto == "tcp" for asset in assets)
        udp = sum(asset.proto == "udp" for asset in assets)
        unique_host_ips = {uint32_to_ip(int(row["ip_address"])) for row in hosts}
        private_hosts = sum(IPv4Address(ip).is_private for ip in unique_host_ips)
        today = date.today()
        new_today = sum(
            isinstance(row.get("first_seen"), datetime)
            and row["first_seen"].date() == today
            for row in hosts
        )
        high_assets = [asset for asset in assets if asset.risk in {"critical", "high"}]
        high_assets.sort(key=lambda item: (-RISK_ORDER[item.risk], int(IPv4Address(item.ip)), item.port))

        day_hosts: Counter[str] = Counter()
        for row in hosts:
            last_seen = row.get("last_seen")
            if isinstance(last_seen, datetime):
                day_hosts[last_seen.strftime("%m-%d")] += 1
        day_ports: Counter[str] = Counter()
        for row in services:
            scan_time = row.get("scan_time") or row.get("host_last_seen")
            if isinstance(scan_time, datetime):
                day_ports[scan_time.strftime("%m-%d")] += 1
        days = sorted(set(day_hosts) | set(day_ports))
        subnets = sorted(risk_subnets)

        limitations = ["平台概览只读取最新扫描批次和已经完成的 L2 服务记录"]
        if not analyses:
            limitations.append("当前批次没有已保存的 Agent 分析结果，资产风险显示为 unknown")
        limitations.extend(["扫描数据没有 TTL 和公网地理位置字段，对应值暂为空", "趋势只展示数据库中实际存在的扫描日期"])

        return PlatformBootstrapResponse(
            overview=PlatformOverview(
                scan_round=scan_round,
                host=len(unique_host_ips),
                port=len(assets),
                tcp=tcp,
                udp=udp,
                svcTypes=len({asset.service for asset in assets}),
                riskHigh=len(high_assets),
                newToday=new_today,
                tcpPct=round(tcp * 100 / len(assets), 1) if assets else 0,
                privPct=round(private_hosts * 100 / len(unique_host_ips), 1) if unique_host_ips else 0,
            ),
            stats=PlatformStats(
                portTop10=[(str(port), count) for port, count in port_counts.most_common(10)],
                svcDist=[
                    {"name": name, "value": category_counts.get(name, 0)}
                    for name in ("Web 服务", "数据库", "远程管理", "DNS/SNMP", "其他")
                ],
                trend=PlatformTrend(
                    days=days,
                    hosts=[day_hosts[day] for day in days],
                    ports=[day_ports[day] for day in days],
                ),
                riskSubnet=PlatformRiskSubnet(
                    subnets=subnets,
                    high=[risk_subnets[item]["high"] for item in subnets],
                    mid=[risk_subnets[item]["mid"] for item in subnets],
                    low=[risk_subnets[item]["low"] for item in subnets],
                ),
                provinces=[],
                highList=[
                    PlatformHighRiskItem(
                        ip=item.ip,
                        port=item.port,
                        proto=item.proto,
                        service=item.service,
                        risk=item.risk,
                    )
                    for item in high_assets[:6]
                ],
            ),
            assets=assets,
            limitations=limitations,
        )
