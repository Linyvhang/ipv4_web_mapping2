"""从既有扫描表读取并整理 Agent 输入。"""

from __future__ import annotations

from collections.abc import Mapping

from sqlalchemy import Select, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from agent_service.models.input_normalizer import (
    DETAIL_TABLE_BY_SERVICE_TYPE,
    normalize_asset,
)
from agent_service.models.input_schema import AssetAnalysisInput

from .scan_tables import DETAIL_TABLES, active_host, service_instance_l2


class L3DataProvider:
    """只读查询 L1/L2/L3 数据并返回统一 Agent 输入。"""

    def __init__(self, session: AsyncSession):
        self.session = session

    @staticmethod
    def build_host_query(ip_value: int, scan_round: int | None = None) -> Select:
        statement = select(active_host).where(active_host.c.ip_address == ip_value)
        if scan_round is not None:
            statement = statement.where(active_host.c.scan_round == scan_round)
        else:
            statement = statement.order_by(desc(active_host.c.scan_round)).limit(1)
        return statement

    @staticmethod
    def build_services_query(host_id: int) -> Select:
        return (
            select(service_instance_l2)
            .where(
                service_instance_l2.c.active_host_id == host_id,
                service_instance_l2.c.scan_status == 1,
            )
            .order_by(service_instance_l2.c.port, service_instance_l2.c.id)
        )

    @staticmethod
    def build_detail_query(service_type: str, service_instance_id: int, port: int) -> Select | None:
        table_name = DETAIL_TABLE_BY_SERVICE_TYPE.get(service_type.lower())
        table = DETAIL_TABLES.get(table_name) if table_name else None
        if table is None:
            return None
        return select(table).where(
            table.c.service_instance_id == service_instance_id,
            table.c.port == port,
        )

    async def fetch_asset(
        self,
        *,
        ip_value: int,
        scan_round: int | None = None,
    ) -> AssetAnalysisInput | None:
        host_result = await self.session.execute(
            self.build_host_query(ip_value, scan_round)
        )
        host_row = host_result.mappings().first()
        if host_row is None:
            return None

        host = dict(host_row)
        service_result = await self.session.execute(
            self.build_services_query(int(host["id"]))
        )
        service_rows = [dict(row) for row in service_result.mappings().all()]
        detail_rows: dict[int, Mapping[str, object] | None] = {}
        for service in service_rows:
            detail_query = self.build_detail_query(
                str(service.get("service_type") or "unknown"),
                int(service["id"]),
                int(service["port"]),
            )
            if detail_query is None:
                detail_rows[int(service["id"])] = None
                continue
            detail_result = await self.session.execute(detail_query)
            row = detail_result.mappings().first()
            detail_rows[int(service["id"])] = dict(row) if row else None

        return normalize_asset(host, service_rows, detail_rows)

