"""将扫描表行归一化为 Agent 输入对象。"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_service.normalization.product import extract_product_fields, normalize_product

from .input_schema import AssetAnalysisInput, L3ServiceInput


DETAIL_TABLE_BY_SERVICE_TYPE = {
    "web": "web_service_detail",
    "ssh": "ssh_service_detail",
    "db": "db_service_detail",
    "rdp": "rdp_service_detail",
    "telnet": "iot_service_detail",
    "ftp": "iot_service_detail",
    "iot": "iot_service_detail",
    "unknown": "iot_service_detail",
}


def _row_value(row: Mapping[str, Any], key: str, default: Any = None) -> Any:
    return row.get(key, default)


def uint32_to_ip(value: int) -> str:
    """将现有 active_host 的 IPv4 整数值转换为点分十进制。"""

    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("IPv4 integer must be between 0 and 2^32-1")
    return ".".join(
        str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0)
    )


def normalize_service(
    service_row: Mapping[str, Any],
    detail_row: Mapping[str, Any] | None = None,
) -> L3ServiceInput:
    """归并一条 L2 服务记录和对应 L3 detail 记录。"""

    service_type = str(_row_value(service_row, "service_type", "unknown")).lower()
    detail_table = DETAIL_TABLE_BY_SERVICE_TYPE.get(service_type)
    detail = dict(detail_row or {})
    detail.pop("id", None)
    detail.pop("service_instance_id", None)
    detail.pop("ip_address", None)
    detail.pop("port", None)
    detail.pop("transport_protocol", None)
    detail.pop("plugin_name", None)
    detail.pop("scan_status", None)
    detail.pop("error_message", None)
    detail.pop("scan_time", None)
    detail.pop("created_at", None)
    detail.pop("updated_at", None)
    raw_product, raw_version, product_evidence = extract_product_fields(
        service_type=service_type,
        application_protocol=service_row.get("application_proto"),
        banner=service_row.get("banner"),
        detail=detail,
    )

    return L3ServiceInput(
        service_instance_id=int(service_row["id"]),
        active_host_id=int(service_row["active_host_id"]),
        port=int(service_row["port"]),
        transport_protocol=service_row.get("transport_protocol") or "tcp",
        service_type=service_type,
        application_protocol=service_row.get("application_proto"),
        banner=service_row.get("banner"),
        confidence=float(service_row.get("confidence") or 0),
        l2_scan_status=int(service_row.get("scan_status") or 0),
        l2_scan_time=service_row.get("scan_time"),
        l3_scan_status=service_row.get("l3_scan_status"),
        l3_scan_time=service_row.get("l3_scan_time"),
        detail_table=detail_table,
        detail=detail,
        product=normalize_product(
            raw_product,
            raw_version,
            evidence=product_evidence,
        ),
    )


def normalize_asset(
    host_row: Mapping[str, Any],
    service_rows: list[Mapping[str, Any]],
    detail_rows: Mapping[int, Mapping[str, Any] | None] | None = None,
) -> AssetAnalysisInput:
    """将主机、服务和 L3 明细行整理成单 IP Agent 输入。"""

    details = detail_rows or {}
    services = [
        normalize_service(row, details.get(int(row["id"])))
        for row in service_rows
    ]
    limitations = ["本次输入仅包含已有 L1/L2/L3 扫描数据"]
    if not services:
        limitations.append("当前扫描数据中未发现可分析服务")

    return AssetAnalysisInput(
        ip=uint32_to_ip(int(host_row["ip_address"])),
        scan_round=int(host_row["scan_round"]),
        active_host_id=int(host_row["id"]),
        alive_type=int(host_row["alive_type"]),
        first_seen=host_row.get("first_seen"),
        last_seen=host_row.get("last_seen"),
        scanner_node=host_row.get("scanner_node"),
        services=services,
        limitations=limitations,
    )

