# l3_store.py
"""第三层数据库读写。

职责：
    1. 从 service_instance_l2 读取待 L3 深扫的服务实例（按优先级排序）
    2. 将插件结果 UPSERT 到对应 detail 表
    3. 回写 service_instance_l2.l3_scan_status / l3_scan_time

L2 的 scan_status 语义保持不变：
    0=未完成, 1=完成, 2=异常
因此 L3 进度使用独立字段 l3_scan_status：
    0=待扫描, 1=完成, 2=异常
"""

import json
from typing import Dict, Iterable, List, Optional

import pymysql

from config import DB_CONFIG
from l3_plugins.base import ScanTarget

# L2 服务实例状态：仅扫描 L2 已完成的服务
L2_STATUS_DONE = 1
# L3 状态
L3_PENDING = 0
L3_DONE = 1
L3_ERROR = 2

# detail 表字段白名单：防止任何动态 SQL 注入
DETAIL_TABLE_FIELDS = {
    "web_service_detail": (
        "http_status", "title", "server_header", "x_powered_by",
        "tls_certificate", "web_fingerprint",
    ),
    "ssh_service_detail": (
        "protocol_version", "software", "os_guess", "auth_methods", "banner",
    ),
    "db_service_detail": ("db_type", "version", "banner", "features"),
    "rdp_service_detail": ("banner", "protocol_version", "encryption", "port_open"),
    "iot_service_detail": ("protocol_guess", "device_model", "banner"),
}

JSON_FIELDS = {"tls_certificate", "web_fingerprint", "auth_methods", "features"}


class L3StoreError(RuntimeError):
    """数据库读写错误"""


def connect() -> pymysql.connections.Connection:
    try:
        return pymysql.connect(**DB_CONFIG)
    except pymysql.err.OperationalError as exc:
        raise L3StoreError(
            f"数据库连接失败：{exc}；请检查 MySQL 与 config.py 中的数据库配置"
        ) from exc


def _dedupe(values: Iterable[str]) -> List[str]:
    result = []
    for value in values:
        value = (value or "").strip().lower()
        if value and value not in result:
            result.append(value)
    return result


def fetch_pending(limit: Optional[int] = None,
                  service_types: Optional[Iterable[str]] = None,
                  scan_round: Optional[int] = None) -> List[ScanTarget]:
    """读取待 L3 深度扫描的服务实例，按服务类型优先级 + 置信度排序

    scan_round 不为空时，仅取该轮 L1 发现的活跃主机上的服务实例。
    """
    types = _dedupe(service_types or [])

    sql = [
        """SELECT si.id, si.ip_address, si.port, si.transport_protocol,
                  si.service_type, si.application_proto, si.banner, si.confidence
           FROM service_instance_l2 si""",
    ]
    params: List[object] = []

    if scan_round is not None:
        sql.append("JOIN active_host ah ON ah.id = si.active_host_id")
        sql.append("WHERE si.scan_status = %s AND si.l3_scan_status = %s AND ah.scan_round = %s")
        params.extend([L2_STATUS_DONE, L3_PENDING, scan_round])
    else:
        sql.append("WHERE si.scan_status = %s AND si.l3_scan_status = %s")
        params.extend([L2_STATUS_DONE, L3_PENDING])

    if types:
        placeholders = ",".join(["%s"] * len(types))
        sql.append(f"AND LOWER(si.service_type) IN ({placeholders})")
        params.extend(types)

    sql.append(
        """ORDER BY CASE LOWER(si.service_type)
                      WHEN 'web' THEN 0 WHEN 'ssh' THEN 1 WHEN 'db' THEN 2 WHEN 'rdp' THEN 3
                      ELSE 4 END,
                  si.confidence DESC, si.id ASC"""
    )
    if limit:
        sql.append("LIMIT %s")
        params.append(int(limit))

    conn = connect()

    try:
        with conn.cursor() as cursor:
            cursor.execute("\n".join(sql), tuple(params))
            rows = cursor.fetchall()
    except pymysql.err.OperationalError as exc:
        if exc.args and exc.args[0] == 1054:
            raise L3StoreError(
                "service_instance_l2 缺少 l3_scan_status 字段，请先执行 init_l3_tables.py"
            ) from exc
        raise L3StoreError(f"读取待扫描服务失败：{exc}") from exc
    finally:
        conn.close()

    targets = [
        ScanTarget(
            service_instance_id=row[0],
            ip_address=row[1],
            port=row[2],
            transport_protocol=row[3] or "tcp",
            service_type=row[4] or "unknown",
            application_proto=row[5],
            banner=row[6],
            confidence=float(row[7] or 0),
        )
        for row in rows
    ]
    return targets


def save_result(conn, target: ScanTarget, plugin, result) -> None:
    """写入 detail 表并回写 L2 调度状态（同一事务）"""
    table = getattr(plugin, "table", "")
    if table not in DETAIL_TABLE_FIELDS:
        raise L3StoreError(f"插件 {plugin.plugin_name} 未配置合法的结果表: {table!r}")

    allowed = DETAIL_TABLE_FIELDS[table]
    unexpected = set(result.fields) - set(allowed)
    if unexpected:
        raise L3StoreError(
            f"插件 {plugin.plugin_name} 返回了 {table} 中不存在的字段: {sorted(unexpected)}"
        )

    row: Dict[str, object] = {}
    for field in allowed:
        value = result.fields.get(field)
        if field in JSON_FIELDS and value is not None:
            value = json.dumps(value, ensure_ascii=False, default=str)
        row[field] = value

    columns = [
        "service_instance_id", "ip_address", "port", "transport_protocol", "plugin_name",
    ] + list(allowed) + ["scan_status", "error_message", "scan_time", "created_at", "updated_at"]
    values: List[object] = [
        target.service_instance_id, target.ip_address, target.port,
        target.transport_protocol, result.plugin_name,
    ] + [row[field] for field in allowed] + [result.scan_status, result.error_message]

    # 时间字段统一用 NOW()，便于与数据库时区保持一致
    placeholders = ",".join(["%s"] * (len(columns) - 3) + ["NOW()", "NOW()", "NOW()"])

    update_columns = [name for name in columns if name not in (
        "service_instance_id", "ip_address", "port", "transport_protocol", "created_at",
    )]
    update_clause = ",\n        ".join(
        f"{name} = NOW()" if name in ("scan_time", "updated_at") else f"{name} = VALUES({name})"
        for name in update_columns
    )

    sql = f"""
        INSERT INTO {table} ({", ".join(columns)})
        VALUES ({placeholders})
        ON DUPLICATE KEY UPDATE
        {update_clause}
    """

    with conn.cursor() as cursor:
        cursor.execute(sql, tuple(values))
        cursor.execute(
            """UPDATE service_instance_l2
               SET l3_scan_status = %s, l3_scan_time = NOW(), updated_at = NOW()
               WHERE id = %s""",
            (L3_DONE if result.scan_status == 1 else L3_ERROR, target.service_instance_id),
        )


def mark_failed(conn, instance_id: int) -> None:
    """detail 写入失败时，仅回写 L3 异常状态"""
    with conn.cursor() as cursor:
        cursor.execute(
            """UPDATE service_instance_l2
               SET l3_scan_status = %s, l3_scan_time = NOW(), updated_at = NOW()
               WHERE id = %s""",
            (L3_ERROR, instance_id),
        )

