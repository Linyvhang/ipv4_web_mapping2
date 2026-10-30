"""现有 L1/L2/L3 扫描表的只读 SQLAlchemy 定义。

这些表由项目既有初始化脚本创建，本模块只用于构造查询，不负责建表。
"""

from sqlalchemy import JSON, BigInteger, Column, DateTime, Float, Integer, MetaData, String


scan_metadata = MetaData()

active_host = __import__("sqlalchemy").Table(
    "active_host",
    scan_metadata,
    Column("id", BigInteger),
    Column("ip_address", Integer),
    Column("alive_type", Integer),
    Column("first_seen", DateTime),
    Column("last_seen", DateTime),
    Column("scan_round", Integer),
    Column("scanner_node", String(64)),
)

service_instance_l2 = __import__("sqlalchemy").Table(
    "service_instance_l2",
    scan_metadata,
    Column("id", BigInteger),
    Column("active_host_id", BigInteger),
    Column("ip_address", Integer),
    Column("port", Integer),
    Column("transport_protocol", String(4)),
    Column("service_type", String(32)),
    Column("application_proto", String(16)),
    Column("banner", String(255)),
    Column("confidence", Float),
    Column("scan_status", Integer),
    Column("scan_time", DateTime),
    Column("l3_scan_status", Integer),
    Column("l3_scan_time", DateTime),
)


def _detail_table(name: str, columns: list[Column]) :
    return __import__("sqlalchemy").Table(name, scan_metadata, *columns)


DETAIL_TABLES = {
    "web_service_detail": _detail_table(
        "web_service_detail",
        [Column("id", BigInteger), Column("service_instance_id", BigInteger), Column("port", Integer), Column("http_status", Integer), Column("title", String(255)), Column("server_header", String(255)), Column("x_powered_by", String(255)), Column("tls_certificate", JSON), Column("web_fingerprint", JSON)],
    ),
    "ssh_service_detail": _detail_table(
        "ssh_service_detail",
        [Column("id", BigInteger), Column("service_instance_id", BigInteger), Column("port", Integer), Column("protocol_version", String(32)), Column("software", String(128)), Column("os_guess", String(64)), Column("auth_methods", JSON), Column("banner", String(255))],
    ),
    "db_service_detail": _detail_table(
        "db_service_detail",
        [Column("id", BigInteger), Column("service_instance_id", BigInteger), Column("port", Integer), Column("db_type", String(32)), Column("version", String(64)), Column("banner", String(255)), Column("features", JSON)],
    ),
    "rdp_service_detail": _detail_table(
        "rdp_service_detail",
        [Column("id", BigInteger), Column("service_instance_id", BigInteger), Column("port", Integer), Column("banner", String(255)), Column("protocol_version", String(64)), Column("encryption", String(64)), Column("port_open", Integer)],
    ),
    "iot_service_detail": _detail_table(
        "iot_service_detail",
        [Column("id", BigInteger), Column("service_instance_id", BigInteger), Column("port", Integer), Column("protocol_guess", String(32)), Column("device_model", String(128)), Column("banner", String(255))],
    ),
}

