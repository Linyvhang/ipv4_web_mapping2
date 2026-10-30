from datetime import datetime

from sqlalchemy.dialects import mysql

from agent_service.db.l3_data import L3DataProvider
from agent_service.models.input_normalizer import normalize_asset, normalize_service, uint32_to_ip


def test_uint32_to_ip_converts_existing_host_format() -> None:
    assert uint32_to_ip(0xC000020A) == "192.0.2.10"


def test_normalize_service_merges_l2_and_l3_detail() -> None:
    service = normalize_service(
        {
            "id": 12,
            "active_host_id": 7,
            "port": 443,
            "transport_protocol": "tcp",
            "service_type": "web",
            "application_proto": "https",
            "banner": "Server: nginx/1.24.0",
            "confidence": 0.95,
            "scan_status": 1,
            "scan_time": datetime(2026, 10, 30),
            "l3_scan_status": 1,
            "l3_scan_time": datetime(2026, 10, 30),
        },
        {
            "id": 99,
            "service_instance_id": 12,
            "port": 443,
            "server_header": "nginx/1.24.0",
            "http_status": 200,
            "scan_status": 1,
        },
    )

    assert service.service_type == "web"
    assert service.detail_table == "web_service_detail"
    assert service.detail == {"server_header": "nginx/1.24.0", "http_status": 200}


def test_normalize_asset_contains_services_and_limitations() -> None:
    result = normalize_asset(
        {
            "id": 7,
            "ip_address": 0xC000020A,
            "alive_type": 4,
            "first_seen": datetime(2026, 10, 29),
            "last_seen": datetime(2026, 10, 30),
            "scan_round": 1,
            "scanner_node": "scanner-1",
        },
        [
            {
                "id": 12,
                "active_host_id": 7,
                "port": 443,
                "service_type": "web",
                "transport_protocol": "tcp",
                "confidence": 0.95,
                "scan_status": 1,
            }
        ],
    )

    assert result.ip == "192.0.2.10"
    assert result.active_host_id == 7
    assert len(result.services) == 1
    assert "已有 L1/L2/L3 扫描数据" in result.limitations[0]


def test_query_builders_target_latest_host_and_detail_table() -> None:
    host_query = L3DataProvider.build_host_query(0xC000020A)
    latest_sql = str(host_query.compile(dialect=mysql.dialect()))
    detail_query = L3DataProvider.build_detail_query("web", 12, 443)
    detail_sql = str(detail_query.compile(dialect=mysql.dialect()))

    assert "active_host.scan_round" in latest_sql
    assert "LIMIT" in latest_sql
    assert "web_service_detail.service_instance_id" in detail_sql
    assert "web_service_detail.port" in detail_sql

