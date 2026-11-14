from datetime import datetime
from ipaddress import IPv4Address

import pytest

from agent_service.services.platform_dashboard import PlatformDashboardService
from agent_service.models.platform_schema import PlatformAssetRow


def test_build_bootstrap_uses_latest_scan_facts_and_saved_risk() -> None:
    response = PlatformDashboardService.build_bootstrap(
        scan_round=3,
        hosts=[
            {
                "id": 10,
                "ip_address": int(IPv4Address("10.0.0.8")),
                "first_seen": datetime(2026, 11, 14, 8),
                "last_seen": datetime(2026, 11, 14, 9),
            },
            {
                "id": 11,
                "ip_address": int(IPv4Address("8.8.8.8")),
                "first_seen": datetime(2026, 11, 13, 8),
                "last_seen": datetime(2026, 11, 14, 9),
            },
        ],
        services=[
            {
                "id": 20,
                "active_host_id": 10,
                "ip_address": int(IPv4Address("10.0.0.8")),
                "port": 22,
                "transport_protocol": "tcp",
                "service_type": "ssh",
                "application_proto": "ssh",
                "banner": "SSH-2.0-OpenSSH_9.2",
                "confidence": 0.9,
                "scan_time": datetime(2026, 11, 14, 9),
            },
            {
                "id": 21,
                "active_host_id": 11,
                "ip_address": int(IPv4Address("8.8.8.8")),
                "port": 53,
                "transport_protocol": "udp",
                "service_type": "dns",
                "application_proto": "dns",
                "banner": None,
                "confidence": 0.8,
                "scan_time": datetime(2026, 11, 14, 9),
            },
        ],
        analyses=[
            {
                "ip": "10.0.0.8",
                "result_json": {"summary": {"risk_level": "high"}},
            }
        ],
    )

    assert response.overview.scan_round == 3
    assert response.overview.host == 2
    assert response.overview.port == 2
    assert response.overview.tcp == 1
    assert response.overview.udp == 1
    assert response.overview.riskHigh == 1
    assert response.overview.privPct == 50.0
    assert response.assets[0].risk == "high"
    assert response.assets[0].subnet == "10.0.0.0/24"
    assert response.assets[1].risk == "unknown"
    assert response.stats.portTop10 == [("22", 1), ("53", 1)]
    assert response.stats.highList[0].ip == "10.0.0.8"
    assert response.stats.provinces == []
    assert any("地理位置" in item for item in response.limitations)


def test_build_bootstrap_handles_empty_database_without_fake_trends() -> None:
    response = PlatformDashboardService.build_bootstrap(
        scan_round=None,
        hosts=[],
        services=[],
        analyses=[],
    )

    assert response.overview.host == 0
    assert response.overview.port == 0
    assert response.stats.trend.days == []
    assert response.assets == []
    assert "unknown" in response.limitations[1]


def test_search_parser_filters_only_whitelisted_asset_fields() -> None:
    asset = PlatformAssetRow(
        ip="192.0.2.10",
        port=22,
        proto="tcp",
        service="ssh · SSH-2.0-OpenSSH_9.2",
        risk="medium",
        subnet="公网",
        loc="未知",
        conf=0.9,
    )
    conditions = PlatformDashboardService._parse_search_query(
        "port=22 && service=openssh && risk=mid"
    )

    assert PlatformDashboardService._matches_conditions(asset, conditions)
    assert not PlatformDashboardService._matches_conditions(
        asset,
        PlatformDashboardService._parse_search_query("proto=udp"),
    )

    for query in ("host=1", "port", "port=70000", "risk="):
        try:
            PlatformDashboardService._parse_search_query(query)
        except ValueError:
            pass
        else:  # pragma: no cover - 失败时提供清晰断言
            raise AssertionError(f"无效检索语法未被拒绝: {query}")


@pytest.mark.asyncio
async def test_search_returns_requested_page_and_full_match_list() -> None:
    bootstrap = PlatformDashboardService.build_bootstrap(
        scan_round=1,
        hosts=[
            {
                "id": index,
                "ip_address": int(IPv4Address(f"192.0.2.{index}")),
                "first_seen": None,
                "last_seen": None,
            }
            for index in range(1, 18)
        ],
        services=[
            {
                "active_host_id": index,
                "ip_address": int(IPv4Address(f"192.0.2.{index}")),
                "port": 22,
                "transport_protocol": "tcp",
                "service_type": "ssh",
                "application_proto": "ssh",
                "banner": "OpenSSH",
                "confidence": 0.9,
            }
            for index in range(1, 18)
        ],
        analyses=[],
    )

    class StubDashboard(PlatformDashboardService):
        async def bootstrap(self):
            return bootstrap

    service = StubDashboard(session_factory=None, db_name="test")
    response = await service.search("port=22 && service=openssh", page=2)

    assert response.total == 17
    assert len(response.rows) == 2
    assert len(response.list) == 17
