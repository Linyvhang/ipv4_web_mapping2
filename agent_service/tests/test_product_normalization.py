import pytest

from agent_service.normalization.product import extract_product_fields, normalize_product


def test_normalize_nginx_product_and_version() -> None:
    result = normalize_product("Server: nginx/1.24.0", evidence=["HTTP Server header"])

    assert result.raw_product_name == "Server: nginx/1.24.0"
    assert result.normalized_product_name == "nginx"
    assert result.normalized_version == "1.24.0"
    assert result.normalization_confidence == 0.95
    assert "HTTP Server header" in result.normalization_evidence


@pytest.mark.parametrize(
    ("raw_name", "raw_version", "expected_product", "expected_version"),
    [
        ("OpenSSH_8.9p1", None, "openssh", "8.9p1"),
        ("MariaDB", "10.6.16", "mariadb", "10.6.16"),
        ("PostgreSQL server", "v15.4", "postgresql", "15.4"),
        ("Microsoft IIS", "10.0", "microsoft-iis", "10.0"),
    ],
)
def test_normalize_common_aliases(
    raw_name: str,
    raw_version: str | None,
    expected_product: str,
    expected_version: str,
) -> None:
    result = normalize_product(raw_name, raw_version)

    assert result.normalized_product_name == expected_product
    assert result.normalized_version == expected_version
    assert result.normalization_confidence == 0.95


def test_unknown_product_is_preserved_with_lower_confidence() -> None:
    result = normalize_product("Vendor Custom Gateway", "release-2026")

    assert result.normalized_product_name == "vendor-custom-gateway"
    assert result.normalized_version is None
    assert result.normalization_confidence == 0.60


def test_missing_product_becomes_unknown() -> None:
    result = normalize_product(None, None)

    assert result.normalized_product_name == "unknown"
    assert result.normalized_version is None
    assert result.normalization_confidence == 0.0


def test_original_values_are_not_overwritten() -> None:
    result = normalize_product(" nginx / 1.24.0 ", " v1.24.0 ")

    assert result.raw_product_name == "nginx / 1.24.0"
    assert result.raw_version == "v1.24.0"
    assert result.normalized_product_name == "nginx"
    assert result.normalized_version == "1.24.0"


def test_extract_ssh_product_from_software() -> None:
    product, version, evidence = extract_product_fields(
        service_type="ssh",
        application_protocol="ssh",
        banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        detail={"software": "OpenSSH_8.9p1"},
    )

    assert product == "OpenSSH_8.9p1"
    assert version is None
    assert evidence == ["ssh_service_detail.software"]


def test_extract_database_product_and_version() -> None:
    product, version, evidence = extract_product_fields(
        service_type="db",
        application_protocol="mysql",
        banner="MySQL Server",
        detail={"db_type": "mariadb", "version": "10.6.16"},
    )

    assert product == "mariadb"
    assert version == "10.6.16"
    assert evidence == ["db_service_detail.db_type"]


def test_extract_web_product_from_fingerprint_when_server_missing() -> None:
    product, version, evidence = extract_product_fields(
        service_type="web",
        application_protocol="http",
        banner=None,
        detail={
            "web_fingerprint": {
                "fingerprints": [{"name": "WordPress", "evidence": "wp-content"}]
            }
        },
    )

    assert product == "WordPress"
    assert version is None
    assert evidence == ["web_service_detail.web_fingerprint"]

