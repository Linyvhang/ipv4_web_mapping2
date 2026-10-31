import pytest

from agent_service.db.session import DatabaseSettings


def test_database_settings_builds_async_url_without_exposing_password() -> None:
    settings = DatabaseSettings.from_env(
        {
            "AGENT_DB_HOST": "127.0.0.1",
            "AGENT_DB_PORT": "3306",
            "AGENT_DB_NAME": "ipv4scan",
            "AGENT_DB_USER": "agent_reader",
            "AGENT_DB_PASSWORD": "secret-password",
        }
    )

    assert settings.url().drivername == "mysql+aiomysql"
    assert settings.url().port == 3306
    assert "secret-password" not in settings.safe_url()
    assert "agent_reader" in settings.safe_url()


def test_database_settings_rejects_missing_required_values() -> None:
    with pytest.raises(ValueError, match="AGENT_DB_PASSWORD"):
        DatabaseSettings.from_env(
            {
                "AGENT_DB_HOST": "127.0.0.1",
                "AGENT_DB_NAME": "ipv4scan",
                "AGENT_DB_USER": "agent_reader",
            }
        )


def test_database_settings_rejects_invalid_port() -> None:
    with pytest.raises(ValueError, match="必须是整数"):
        DatabaseSettings.from_env(
            {
                "AGENT_DB_HOST": "127.0.0.1",
                "AGENT_DB_PORT": "not-a-port",
                "AGENT_DB_NAME": "ipv4scan",
                "AGENT_DB_USER": "agent_reader",
                "AGENT_DB_PASSWORD": "secret",
            }
        )
