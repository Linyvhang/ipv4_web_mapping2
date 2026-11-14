from pathlib import Path


README = Path(__file__).resolve().parents[2] / "README.md"


def test_readme_contains_current_startup_and_test_commands() -> None:
    content = README.read_text(encoding="utf-8")

    assert "agent_service.api.mock_main:app" in content
    assert "agent_service.api.real_main:app" in content
    assert "python -m alembic upgrade head" in content
    assert "python -m pytest agent_service/tests -q" in content
    assert "http://127.0.0.1:8010/docs" in content
    assert "白名单 Agent 工具层" in content
    assert "POST /agent/chat" in content
    assert "http://127.0.0.1:8010/chat" in content
    assert "codex/langgraph-multi-step-agent" in content
    assert "ipv4-agent.service" in content
    assert "POST /api/report" in content


def test_readme_uses_placeholders_instead_of_credentials() -> None:
    content = README.read_text(encoding="utf-8")

    assert "AGENT_DB_PASSWORD=数据库密码" in content
    assert "DEEPSEEK_API_KEY=你的API密钥" in content
