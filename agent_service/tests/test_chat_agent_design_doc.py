from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DESIGN = ROOT / "docs" / "自然语言Agent设计方案.md"
README = ROOT / "README.md"


def test_chat_agent_design_defines_role_workflow_and_safety_boundary() -> None:
    content = DESIGN.read_text(encoding="utf-8")

    assert "IPv4 网络资产分析助手" in content
    assert "understand_question" in content
    assert "validate_request" in content
    assert "select_tool" in content
    assert "execute_tool" in content
    assert "evaluate_result" in content
    assert "compose_answer" in content
    assert "最多允许调用两个工具" in content
    assert "不能只依赖 Prompt" in content


def test_chat_agent_design_references_only_registered_tools() -> None:
    content = DESIGN.read_text(encoding="utf-8")

    assert "`get_ip_scan_data`" in content
    assert "`get_ip_analysis_result`" in content
    assert "`create_ip_analysis`" in content
    assert "任何未注册工具" in content


def test_readme_links_to_chat_agent_design() -> None:
    content = README.read_text(encoding="utf-8")

    assert "docs/自然语言Agent设计方案.md" in content
