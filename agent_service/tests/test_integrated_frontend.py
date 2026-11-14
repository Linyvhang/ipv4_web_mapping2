from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "前端" / "index.html"


def test_integrated_frontend_uses_same_origin_agent_and_multiturn_chat() -> None:
    content = FRONTEND.read_text(encoding="utf-8")

    assert "const AGENT_BASE=''" in content
    assert "conversation_id:AGENT_CONVERSATION_ID" in content
    assert "data.priority_assets" in content
    assert "data.tools_used" in content
    assert "data.evidence" in content
    assert "resetAgentConversation" in content
    assert "/agent/conversations/" in content
    assert "renderAgent(result.result||result)" in content
    assert "ev.type==='error'" in content
    assert "function escapeHtml" in content
    assert "escapeHtml(r.confidence)" in content
    assert "l.includes('critical')" in content


def test_integrated_frontend_loads_platform_bootstrap() -> None:
    content = FRONTEND.read_text(encoding="utf-8")

    assert "apiJson('/api/bootstrap')" in content
    assert "FastAPI · MySQL · LangGraph" in content
    assert "SQLite 自有数据库" not in content
    assert "apiJson('/api/report'" in content
    assert 'report_type:"comprehensive"' in content
    assert 'scope:"latest_services"' in content
    assert "授权网段 3 段" not in content
    assert "授权网段白名单（3 段）" not in content
    assert "最新扫描批次中已发现服务的全部资产" in content
    assert "FastAPI 读取 MySQL 最新扫描批次并执行只读过滤" in content
    assert "MySQL 服务资产" in content
    assert "MySQL 聚合取数" in content
    assert "本页为前端模拟" not in content
    assert "Elasticsearch bool 查询" not in content
    assert "ES 索引 asset" not in content
    assert "SQL/ES 聚合取数" not in content
