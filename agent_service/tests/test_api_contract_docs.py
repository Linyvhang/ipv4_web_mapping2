from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_api_contract_documents_all_visualization_routes() -> None:
    content = (ROOT / "docs" / "API接口契约.md").read_text(encoding="utf-8")
    for route in (
        "GET /api/health",
        "GET /api/bootstrap",
        "GET /api/search",
        "GET /assets/{ip}/scan-data",
        "GET /assets/{ip}/analysis",
        "GET /assets/{ip}/changes",
        "POST /analysis/ip",
        "POST /analysis/ip/stream",
        "POST /analysis/batch",
        "GET /analysis/tasks/{task_id}",
        "GET /analysis/tasks/{task_id}/result",
        "POST /analysis/tasks/{task_id}/report",
        "GET /analysis/tasks/{task_id}/report",
        "POST /agent/chat",
    ):
        assert route in content
    assert "不触发主动扫描" in content
    assert "application/x-ndjson" in content
    assert "2～50" in content
    assert "不接受 CIDR" in content
    assert "不调用大模型" in content
    assert "from_scan_round" in content
    assert "to_scan_round" in content


def test_visualization_handoff_is_directly_actionable() -> None:
    content = (ROOT / "docs" / "可视化模块对接说明.md").read_text(encoding="utf-8")
    assert "第一版请优先完成单 IP 分析结果页面" in content
    assert "http://127.0.0.1:8003/docs" in content
    assert "API接口契约.md" in content
    assert "不会主动扫描" in content
