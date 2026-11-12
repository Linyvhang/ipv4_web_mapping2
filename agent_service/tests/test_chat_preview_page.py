from fastapi.testclient import TestClient

from agent_service.api.chat_preview import CHAT_PREVIEW_HTML, create_chat_preview_router


def test_chat_preview_page_is_served() -> None:
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(create_chat_preview_router())

    with TestClient(app) as client:
        response = client.get("/chat")

    assert response.status_code == 200
    assert "网络资产分析助手" in response.text
    assert "工具调用轨迹" in response.text
    assert "引用证据" in response.text
    assert "LangGraph 工作流" in response.text


def test_chat_preview_calls_agent_api_and_uses_safe_text_rendering() -> None:
    assert "fetch('/agent/chat'" in CHAT_PREVIEW_HTML
    assert "data.tools_used" in CHAT_PREVIEW_HTML
    assert "data.evidence" in CHAT_PREVIEW_HTML
    assert "data.model_provider" in CHAT_PREVIEW_HTML
    assert "data.fallback_used" in CHAT_PREVIEW_HTML
    assert "data.workflow_trace" in CHAT_PREVIEW_HTML
    assert "showWorkflow" in CHAT_PREVIEW_HTML
    assert "textContent" in CHAT_PREVIEW_HTML
    assert "innerHTML" not in CHAT_PREVIEW_HTML


def test_chat_preview_has_navigation_and_responsive_layout() -> None:
    assert 'href="/"' in CHAT_PREVIEW_HTML
    assert 'href="/docs"' in CHAT_PREVIEW_HTML
    assert "@media (max-width:900px)" in CHAT_PREVIEW_HTML
    assert "单轮问答 · 工具可追踪" in CHAT_PREVIEW_HTML
