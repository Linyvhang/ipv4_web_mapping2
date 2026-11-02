from agent_service.api.preview import create_preview_router


def render_preview(path: str) -> str:
    router = create_preview_router()
    route = next(route for route in router.routes if route.path == path)
    response = route.endpoint()
    return response.body.decode("utf-8")


def test_preview_page_is_available_from_root_and_preview_path() -> None:
    for path in ("/", "/preview"):
        html = render_preview(path)
        assert "IPv4 资产分析预览" in html
        assert "fetch('/analysis/ip'" in html


def test_preview_page_escapes_model_values_via_text_content() -> None:
    html = render_preview("/preview")

    assert "textContent = risk.description" in html
    assert "innerHTML" not in html
