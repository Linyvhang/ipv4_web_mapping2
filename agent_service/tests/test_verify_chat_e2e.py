import httpx
import pytest

from agent_service.scripts.verify_chat_e2e import run_acceptance


def payload(*, fallback_used=False, target_ip="192.0.2.10"):
    return {
        "answer": "发现 SSH 服务。",
        "intent": "query_scan_data",
        "target_ip": target_ip,
        "status": "success",
        "model_provider": "deepseek",
        "fallback_used": fallback_used,
        "tools_used": [
            {"name": "get_ip_scan_data", "status": "success", "message": "已读取"}
        ],
        "evidence": [],
        "limitations": ["回答仅基于已有扫描数据"],
    }


def client_for(data):
    def handler(request):
        assert request.url == "http://test/agent/chat"
        assert request.method == "POST"
        return httpx.Response(200, json=data)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_acceptance_validates_real_api_contract():
    with client_for(payload()) as client:
        result = run_acceptance(
            base_url="http://test", ip="192.0.2.10", client=client
        )
    assert result.model_provider == "deepseek"
    assert result.tools_used[0].name == "get_ip_scan_data"


@pytest.mark.parametrize(
    "data,error",
    [
        (payload(fallback_used=True), "安全降级"),
        (payload(target_ip="192.0.2.11"), "目标 IP"),
    ],
)
def test_acceptance_rejects_fallback_and_wrong_target(data, error):
    with client_for(data) as client:
        with pytest.raises(RuntimeError, match=error):
            run_acceptance(base_url="http://test", ip="192.0.2.10", client=client)


def test_acceptance_rejects_ipv6():
    with pytest.raises(ValueError, match="IPv4"):
        run_acceptance(base_url="http://test", ip="2001:db8::1")
