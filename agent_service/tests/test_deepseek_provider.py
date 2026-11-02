import asyncio
import json

import httpx
import pytest
from pydantic import BaseModel

from agent_service.providers.base import ModelProviderError
from agent_service.providers.deepseek import DeepSeekModelProvider


class Output(BaseModel):
    answer: str


def call_provider(handler):
    provider = DeepSeekModelProvider("test-secret", transport=httpx.MockTransport(handler))
    return asyncio.run(provider.generate_structured("只分析已有数据", Output))


def test_json_request_and_validated_output():
    def handler(request):
        body = json.loads(request.content)
        assert request.url == "https://api.deepseek.com/chat/completions"
        assert body["response_format"] == {"type": "json_object"}
        assert "JSON Schema" in body["messages"][0]["content"]
        assert request.headers["authorization"] == "Bearer test-secret"
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop",
            "message": {"content": '{"answer":"ok"}'}}]})
    assert call_provider(handler).answer == "ok"


@pytest.mark.parametrize("status", [401, 402, 429, 500])
def test_http_errors_hide_raw_body_and_credentials(status):
    with pytest.raises(ModelProviderError, match=f"HTTP {status}") as error:
        call_provider(lambda _: httpx.Response(status, text="test-secret"))
    assert "test-secret" not in str(error.value)


@pytest.mark.parametrize("content,reason", [("", "stop"), (" ", "stop"),
    ("not json", "stop"), ('{"wrong":1}', "stop"), ('{"answer":"ok"}', "length")])
def test_rejects_empty_invalid_or_truncated_output(content, reason):
    with pytest.raises(ModelProviderError):
        call_provider(lambda _: httpx.Response(200, json={"choices": [
            {"finish_reason": reason, "message": {"content": content}}]}))


def test_timeout_is_sanitized():
    def handler(request):
        raise httpx.ReadTimeout("test-secret", request=request)
    with pytest.raises(ModelProviderError, match="超时"):
        call_provider(handler)


def test_missing_key_and_model_configuration():
    with pytest.raises(ValueError, match="DEEPSEEK_API_KEY"):
        DeepSeekModelProvider.from_env({})
    provider = DeepSeekModelProvider.from_env({"DEEPSEEK_API_KEY":"test", "DEEPSEEK_MODEL":"custom"})
    assert provider.info.provider == "deepseek"
    assert provider.info.name == "custom"
