"""对正在运行的自然语言 Agent API 执行可重复的端到端验收。"""

from __future__ import annotations

import argparse
import json
from ipaddress import IPv4Address, ip_address

import httpx

from agent_service.models.chat_schema import AgentChatResponse


def verify_chat_response(
    response: AgentChatResponse,
    *,
    expected_ip: str,
    expected_provider: str,
    allow_fallback: bool,
) -> None:
    """校验真实接口是否经过预期模型和至少一个受控工具。"""

    if response.target_ip != expected_ip:
        raise RuntimeError("响应目标 IP 与验收 IP 不一致")
    if response.status != "success":
        raise RuntimeError(f"Agent 未成功完成请求：{response.status}")
    if response.model_provider != expected_provider:
        raise RuntimeError(
            f"模型来源不符合预期：{response.model_provider} != {expected_provider}"
        )
    if response.fallback_used and not allow_fallback:
        raise RuntimeError("Agent 在验收过程中发生了安全降级")
    if not response.tools_used:
        raise RuntimeError("Agent 没有调用任何白名单工具")
    if not response.workflow_trace:
        raise RuntimeError("Agent 没有返回 LangGraph 工作流轨迹")
    sequences = [step.sequence for step in response.workflow_trace]
    if sequences != list(range(1, len(sequences) + 1)):
        raise RuntimeError("LangGraph 工作流轨迹顺序不连续")


def run_acceptance(
    *,
    base_url: str,
    ip: str,
    scan_round: int | None = None,
    expected_provider: str = "deepseek",
    allow_fallback: bool = False,
    client: httpx.Client | None = None,
) -> AgentChatResponse:
    """调用 `/agent/chat` 并返回经过契约与验收规则校验的响应。"""

    address = ip_address(ip)
    if not isinstance(address, IPv4Address):
        raise ValueError("验收目标必须是 IPv4 地址")
    owns_client = client is None
    active_client = client or httpx.Client(timeout=180)
    try:
        raw = active_client.post(
            f"{base_url.rstrip('/')}/agent/chat",
            json={
                "question": f"查询 {address} 开放了哪些服务和产品？",
                "scan_round": scan_round,
            },
        )
        raw.raise_for_status()
        response = AgentChatResponse.model_validate(raw.json())
        verify_chat_response(
            response,
            expected_ip=str(address),
            expected_provider=expected_provider,
            allow_fallback=allow_fallback,
        )
        return response
    finally:
        if owns_client:
            active_client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="验收自然语言 Agent 真实端到端流程")
    parser.add_argument("--base-url", default="http://127.0.0.1:8002")
    parser.add_argument("--ip", required=True)
    parser.add_argument("--scan-round", type=int)
    parser.add_argument("--expect-provider", default="deepseek")
    parser.add_argument("--allow-fallback", action="store_true")
    args = parser.parse_args()

    result = run_acceptance(
        base_url=args.base_url,
        ip=args.ip,
        scan_round=args.scan_round,
        expected_provider=args.expect_provider,
        allow_fallback=args.allow_fallback,
    )
    print(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
