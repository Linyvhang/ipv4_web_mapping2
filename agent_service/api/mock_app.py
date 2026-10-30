"""本地联调用 Mock FastAPI 应用。

该模块不访问数据库、不发起网络请求，仅用于前端和 API 契约联调。
"""

from __future__ import annotations

import re
from datetime import datetime
from ipaddress import IPv4Address
from types import SimpleNamespace

from agent_service.api.app import create_app
from agent_service.models.analysis_schema import AnalysisResult
from agent_service.models.input_schema import AssetAnalysisInput
from agent_service.providers.mock import MockModelProvider
from agent_service.services.ip_analysis import SingleIPAnalysisService
from agent_service.services.task_orchestrator import SingleIPTaskOrchestrator


class MockL3DataProvider:
    async def fetch_asset(self, *, ip_value: int, scan_round: int | None = None):
        ip = str(IPv4Address(ip_value))
        return AssetAnalysisInput(
            ip=ip,
            scan_round=scan_round or 1,
            active_host_id=1,
            alive_type=4,
            first_seen=datetime(2026, 1, 1),
            last_seen=datetime(2026, 1, 1),
            services=[],
            limitations=["Mock 数据，仅用于接口联调"],
        )


class MockTaskRepository:
    def __init__(self) -> None:
        self.next_id = 1

    async def create_task(self, **_: object):
        task = SimpleNamespace(id=self.next_id)
        self.next_id += 1
        return task

    async def create_items(self, *, task_id: int, targets: list[tuple[str, int]]):
        return [SimpleNamespace(id=self.next_id, task_id=task_id, ip=targets[0][0])]

    async def update_task_status(self, *_: object, **__: object) -> None:
        return None

    async def update_item_status(self, *_: object, **__: object) -> None:
        return None


class MockAnalysisRepository:
    def __init__(self) -> None:
        self.results: dict[tuple[str, int], SimpleNamespace] = {}

    async def get_cached_result(self, *, ip: str, scan_round: int):
        return self.results.get((ip, scan_round))

    async def create_result(self, **kwargs: object):
        result = SimpleNamespace(**kwargs, id=len(self.results) + 1)
        self.results[(str(kwargs["ip"]), int(kwargs["scan_round"]))] = result
        return result


def _mock_result_factory(prompt: str, _output_model: type[AnalysisResult]) -> dict:
    ip = re.search(r'"ip":\s*"([^"]+)"', prompt)
    round_match = re.search(r'"scan_round":\s*(\d+)', prompt)
    return {
        "analysis_id": f"mock-{ip.group(1) if ip else 'unknown'}",
        "ip": ip.group(1) if ip else "192.0.2.1",
        "scan_round": int(round_match.group(1)) if round_match else 1,
        "scan_time": "2026-01-01T00:00:00Z",
        "summary": {
            "risk_level": "info",
            "description": "Mock 分析结果，仅用于接口联调",
            "confidence": 0.5,
        },
        "metadata": {
            "model_provider": "mock",
            "model_name": "mock-model",
            "prompt_version": "1.0",
        },
    }


def create_mock_app():
    """创建可供本地联调的 FastAPI 应用。"""

    model_provider = MockModelProvider(response_factory=_mock_result_factory)
    analysis_service = SingleIPAnalysisService(
        data_provider=MockL3DataProvider(), model_provider=model_provider
    )
    orchestrator = SingleIPTaskOrchestrator(
        task_repository=MockTaskRepository(),
        analysis_repository=MockAnalysisRepository(),
        data_provider=MockL3DataProvider(),
        analysis_service=analysis_service,
    )
    return create_app(orchestrator)

