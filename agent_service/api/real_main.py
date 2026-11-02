"""真实数据库启动入口：uvicorn agent_service.api.real_main:app --host 0.0.0.0 --port 8000

依赖环境变量（可放 .env）:
    AGENT_DB_HOST=127.0.0.1
    AGENT_DB_PORT=3306
    AGENT_DB_NAME=ipv4scan
    AGENT_DB_USER=root
    AGENT_DB_PASSWORD=从本地环境读取

AGENT_MODEL_PROVIDER=mock 或 deepseek，DeepSeek 密钥使用 DEEPSEEK_API_KEY。
"""

from __future__ import annotations

import re
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from agent_service.api.app import create_app
from agent_service.db.l3_data import L3DataProvider
from agent_service.db.repositories import AgentAnalysisRepository, AgentTaskRepository
from agent_service.db.session import create_session_factory
from agent_service.models.analysis_schema import AnalysisResult
from agent_service.providers.mock import MockModelProvider
from agent_service.providers.deepseek import DeepSeekModelProvider
from agent_service.providers.base import ModelProvider
from agent_service.services.ip_analysis import SingleIPAnalysisService
from agent_service.services.task_orchestrator import SingleIPTaskOrchestrator


def _build_model_provider() -> ModelProvider:
    """通过环境变量选择模型；保持 Mock 为显式默认值。"""

    provider = os.environ.get("AGENT_MODEL_PROVIDER", "mock").lower()
    if provider == "deepseek":
        return DeepSeekModelProvider.from_env()
    if provider != "mock":
        raise ValueError("AGENT_MODEL_PROVIDER 仅支持 mock 或 deepseek")

    def _factory(prompt: str, _output_model: type[AnalysisResult]) -> dict:
        ip = re.search(r'"ip":\s*"([^"]+)"', prompt)
        round_match = re.search(r'"scan_round":\s*(\d+)', prompt)
        return {
            "analysis_id": f"mock-{ip.group(1) if ip else 'unknown'}",
            "ip": ip.group(1) if ip else "192.0.2.1",
            "scan_round": int(round_match.group(1)) if round_match else 1,
            "scan_time": "2026-01-01T00:00:00Z",
            "summary": {
                "risk_level": "info",
                "description": "模型调用尚未接入，当前为 Mock 结果。",
                "confidence": 0.3,
            },
            "metadata": {
                "model_provider": "mock",
                "model_name": "mock-model",
                "prompt_version": "1.0",
            },
        }

    return MockModelProvider(response_factory=_factory)


def _build_orchestrator():
    engine, factory = create_session_factory()
    session = factory()

    task_repo = AgentTaskRepository(session)
    analysis_repo = AgentAnalysisRepository(session)
    data_provider = L3DataProvider(session)
    model_provider = _build_model_provider()
    analysis_service = SingleIPAnalysisService(
        data_provider=data_provider, model_provider=model_provider
    )

    return SingleIPTaskOrchestrator(
        task_repository=task_repo,
        analysis_repository=analysis_repo,
        data_provider=data_provider,
        analysis_service=analysis_service,
    ), engine


def _make_app() -> FastAPI:
    orchestrator, engine = _build_orchestrator()
    app = create_app(orchestrator)

    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def combined_lifespan(app: FastAPI):
        app.state.engine = engine
        try:
            async with original_lifespan(app):
                yield
        finally:
            await engine.dispose()

    app.router.lifespan_context = combined_lifespan
    return app


app = _make_app()
