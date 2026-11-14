"""真实数据库启动入口：uvicorn agent_service.api.real_main:app --host 0.0.0.0 --port 8000

依赖环境变量（可放 .env）:
    AGENT_DB_HOST=127.0.0.1
    AGENT_DB_PORT=3306
    AGENT_DB_NAME=ipv4scan
    AGENT_DB_USER=root
    AGENT_DB_PASSWORD=从本地环境读取

AGENT_MODEL_PROVIDER=mock 或 deepseek，DeepSeek 密钥使用 DEEPSEEK_API_KEY。
AGENT_CHAT_PROVIDER=rules 或 deepseek；未设置时跟随 AGENT_MODEL_PROVIDER。
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from agent_service.api.app import create_app
from agent_service.db.l3_data import L3DataProvider
from agent_service.db.repositories import AgentAnalysisRepository, AgentTaskRepository
from agent_service.db.session import create_session_factory
from agent_service.models.analysis_schema import ModelAnalysisPayload
from agent_service.providers.mock import MockModelProvider
from agent_service.providers.deepseek import DeepSeekModelProvider
from agent_service.providers.deepseek_chat import DeepSeekNaturalLanguageProvider
from agent_service.providers.base import ModelProvider
from agent_service.services.ip_analysis import SingleIPAnalysisService
from agent_service.services.task_orchestrator import SingleIPTaskOrchestrator
from agent_service.services.batch_analysis import BatchAnalysisService


def _build_model_provider() -> ModelProvider:
    """通过环境变量选择模型；保持 Mock 为显式默认值。"""

    provider = os.environ.get("AGENT_MODEL_PROVIDER", "mock").lower()
    if provider == "deepseek":
        return DeepSeekModelProvider.from_env()
    if provider != "mock":
        raise ValueError("AGENT_MODEL_PROVIDER 仅支持 mock 或 deepseek")

    def _factory(_prompt: str, _output_model: type[ModelAnalysisPayload]) -> dict:
        return {
            "summary": {
                "risk_level": "info",
                "description": "模型调用尚未接入，当前为 Mock 结果。",
                "confidence": 0.3,
            },
            "limitations": ["模型调用尚未接入，当前为 Mock 结果。"],
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

    orchestrator = SingleIPTaskOrchestrator(
        task_repository=task_repo,
        analysis_repository=analysis_repo,
        data_provider=data_provider,
        analysis_service=analysis_service,
    )
    return orchestrator, engine, factory, model_provider


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} 必须是整数") from exc
    if value < 1:
        raise ValueError(f"{name} 必须大于 0")
    return value


def _build_chat_ai_provider():
    """自然语言能力可独立切换；rules 表示完全使用本地规则和模板。"""

    provider = os.environ.get(
        "AGENT_CHAT_PROVIDER", os.environ.get("AGENT_MODEL_PROVIDER", "mock")
    ).lower()
    if provider == "deepseek":
        return DeepSeekNaturalLanguageProvider.from_env()
    if provider in {"rules", "mock"}:
        return None
    raise ValueError("AGENT_CHAT_PROVIDER 仅支持 rules、mock 或 deepseek")


def _make_app() -> FastAPI:
    orchestrator, engine, session_factory, model_provider = _build_orchestrator()
    batch_service = BatchAnalysisService(
        session_factory=session_factory,
        model_provider=model_provider,
        max_concurrency=_positive_int_env("AGENT_BATCH_CONCURRENCY", 3),
        max_ips=min(_positive_int_env("AGENT_BATCH_MAX_IPS", 50), 50),
    )
    app = create_app(
        orchestrator,
        chat_ai_provider=_build_chat_ai_provider(),
        batch_service=batch_service,
        query_session_factory=session_factory,
    )

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
