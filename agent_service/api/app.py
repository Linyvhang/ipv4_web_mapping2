"""FastAPI 应用工厂。

应用工厂只负责装配路由和运行元信息，数据库 Session、L3 Provider、模型
Provider 及任务编排 Service 必须由启动层显式构造后传入。
"""

from __future__ import annotations

from fastapi import FastAPI

from agent_service.services.task_orchestrator import SingleIPTaskOrchestrator
from agent_service.services.batch_analysis import BatchAnalysisService
from agent_service.services.chat_ai import NaturalLanguageAgentProvider
from agent_service.services.single_ip_graph import build_single_ip_graph
from agent_service.services.chat_agent_graph import build_chat_agent_graph
from agent_service.services.chat_understanding import (
    ChatRequestValidator,
    QuestionUnderstandingProvider,
    RuleBasedQuestionUnderstandingProvider,
)
from agent_service.tools.asset_tools import AssetAgentToolRegistry

from .chat_routes import create_chat_agent_router
from .asset_routes import create_asset_router
from .task_routes import create_task_query_router
from .chat_preview import create_chat_preview_router
from .preview import create_preview_router
from .routes import create_single_ip_router
from .batch_routes import create_batch_analysis_router


def create_app(
    orchestrator: SingleIPTaskOrchestrator,
    *,
    understanding_provider: QuestionUnderstandingProvider | None = None,
    chat_ai_provider: NaturalLanguageAgentProvider | None = None,
    batch_service: BatchAnalysisService | None = None,
) -> FastAPI:
    """创建已连接单 IP 编排 Service 的 FastAPI 应用。"""

    app = FastAPI(
        title="IPv4 Web Mapping Agent API",
        version="0.1.0",
        description="基于已有扫描数据的被动资产分析接口",
    )
    graph = build_single_ip_graph(orchestrator)
    tool_registry = AssetAgentToolRegistry(orchestrator=orchestrator, graph=graph)
    rules = RuleBasedQuestionUnderstandingProvider()
    primary_understanding = chat_ai_provider or understanding_provider or rules
    chat_graph = build_chat_agent_graph(
        understanding_provider=primary_understanding,
        fallback_understanding_provider=(rules if chat_ai_provider is not None else None),
        tool_selection_provider=chat_ai_provider,
        answer_provider=chat_ai_provider,
        request_validator=ChatRequestValidator(),
        tool_registry=tool_registry,
    )
    app.state.single_ip_graph = graph
    app.state.agent_tool_registry = tool_registry
    app.state.chat_agent_graph = chat_graph
    app.include_router(create_preview_router())
    app.include_router(create_chat_preview_router())
    app.include_router(create_single_ip_router(graph))
    app.include_router(create_chat_agent_router(chat_graph))
    app.include_router(create_asset_router(orchestrator))
    app.include_router(create_task_query_router(orchestrator))
    if batch_service is not None:
        app.state.batch_analysis_service = batch_service
        app.include_router(create_batch_analysis_router(batch_service))
    return app

