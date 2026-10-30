"""FastAPI 应用工厂。

应用工厂只负责装配路由和运行元信息，数据库 Session、L3 Provider、模型
Provider 及任务编排 Service 必须由启动层显式构造后传入。
"""

from __future__ import annotations

from fastapi import FastAPI

from agent_service.services.task_orchestrator import SingleIPTaskOrchestrator

from .routes import create_single_ip_router


def create_app(orchestrator: SingleIPTaskOrchestrator) -> FastAPI:
    """创建已连接单 IP 编排 Service 的 FastAPI 应用。"""

    app = FastAPI(
        title="IPv4 Web Mapping Agent API",
        version="0.1.0",
        description="基于已有扫描数据的被动资产分析接口",
    )
    app.include_router(create_single_ip_router(orchestrator))
    return app

