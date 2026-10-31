"""Agent 数据库配置和 SQLAlchemy 异步 Session 工厂。"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - 依赖缺失时仍可使用系统环境变量
    load_dotenv = None


@dataclass(frozen=True)
class DatabaseSettings:
    """从环境变量读取的 Agent 数据库配置。"""

    host: str
    port: int
    name: str
    user: str
    password: str

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "DatabaseSettings":
        if environ is None and load_dotenv is not None:
            load_dotenv()
        values = os.environ if environ is None else environ
        required = {
            "host": "AGENT_DB_HOST",
            "name": "AGENT_DB_NAME",
            "user": "AGENT_DB_USER",
            "password": "AGENT_DB_PASSWORD",
        }
        missing = [env_name for env_name in required.values() if not values.get(env_name)]
        if missing:
            raise ValueError("缺少数据库环境变量: " + ", ".join(missing))
        try:
            port = int(values.get("AGENT_DB_PORT", "3306"))
        except ValueError as exc:
            raise ValueError("AGENT_DB_PORT 必须是整数") from exc
        if not 1 <= port <= 65535:
            raise ValueError("AGENT_DB_PORT 必须在 1 到 65535 之间")
        return cls(
            host=values["AGENT_DB_HOST"],
            port=port,
            name=values["AGENT_DB_NAME"],
            user=values["AGENT_DB_USER"],
            password=values["AGENT_DB_PASSWORD"],
        )

    def url(self) -> URL:
        return URL.create(
            drivername="mysql+aiomysql",
            username=self.user,
            password=self.password,
            host=self.host,
            port=self.port,
            database=self.name,
        )

    def safe_url(self) -> str:
        """返回隐藏密码的 URL，仅用于日志和诊断。"""

        return self.url().render_as_string(hide_password=True)


def create_session_factory(
    settings: DatabaseSettings | None = None,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    """创建 Engine 和 Session 工厂；调用方负责在应用退出时 dispose engine。"""

    resolved = settings or DatabaseSettings.from_env()
    engine = create_async_engine(resolved.url(), pool_pre_ping=True)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    return engine, factory

