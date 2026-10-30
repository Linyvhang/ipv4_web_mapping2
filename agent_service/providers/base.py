"""模型调用抽象层。

业务流程只依赖本模块定义的协议，不直接依赖某一家模型供应商 SDK。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypeVar

from pydantic import BaseModel


ResultModel = TypeVar("ResultModel", bound=BaseModel)


@dataclass(frozen=True)
class ModelInfo:
    """模型运行元信息，用于写入分析结果。"""

    provider: str
    name: str
    version: str | None = None


class ModelProviderError(RuntimeError):
    """统一的模型调用异常。"""


class ModelProvider(Protocol):
    """所有模型 Provider 必须实现的异步结构化输出接口。"""

    @property
    def info(self) -> ModelInfo:
        ...

    async def generate_structured(
        self,
        prompt: str,
        output_model: type[ResultModel],
    ) -> ResultModel:
        """根据 Prompt 生成并校验指定 Pydantic 输出模型。"""

