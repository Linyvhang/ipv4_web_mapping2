"""不调用真实模型的 Mock Provider。"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ValidationError

from .base import ModelInfo, ModelProviderError, ResultModel


MockResponseFactory = Callable[[str, type[ResultModel]], BaseModel | dict[str, Any]]


class MockModelProvider:
    """使用预设结果模拟模型调用，供单元测试和流程开发使用。

    ``build_structured`` 是同步测试入口，``generate_structured`` 是与正式
    Provider 一致的异步接口。Mock 不访问网络、不消耗 Token。
    """

    def __init__(
        self,
        response: BaseModel | dict[str, Any] | None = None,
        *,
        provider: str = "mock",
        model_name: str = "mock-model",
        model_version: str | None = "1.0",
        response_factory: MockResponseFactory | None = None,
    ) -> None:
        if response is None and response_factory is None:
            raise ValueError("response or response_factory must be provided")
        if response is not None and response_factory is not None:
            raise ValueError("response and response_factory are mutually exclusive")
        self._response = response
        self._response_factory = response_factory
        self._info = ModelInfo(provider, model_name, model_version)
        self.calls: list[str] = []

    @property
    def info(self) -> ModelInfo:
        return self._info

    def build_structured(
        self,
        prompt: str,
        output_model: type[ResultModel],
    ) -> ResultModel:
        """同步生成经过 Pydantic 校验的 Mock 结果。"""

        self.calls.append(prompt)
        raw = (
            self._response_factory(prompt, output_model)
            if self._response_factory is not None
            else self._response
        )
        try:
            if isinstance(raw, output_model):
                return raw
            return output_model.model_validate(raw)
        except (ValidationError, TypeError, ValueError) as exc:
            raise ModelProviderError(
                f"Mock response cannot be validated as {output_model.__name__}: {exc}"
            ) from exc

    async def generate_structured(
        self,
        prompt: str,
        output_model: type[ResultModel],
    ) -> ResultModel:
        return self.build_structured(prompt, output_model)

