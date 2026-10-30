"""启动本地 Mock API：uvicorn agent_service.api.mock_main:app --reload"""

from .mock_app import create_mock_app

app = create_mock_app()

