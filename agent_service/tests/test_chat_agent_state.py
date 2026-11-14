import pytest
from pydantic import ValidationError

from agent_service.services.chat_agent_state import (
    DEFAULT_CHAT_LIMITATIONS,
    initial_chat_state,
)


def test_initial_chat_state_contains_safe_defaults() -> None:
    state = initial_chat_state("  查询 192.0.2.10 的服务  ", scan_round=3)

    assert state == {
        "question": "查询 192.0.2.10 的服务",
        "scan_round": 3,
        "intent": None,
        "understanding": None,
        "target_ip": None,
        "from_scan_round": None,
        "to_scan_round": None,
        "task_id": None,
        "explicit_analysis_request": False,
        "request_error": None,
        "selected_tool": None,
        "tool_arguments": {},
        "tool_history": [],
        "tool_call_count": 0,
        "max_tool_calls": 2,
        "continue_tool_loop": False,
        "answer": None,
        "evidence": [],
        "limitations": [
            "回答仅基于已有扫描数据",
            "当前扫描只覆盖指定常用端口",
        ],
        "status": "pending",
        "model_provider": "rules",
        "fallback_used": False,
        "fallback_steps": [],
        "workflow_trace": [],
    }


def test_initial_states_do_not_share_mutable_collections() -> None:
    first = initial_chat_state("查询 192.0.2.10")
    second = initial_chat_state("查询 192.0.2.11")

    first["tool_arguments"]["ip"] = "192.0.2.10"
    first["limitations"].append("额外限制")
    first["workflow_trace"].append("trace")

    assert second["tool_arguments"] == {}
    assert second["limitations"] == DEFAULT_CHAT_LIMITATIONS
    assert second["workflow_trace"] == []


def test_initial_state_rejects_blank_question_and_invalid_round() -> None:
    with pytest.raises(ValidationError):
        initial_chat_state("   ")
    with pytest.raises(ValidationError):
        initial_chat_state("查询 192.0.2.10", scan_round=0)
