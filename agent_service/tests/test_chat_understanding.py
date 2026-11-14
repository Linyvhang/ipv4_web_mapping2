import pytest

from agent_service.models.chat_schema import QuestionUnderstanding
from agent_service.services.chat_understanding import (
    ChatRequestValidator,
    RuleBasedQuestionUnderstandingProvider,
    extract_ipv4_candidates,
    prohibited_operation,
    valid_ipv4s,
)


def run_immediate(coroutine):
    try:
        yielded = coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    coroutine.close()
    raise AssertionError(f"测试协程意外等待了异步对象: {yielded!r}")


@pytest.mark.parametrize(
    ("question", "intent", "explicit"),
    [
        ("192.0.2.10 开放了哪些服务？", "query_scan_data", False),
        ("192.0.2.10 有哪些风险？", "query_analysis_result", False),
        ("帮我分析 192.0.2.10", "create_analysis", True),
        ("为什么 192.0.2.10 被判断为低风险？", "explain_result", False),
        (
            "比较 192.0.2.10 扫描批次 1 和扫描批次 2 的变化",
            "compare_scan_rounds",
            False,
        ),
    ],
)
def test_rule_based_provider_classifies_supported_questions(
    question: str, intent: str, explicit: bool
) -> None:
    provider = RuleBasedQuestionUnderstandingProvider()

    result = run_immediate(provider.understand(question))

    assert result.intent == intent
    assert result.target_ip == "192.0.2.10"
    assert result.explicit_analysis_request is explicit


def test_rule_provider_extracts_history_rounds_and_batch_task_id() -> None:
    provider = RuleBasedQuestionUnderstandingProvider()
    history_question = "比较 192.0.2.10 扫描批次 1 和扫描批次 2 的变化"
    report_question = "查询批量任务 11 的统计报告"

    history = run_immediate(provider.understand(history_question))
    report = run_immediate(provider.understand(report_question))

    assert (history.from_scan_round, history.to_scan_round) == (1, 2)
    assert ChatRequestValidator().validate(history_question, history).valid is True
    assert report.intent == "query_batch_report"
    assert report.target_ip is None
    assert report.task_id == 11
    assert ChatRequestValidator().validate(report_question, report).valid is True


def test_safe_scan_result_query_is_not_treated_as_active_scanning() -> None:
    provider = RuleBasedQuestionUnderstandingProvider()

    result = run_immediate(provider.understand("查询 192.0.2.10 的扫描结果"))

    assert result.intent == "query_scan_data"
    assert prohibited_operation("查询 192.0.2.10 的扫描结果") is None


@pytest.mark.parametrize(
    "question",
    [
        "帮我扫描 192.0.2.10",
        "爆破 192.0.2.10 的 SSH 密码",
        "验证漏洞并攻击这个 192.0.2.10",
        "对 192.0.2.10 执行 SQL",
    ],
)
def test_prohibited_requests_are_classified_as_unsupported(question: str) -> None:
    provider = RuleBasedQuestionUnderstandingProvider()

    result = run_immediate(provider.understand(question))
    validation = ChatRequestValidator().validate(question, result)

    assert result.intent == "unsupported"
    assert validation.valid is False
    assert validation.status == "unsupported"


def test_missing_invalid_and_multiple_ip_requests_are_rejected() -> None:
    provider = RuleBasedQuestionUnderstandingProvider()
    validator = ChatRequestValidator()

    missing_question = "这个 IP 有哪些服务？"
    missing = run_immediate(provider.understand(missing_question))
    invalid_question = "999.2.3.4 有哪些服务？"
    invalid = run_immediate(provider.understand(invalid_question))
    multiple_question = "比较 192.0.2.10 和 192.0.2.11"
    multiple = run_immediate(provider.understand(multiple_question))

    assert validator.validate(missing_question, missing).error == "请提供需要查询的 IPv4 地址"
    assert validator.validate(invalid_question, invalid).error == "问题中的 IPv4 地址格式无效"
    assert "一次只支持" in validator.validate(multiple_question, multiple).error


def test_validator_does_not_trust_inconsistent_model_output() -> None:
    validator = ChatRequestValidator()
    question = "查询 192.0.2.10 的服务"

    wrong_ip = QuestionUnderstanding(
        intent="query_scan_data",
        target_ip="192.0.2.11",
        confidence=1.0,
        reason="模拟模型改写 IP",
    )
    unauthorized_creation = QuestionUnderstanding(
        intent="create_analysis",
        target_ip="192.0.2.10",
        explicit_analysis_request=False,
        confidence=1.0,
        reason="模拟模型越权创建任务",
    )

    assert "不一致" in validator.validate(question, wrong_ip).error
    assert "明确" in validator.validate(question, unauthorized_creation).error


def test_ip_helpers_return_candidates_and_normalized_unique_addresses() -> None:
    question = "查询 192.0.2.10、192.0.2.10 和 999.1.1.1"

    assert extract_ipv4_candidates(question) == [
        "192.0.2.10",
        "192.0.2.10",
        "999.1.1.1",
    ]
    assert valid_ipv4s(question) == ["192.0.2.10"]
