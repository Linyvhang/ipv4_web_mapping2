"""自然语言问题理解接口、规则型 Mock 实现和程序安全校验。"""

from __future__ import annotations

import re
from ipaddress import IPv4Address, ip_address
from typing import Protocol

from agent_service.models.chat_schema import (
    QuestionUnderstanding,
    RequestValidation,
)


IPV4_CANDIDATE_PATTERN = re.compile(
    r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
)

PROHIBITED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("主动扫描", re.compile(r"主动扫描|帮我扫描|扫描一下|扫描这个|端口扫描|scan\s+(host|port)", re.I)),
    ("爆破或弱口令测试", re.compile(r"爆破|暴力破解|弱口令测试|brute[\s_-]*force", re.I)),
    ("漏洞利用或攻击", re.compile(r"漏洞利用|验证漏洞|利用漏洞|攻击这个|exploit", re.I)),
    ("任意 SQL 或数据修改", re.compile(r"执行\s*sql|运行\s*sql|run\s+sql|select\s+\*|删除(?:数据库|数据|表)|drop\s+table", re.I)),
)

CREATE_ANALYSIS_PATTERNS = re.compile(
    r"帮我分析|请分析|创建(?:一次)?分析|重新分析|生成(?:资产)?(?:画像|分析报告|报告)",
    re.I,
)
EXPLAIN_PATTERNS = re.compile(r"为什么|为何|依据|原因|解释|怎么判断|如何判断")
ANALYSIS_QUERY_PATTERNS = re.compile(
    r"风险|资产类型|资产画像|分析结果|分析报告|处置建议|修复建议|安全吗"
)
SCAN_QUERY_PATTERNS = re.compile(
    r"服务|端口|产品|版本|指纹|banner|扫描数据|扫描结果|开放了什么|open\s+port",
    re.I,
)
COMPARE_PATTERNS = re.compile(r"对比|比较|变化|变更|新增.*消失|前后差异", re.I)
BATCH_REPORT_PATTERNS = re.compile(
    r"批量.*(?:统计|汇总|报告)|任务\s*#?\s*\d+.*(?:统计|汇总|报告)|(?:统计|汇总|报告).*任务\s*#?\s*\d+",
    re.I,
)
SCAN_ROUND_PATTERN = re.compile(r"(?:扫描)?批次\s*#?\s*(\d+)|第\s*(\d+)\s*批")
TASK_ID_PATTERN = re.compile(r"(?:批量)?任务\s*#?\s*(\d+)", re.I)


def scan_rounds(question: str) -> list[int]:
    rounds: list[int] = []
    for first, second in SCAN_ROUND_PATTERN.findall(question):
        value = int(first or second)
        if value > 0 and value not in rounds:
            rounds.append(value)
    return rounds


def extract_task_id(question: str) -> int | None:
    match = TASK_ID_PATTERN.search(question)
    return int(match.group(1)) if match else None


class QuestionUnderstandingProvider(Protocol):
    """问题理解器接口；后续 DeepSeek 实现遵守同一契约。"""

    @property
    def provider_name(self) -> str:
        ...

    async def understand(self, question: str) -> QuestionUnderstanding:
        """把自然语言问题转换成结构化意图。"""


def extract_ipv4_candidates(question: str) -> list[str]:
    """返回问题中的 IPv4 外形字符串，包含可能非法的候选值。"""

    return IPV4_CANDIDATE_PATTERN.findall(question)


def valid_ipv4s(question: str) -> list[str]:
    """按出现顺序返回去重后的合法 IPv4。"""

    addresses: list[str] = []
    for candidate in extract_ipv4_candidates(question):
        try:
            address = ip_address(candidate)
        except ValueError:
            continue
        if isinstance(address, IPv4Address):
            normalized = str(address)
            if normalized not in addresses:
                addresses.append(normalized)
    return addresses


def prohibited_operation(question: str) -> str | None:
    """返回命中的禁止操作类型；安全的“查询扫描结果”不会被拦截。"""

    for label, pattern in PROHIBITED_PATTERNS:
        if pattern.search(question):
            return label
    return None


class RuleBasedQuestionUnderstandingProvider:
    """不调用模型的可预测 Mock 问题理解器。"""

    @property
    def provider_name(self) -> str:
        return "rules"

    async def understand(self, question: str) -> QuestionUnderstanding:
        normalized = question.strip()
        addresses = valid_ipv4s(normalized)
        target_ip = addresses[0] if addresses else None
        rounds = scan_rounds(normalized)
        task_id = extract_task_id(normalized)

        prohibited = prohibited_operation(normalized)
        if prohibited is not None:
            return QuestionUnderstanding(
                intent="unsupported",
                target_ip=target_ip,
                explicit_analysis_request=False,
                confidence=1.0,
                reason=f"请求包含禁止操作：{prohibited}",
            )
        if BATCH_REPORT_PATTERNS.search(normalized) and task_id is not None:
            return QuestionUnderstanding(
                intent="query_batch_report",
                target_ip=None,
                task_id=task_id,
                explicit_analysis_request=False,
                confidence=0.95,
                reason="用户正在查询已保存的批量统计报告",
            )
        if target_ip is None:
            return QuestionUnderstanding(
                intent="missing_target",
                target_ip=None,
                explicit_analysis_request=False,
                confidence=1.0,
                reason="问题中没有可用的 IPv4 地址",
            )
        if COMPARE_PATTERNS.search(normalized) and len(rounds) >= 2:
            return QuestionUnderstanding(
                intent="compare_scan_rounds",
                target_ip=target_ip,
                from_scan_round=rounds[0],
                to_scan_round=rounds[1],
                explicit_analysis_request=False,
                confidence=0.95,
                reason="用户正在比较同一 IP 的两个扫描批次",
            )
        if CREATE_ANALYSIS_PATTERNS.search(normalized):
            return QuestionUnderstanding(
                intent="create_analysis",
                target_ip=target_ip,
                explicit_analysis_request=True,
                confidence=0.95,
                reason="用户明确要求创建或重新执行资产分析",
            )
        if EXPLAIN_PATTERNS.search(normalized):
            return QuestionUnderstanding(
                intent="explain_result",
                target_ip=target_ip,
                explicit_analysis_request=False,
                confidence=0.9,
                reason="用户要求解释已有分析判断或证据",
            )
        if ANALYSIS_QUERY_PATTERNS.search(normalized):
            return QuestionUnderstanding(
                intent="query_analysis_result",
                target_ip=target_ip,
                explicit_analysis_request=False,
                confidence=0.9,
                reason="用户正在查询已有资产分析结果",
            )
        if SCAN_QUERY_PATTERNS.search(normalized):
            return QuestionUnderstanding(
                intent="query_scan_data",
                target_ip=target_ip,
                explicit_analysis_request=False,
                confidence=0.9,
                reason="用户正在查询已有扫描指纹",
            )
        return QuestionUnderstanding(
            intent="query_scan_data",
            target_ip=target_ip,
            explicit_analysis_request=False,
            confidence=0.5,
            reason="问题包含目标 IP，但意图不明确，默认查询已有扫描数据",
        )


class ChatRequestValidator:
    """不信任模型判断，对原问题和结构化结果执行确定性安全校验。"""

    def validate(
        self,
        question: str,
        understanding: QuestionUnderstanding,
    ) -> RequestValidation:
        prohibited = prohibited_operation(question)
        if prohibited is not None:
            return RequestValidation(
                valid=False,
                status="unsupported",
                error=f"不支持{prohibited}；本 Agent 只能分析已有扫描数据",
            )

        candidates = extract_ipv4_candidates(question)
        addresses = valid_ipv4s(question)
        extracted_rounds = scan_rounds(question)
        extracted_task_id = extract_task_id(question)
        if understanding.intent == "query_batch_report":
            if understanding.target_ip is not None:
                return RequestValidation(
                    valid=False,
                    status="invalid_request",
                    error="批量报告查询不应指定单个 IP",
                )
            if extracted_task_id is None or understanding.task_id != extracted_task_id:
                return RequestValidation(
                    valid=False,
                    status="invalid_request",
                    error="请在问题中提供一致的批量任务 ID",
                )
            return RequestValidation(valid=True, status="valid", error=None)
        if len(addresses) > 1:
            return RequestValidation(
                valid=False,
                status="invalid_request",
                error="第一版一次只支持查询一个 IPv4 地址",
            )
        if candidates and not addresses:
            return RequestValidation(
                valid=False,
                status="invalid_request",
                error="问题中的 IPv4 地址格式无效",
            )
        if understanding.target_ip is None:
            return RequestValidation(
                valid=False,
                status="invalid_request",
                error="请提供需要查询的 IPv4 地址",
            )
        if not addresses or understanding.target_ip != addresses[0]:
            return RequestValidation(
                valid=False,
                status="invalid_request",
                error="结构化目标 IP 与用户问题不一致",
            )
        if understanding.intent == "compare_scan_rounds":
            if len(extracted_rounds) != 2:
                return RequestValidation(
                    valid=False,
                    status="invalid_request",
                    error="历史变化对比需要明确提供两个不同扫描批次",
                )
            if (
                understanding.from_scan_round,
                understanding.to_scan_round,
            ) != tuple(extracted_rounds):
                return RequestValidation(
                    valid=False,
                    status="invalid_request",
                    error="结构化扫描批次与用户问题不一致",
                )
            if understanding.from_scan_round == understanding.to_scan_round:
                return RequestValidation(
                    valid=False,
                    status="invalid_request",
                    error="两个扫描批次不能相同",
                )
        if understanding.intent == "unsupported":
            return RequestValidation(
                valid=False,
                status="unsupported",
                error="该请求不在只读资产分析能力范围内",
            )
        if understanding.intent == "missing_target":
            return RequestValidation(
                valid=False,
                status="invalid_request",
                error="请提供需要查询的 IPv4 地址",
            )
        if (
            understanding.intent == "create_analysis"
            and not understanding.explicit_analysis_request
        ):
            return RequestValidation(
                valid=False,
                status="invalid_request",
                error="创建分析任务需要用户明确提出分析要求",
            )
        if (
            understanding.explicit_analysis_request
            and understanding.intent != "create_analysis"
        ):
            return RequestValidation(
                valid=False,
                status="invalid_request",
                error="分析任务授权与识别出的用户意图不一致",
            )
        return RequestValidation(valid=True, status="valid", error=None)
