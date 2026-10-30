"""产品名称和版本的确定性归一化。

规则优先处理常见产品。无法确认时保留原始值的清洗结果，并降低置信度；
完全没有产品信息时使用 ``unknown``，不让模型或统计层误以为已识别。
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from agent_service.models.analysis_schema import ProductFingerprint


_PRODUCT_ALIASES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bnginx\b", re.IGNORECASE), "nginx"),
    (re.compile(r"\b(?:apache(?:\s+httpd)?|httpd)\b", re.IGNORECASE), "apache-httpd"),
    (re.compile(r"\bopen[_\s-]*ssh|\bopenssh\b", re.IGNORECASE), "openssh"),
    (re.compile(r"\bmariadb\b", re.IGNORECASE), "mariadb"),
    (re.compile(r"\bmysql\b", re.IGNORECASE), "mysql"),
    (re.compile(r"\bpostgres(?:ql)?\b", re.IGNORECASE), "postgresql"),
    (re.compile(r"\bredis\b", re.IGNORECASE), "redis"),
    (re.compile(r"\b(?:mongodb|mongo\s+db)\b", re.IGNORECASE), "mongodb"),
    (re.compile(r"\belasticsearch\b", re.IGNORECASE), "elasticsearch"),
    (re.compile(r"\b(?:microsoft\s+)?iis\b", re.IGNORECASE), "microsoft-iis"),
    (re.compile(r"\bvsftpd\b", re.IGNORECASE), "vsftpd"),
    (re.compile(r"\bproftpd\b", re.IGNORECASE), "proftpd"),
    (re.compile(r"\bdovecot\b", re.IGNORECASE), "dovecot"),
    (re.compile(r"\bpostfix\b", re.IGNORECASE), "postfix"),
    (re.compile(r"\btelnetd\b", re.IGNORECASE), "telnetd"),
)

_VERSION_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:version\s*|ver\.?\s*|v\s*)?"
    r"(\d+(?:\.\d+){0,3}(?:(?:[-_])?[A-Za-z][0-9A-Za-z.-]*)?)",
    re.IGNORECASE,
)


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = re.sub(r"\s+", " ", value).strip()
    return cleaned or None


def _extract_version(*values: str | None) -> str | None:
    for index, value in enumerate(values):
        cleaned = _clean(value)
        if not cleaned:
            continue
        match = _VERSION_PATTERN.search(cleaned)
        if match:
            candidate = match.group(1).replace("_", "-")
            # 独立版本字段中的整数版本是合法的；普通 banner 中的四位数字
            # 可能只是年份或其他编号，只有带小数点或显式 version/v 前缀时采信。
            if (
                "." in candidate
                or (index == 0 and cleaned == candidate and len(candidate) <= 2)
                or re.search(
                rf"(?:version|ver\.?|v)\s*{re.escape(candidate)}",
                cleaned,
                re.IGNORECASE,
                )
            ):
                return candidate
    return None


def _find_product(*values: str | None) -> tuple[str | None, bool]:
    for value in values:
        cleaned = _clean(value)
        if not cleaned:
            continue
        for pattern, canonical in _PRODUCT_ALIASES:
            if pattern.search(cleaned):
                return canonical, True
    return None, False


def normalize_product(
    raw_product_name: str | None,
    raw_version: str | None = None,
    *,
    evidence: Iterable[str] = (),
) -> ProductFingerprint:
    """归一化产品名称和版本，同时保留原始值。

    置信度含义：
    - ``0.95``：匹配到明确的常见产品别名；
    - ``0.60``：无法匹配别名，但保留了非空原始产品名；
    - ``0.0``：没有足够的产品信息，归一化名称为 ``unknown``。
    """

    raw_name = _clean(raw_product_name)
    raw_ver = _clean(raw_version)
    canonical, matched = _find_product(raw_name, raw_ver)
    normalized_version = _extract_version(raw_ver, raw_name)
    normalized_evidence = list(dict.fromkeys(item.strip() for item in evidence if item.strip()))

    if matched:
        confidence = 0.95
        normalized_evidence.append("命中内置产品别名规则")
    elif raw_name:
        canonical = re.sub(r"[^a-z0-9]+", "-", raw_name.lower()).strip("-") or "unknown"
        confidence = 0.60
        normalized_evidence.append("未命中内置别名，保留清洗后的原始产品名")
    else:
        canonical = "unknown"
        confidence = 0.0
        normalized_evidence.append("没有可用的产品名称")

    if normalized_version and normalized_version != raw_ver:
        normalized_evidence.append("从原始产品或版本字段提取版本号")

    return ProductFingerprint(
        raw_product_name=raw_name,
        raw_version=raw_ver,
        normalized_product_name=canonical,
        normalized_version=normalized_version,
        normalization_confidence=confidence,
        normalization_evidence=normalized_evidence,
    )

