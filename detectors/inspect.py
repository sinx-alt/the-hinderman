from __future__ import annotations

import re

from contracts import Finding, UserContext
from detectors.india_pii import detect_india_pii

_SECRET_PATTERNS = [
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.99),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), 0.98),
    ("OPENAI_KEY", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), 0.96),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"), 0.96),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 1.0),
]
_PASSWORD = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret)\s*(?:(?:is|:|=)\s*)['\"]?([^\s'\";,]{6,})"
)
_API_KEY = re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{10,}\b")
_CONFIDENTIAL = re.compile(
    r"(?i)\b(?:confidential|strictly confidential|internal only|do not distribute)\b"
)
_SOURCE_CODE = re.compile(r"(?m)^\s*(?:def |class |import |from \S+ import |const \w+\s*=|SELECT .+ FROM )")


def inspect(text: str, direction: str = "prompt", ctx: UserContext | None = None) -> list[Finding]:
    findings = detect_india_pii(text)
    findings.extend(
        Finding(category="CREDENTIAL", type=kind, start=match.start(), end=match.end(),
                confidence=confidence, detector="secret_regex")
        for kind, pattern, confidence in _SECRET_PATTERNS
        for match in pattern.finditer(text)
    )
    findings.extend(
        Finding(category="CREDENTIAL", type="PASSWORD", start=match.start(1), end=match.end(1),
                confidence=0.92, detector="password_context")
        for match in _PASSWORD.finditer(text)
    )
    findings.extend(
        Finding(category="CREDENTIAL", type="API_KEY", start=match.start(), end=match.end(),
                confidence=0.95, detector="secret_regex")
        for match in _API_KEY.finditer(text)
        if not any(item.start == match.start() and item.end == match.end() for item in findings)
    )
    findings.extend(
        Finding(category="CONFIDENTIAL", type="CONFIDENTIAL_MARKER", start=match.start(),
                end=match.end(), confidence=0.85, detector="confidential_rules")
        for match in _CONFIDENTIAL.finditer(text)
    )
    findings.extend(
        Finding(category="CONFIDENTIAL", type="SOURCE_CODE", start=match.start(),
                end=match.end(), confidence=0.65, detector="source_code_rules")
        for match in _SOURCE_CODE.finditer(text)
    )
    return sorted(findings, key=lambda item: item.start if item.start is not None else -1)
