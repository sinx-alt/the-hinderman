from __future__ import annotations

import re

from contracts import Finding

_RULES: list[tuple[str, re.Pattern[str], float]] = [
    ("SYSTEM_PROMPT_EXTRACTION", re.compile(r"(?i)\b(?:reveal|print|show|repeat|give me)\b.{0,50}\b(?:system prompt|hidden instructions|developer message)\b"), 0.96),
    ("IGNORE_INSTRUCTIONS", re.compile(r"(?i)\bignore\b.{0,40}\b(?:all |previous |prior )?(?:rules|instructions|safeguards|policies)\b"), 0.94),
    ("ROLEPLAY_JAILBREAK", re.compile(r"(?i)\b(?:act as|pretend to be|you are now)\b.{0,50}\b(?:unrestricted|developer mode|no rules|DAN)\b"), 0.87),
    ("CROSS_USER_DATA", re.compile(r"(?i)\b(?:other users?|previous user|another user).{0,45}\b(?:chat|conversation|data|messages)\b"), 0.9),
    ("INDIRECT_INSTRUCTION", re.compile(r"(?i)(?:assistant|ai)\s*[,!:].{0,80}\b(?:ignore|reveal|send|exfiltrate|override|disclose)\b"), 0.88),
    ("ENCODED_EVASION", re.compile(r"(?i)\b(?:decode|base64|rot13)\b.{0,60}\b(?:instruction|prompt|ignore|reveal)\b"), 0.8),
]


def score(text: str, source: str = "user") -> dict[str, object]:
    reasons = [
        {"type": kind, "start": match.start(), "end": match.end(), "confidence": confidence}
        for kind, pattern, confidence in _RULES
        for match in pattern.finditer(text)
    ]
    max_score = max((float(item["confidence"]) for item in reasons), default=0.0)
    if re.search(r"(?i)(?:ignore.{0,30}instructions|system prompt|previous user)", text):
        max_score = min(1.0, max_score + 0.03)
    return {"score": max_score, "label": "injection" if max_score >= 0.5 else "benign",
            "reasons": reasons, "source": source}


def findings(text: str, source: str = "user") -> list[Finding]:
    result = score(text, source)
    return [
        Finding(category="INJECTION", type=str(reason["type"]), start=int(reason["start"]),
                end=int(reason["end"]), confidence=float(reason["confidence"]),
                detector="rules")
        for reason in result["reasons"]  # type: ignore[union-attr]
    ]
