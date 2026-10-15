from __future__ import annotations

import re

from contracts import Finding

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def valid_aadhaar(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 12 or digits[0] in "0 1":
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        checksum = _VERHOEFF_D[checksum][_VERHOEFF_P[index % 8][int(digit)]]
    return _VERHOEFF_INV[checksum] == 0


def valid_luhn(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


PATTERNS: list[tuple[str, str, re.Pattern[str], float]] = [
    ("AADHAAR", "PII", re.compile(r"(?<!\d)(?:\d[ -]?){11}\d(?!\d)"), 0.99),
    ("PAN", "PII", re.compile(r"(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])", re.I), 0.98),
    ("PHONE", "PII", re.compile(r"(?<!\w)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\w)"), 0.9),
    ("EMAIL", "PII", re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.I), 0.98),
    ("IFSC", "FINANCIAL", re.compile(r"(?<![A-Z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Z0-9])", re.I), 0.96),
    ("UPI_ID", "FINANCIAL", re.compile(r"(?<![\w.-])[\w.-]{2,}@[a-zA-Z]{2,}(?!\w)"), 0.88),
    ("GSTIN", "FINANCIAL", re.compile(r"(?<![A-Z0-9])\d{2}[A-Z]{5}\d{4}[A-Z]\dZ[A-Z0-9](?![A-Z0-9])", re.I), 0.95),
    ("CARD", "FINANCIAL", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), 0.99),
]


def detect_india_pii(text: str) -> list[Finding]:
    findings: list[Finding] = []
    aadhaar_candidates: set[tuple[int, int]] = set()
    card_candidates: set[tuple[int, int]] = set()
    for kind, category, pattern, confidence in PATTERNS:
        for match in pattern.finditer(text):
            value = match.group()
            if kind == "AADHAAR":
                if valid_aadhaar(value):
                    aadhaar_candidates.add(match.span())
                continue
            if kind == "CARD":
                if valid_luhn(value):
                    card_candidates.add(match.span())
                continue
            findings.append(
                Finding(category=category, type=kind, start=match.start(), end=match.end(),
                        confidence=confidence, detector="india_regex")
            )
    findings.extend(
        Finding(category="PII", type="AADHAAR", start=start, end=end, confidence=0.99,
                detector="verhoeff")
        for start, end in aadhaar_candidates
    )
    findings.extend(
        Finding(category="FINANCIAL", type="CARD", start=start, end=end, confidence=0.99,
                detector="luhn")
        for start, end in card_candidates
    )
    return sorted(findings, key=lambda item: item.start or 0)
