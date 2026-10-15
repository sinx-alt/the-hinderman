from collections import defaultdict

from contracts import Finding


def transform_text(text: str, findings: list[Finding], action: str) -> str:
    if action not in {"mask", "redact"}:
        return text
    replacements: list[tuple[int, int, str]] = []
    counts: defaultdict[str, int] = defaultdict(int)
    for finding in sorted(
        (item for item in findings if item.start is not None and item.end is not None),
        key=lambda item: (item.start or 0, -(item.end or 0)),
    ):
        start, end = finding.start, finding.end
        if start is None or end is None or end <= start or start < 0 or end > len(text):
            continue
        if replacements and start < replacements[-1][1]:
            continue
        counts[finding.type] += 1
        replacement = f"[{finding.type}_{counts[finding.type]}]" if action == "mask" else f"[REDACTED_{finding.type}]"
        replacements.append((start, end, replacement))
    for start, end, replacement in reversed(replacements):
        text = text[:start] + replacement + text[end:]
    return text


def summarize_findings(findings: list[Finding]) -> list[dict[str, object]]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[finding.type].append(finding)
    return [
        {
            "category": items[0].category,
            "type": kind,
            "count": len(items),
            "confidence": round(max(item.confidence for item in items), 3),
        }
        for kind, items in sorted(groups.items())
    ]
