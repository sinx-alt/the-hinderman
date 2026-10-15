import os
from pathlib import Path

import pytest

from contracts import Finding
from gateway.actions import transform_text
from gateway.policy.engine import PolicyEngine


@pytest.fixture
def engine(tmp_path: Path) -> PolicyEngine:
    path = tmp_path / "policies.yaml"
    path.write_text(
        "policies:\n"
        "  - id: pii\n    when: {category: PII}\n    action: mask\n"
        "  - id: inj\n    when: {category: INJECTION}\n    action: block\n",
        encoding="utf-8",
    )
    return PolicyEngine(path)


def test_policy_action_precedence_selects_block(engine: PolicyEngine) -> None:
    pii = Finding(category="PII", type="PAN", start=0, end=10, confidence=0.9, detector="test")
    injection = Finding(category="INJECTION", type="JAILBREAK", confidence=0.9, detector="test")
    result = engine.decide([pii, injection])
    assert result.action == "block"
    assert result.policy_ids == ["pii", "inj"]


def test_policy_hot_reload(engine: PolicyEngine) -> None:
    original_stat = engine.path.stat()
    engine.path.write_text(
        "policies:\n  - id: redact\n    when: {category: PII}\n    action: redact\n",
        encoding="utf-8",
    )
    os.utime(engine.path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    finding = Finding(category="PII", type="PAN", start=0, end=10, confidence=0.9, detector="test")
    assert engine.decide([finding]).action == "redact"


def test_policy_replace_rejects_duplicate_ids(engine: PolicyEngine) -> None:
    with pytest.raises(ValueError, match="unique"):
        engine.replace({"policies": [
            {"id": "same", "when": {}, "action": "allow"},
            {"id": "same", "when": {}, "action": "block"},
        ]})


def test_masking_uses_placeholders_without_leaking_source() -> None:
    text = "PAN ABCDE1234F belongs to me"
    finding = Finding(category="PII", type="PAN", start=4, end=14, confidence=0.9, detector="test")
    masked = transform_text(text, [finding], "mask")
    assert masked == "PAN [PAN_1] belongs to me"
    assert "ABCDE1234F" not in masked
