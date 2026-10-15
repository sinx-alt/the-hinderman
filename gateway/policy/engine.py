from __future__ import annotations

import hashlib
from io import StringIO
from pathlib import Path
from threading import RLock
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from ruamel.yaml import YAML

from contracts import Action, Finding

PRIORITY: dict[str, int] = {
    "allow": 0,
    "warn": 1,
    "mask": 2,
    "redact": 3,
    "require_approval": 4,
    "block": 5,
}


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    when: dict[str, Any]
    action: Action


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policies: list[PolicyRule]


class PolicyDecision(BaseModel):
    action: Action
    policy_ids: list[str] = Field(default_factory=list)
    matched_findings: list[Finding] = Field(default_factory=list)


class PolicyEngine:
    def __init__(self, path: Path):
        self.path = path
        self._lock = RLock()
        self._content_hash = ""
        self._document = PolicyDocument(policies=[])
        self.reload()

    @staticmethod
    def _yaml() -> YAML:
        return YAML(typ="safe")

    def reload(self, force: bool = False) -> None:
        with self._lock:
            content = self.path.read_bytes()
            content_hash = hashlib.sha256(content).hexdigest()
            if not force and content_hash == self._content_hash:
                return
            raw = self._yaml().load(content.decode("utf-8"))
            document = PolicyDocument.model_validate(raw)
            if len({rule.id for rule in document.policies}) != len(document.policies):
                raise ValueError("Policy IDs must be unique")
            self._document = document
            self._content_hash = content_hash

    def replace(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        document = PolicyDocument.model_validate(payload)
        if len({rule.id for rule in document.policies}) != len(document.policies):
            raise ValueError("Policy IDs must be unique")
        stream = StringIO()
        yaml = YAML()
        yaml.default_flow_style = False
        yaml.dump(document.model_dump(mode="json"), stream)
        temporary = self.path.with_suffix(".yaml.tmp")
        temporary.write_text(stream.getvalue(), encoding="utf-8")
        temporary.replace(self.path)
        with self._lock:
            self._document = document
            self._content_hash = hashlib.sha256(self.path.read_bytes()).hexdigest()
        return [rule.model_dump(mode="json") for rule in document.policies]

    def list(self) -> list[dict[str, Any]]:
        self.reload()
        return [rule.model_dump(mode="json") for rule in self._document.policies]

    @staticmethod
    def _matches(rule: PolicyRule, finding: Finding, direction: str, source: str | None) -> bool:
        conditions = rule.when
        if conditions.get("category") not in (None, finding.category):
            return False
        type_condition = conditions.get("type")
        if type_condition is not None:
            allowed_types = type_condition if isinstance(type_condition, list) else [type_condition]
            if finding.type not in allowed_types:
                return False
        if finding.confidence < float(conditions.get("min_confidence", 0)):
            return False
        if conditions.get("direction") not in (None, direction):
            return False
        if conditions.get("source") not in (None, source):
            return False
        return True

    def decide(
        self, findings: list[Finding], direction: str = "prompt", source: str | None = None
    ) -> PolicyDecision:
        self.reload()
        matched: list[tuple[PolicyRule, Finding]] = []
        for finding in findings:
            for rule in self._document.policies:
                if self._matches(rule, finding, direction, source):
                    matched.append((rule, finding))
        if not matched:
            return PolicyDecision(action="allow")
        action = max((rule.action for rule, _ in matched), key=lambda item: PRIORITY[item])
        return PolicyDecision(
            action=action,
            policy_ids=list(dict.fromkeys(rule.id for rule, _ in matched)),
            matched_findings=[finding for _, finding in matched],
        )

    @staticmethod
    def validate(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            document = PolicyDocument.model_validate(payload)
        except ValidationError:
            raise
        if len({rule.id for rule in document.policies}) != len(document.policies):
            raise ValueError("Policy IDs must be unique")
        return document.model_dump(mode="json")
