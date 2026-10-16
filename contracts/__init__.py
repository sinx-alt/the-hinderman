"""Shared API contracts, version 1.2."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Category = Literal[
    "PII", "FINANCIAL", "CREDENTIAL", "CONFIDENTIAL", "INJECTION", "RESTRICTED_DOC"
]
Direction = Literal["prompt", "response"]
Action = Literal["allow", "warn", "mask", "redact", "block", "require_approval"]


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: Category
    type: str
    start: int | None = None
    end: int | None = None
    confidence: float = Field(ge=0, le=1)
    detector: str


class UserContext(BaseModel):
    user_id: str
    role: str
    department: str
    clearance: int = Field(ge=0, le=3)


class Attachment(BaseModel):
    kind: Literal["image"] = "image"
    mime: Literal["image/png", "image/jpeg"]
    data_b64: str = Field(min_length=1, max_length=7_000_000)


class ChatRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=20_000)
    use_rag: bool = False
    attachments: list[Attachment] = Field(default_factory=list, max_length=3)


class AuditFinding(BaseModel):
    type: str
    count: int = Field(ge=1)
    confidence: float = Field(ge=0, le=1)


class AuditEvent(BaseModel):
    id: str
    ts: str
    user_id: str
    direction: Direction
    findings: list[AuditFinding] = Field(default_factory=list)
    policy_id: str | None = None
    action: Action
    snippet_redacted: str
    content_sha256: str
    prev_hash: str
    event_hash: str
    latency_ms: float = 0
    source: Literal["prompt", "document", "image"] | None = None


class DetectionTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    start: int | None = None
    end: int | None = None
    confidence: float = Field(ge=0, le=1)
    policy: str | None = None
    action: Action | None = None


class GatewayTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["allow", "mask", "redact", "warn", "block"]
    detections: list[DetectionTrace] = Field(default_factory=list)
    sanitized_prompt: str | None = None
    outbound_changes: dict[str, object] = Field(default_factory=dict)


class ChatResponse(BaseModel):
    response: str
    action_taken: Action
    findings_summary: list[dict[str, object]]
    request_id: str
    gateway_report: dict[str, object]
    trace: GatewayTrace | None = None
