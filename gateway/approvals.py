from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from contracts import Finding

_LOCK = threading.RLock()
_QUEUE: dict[str, dict[str, Any]] = {}


def enqueue_approval(request_id: str, findings: list[Finding], redacted_snippet: str) -> str:
    approval_id = str(uuid.uuid4())
    with _LOCK:
        _QUEUE[approval_id] = {
            "id": approval_id, "request_id": request_id, "status": "pending",
            "findings": [item.model_dump(mode="json", exclude={"start", "end"}) for item in findings],
            "snippet_redacted": redacted_snippet, "created_at": datetime.now(timezone.utc).isoformat(),
            "decision_by": None, "decided_at": None,
        }
    return approval_id


def list_approvals() -> list[dict[str, Any]]:
    with _LOCK:
        return list(reversed(list(_QUEUE.values())))


def decide(approval_id: str, decision: str, user_id: str) -> dict[str, Any] | None:
    if decision not in {"approved", "rejected"}:
        raise ValueError("Decision must be approved or rejected")
    with _LOCK:
        item = _QUEUE.get(approval_id)
        if item is None:
            return None
        if item["status"] != "pending":
            raise ValueError("Approval has already been decided")
        item["status"] = decision
        item["decision_by"] = user_id
        item["decided_at"] = datetime.now(timezone.utc).isoformat()
        return dict(item)


def get_approval_status(approval_id: str) -> str | None:
    with _LOCK:
        item = _QUEUE.get(approval_id)
        return item["status"] if item else None
