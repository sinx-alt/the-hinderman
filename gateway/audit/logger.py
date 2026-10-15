from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from contracts import AuditEvent, AuditFinding

_LOCK = threading.RLock()
_GENESIS = "0" * 64


def _db_path() -> Path:
    return Path(os.getenv("AUDIT_DB", "data/audit.sqlite3"))


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY, ts TEXT NOT NULL, user_id TEXT NOT NULL, direction TEXT NOT NULL,
        findings TEXT NOT NULL, policy_id TEXT, action TEXT NOT NULL, snippet_redacted TEXT NOT NULL,
        content_sha256 TEXT NOT NULL, prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
        latency_ms REAL NOT NULL, source TEXT)"""
    )
    connection.commit()
    return connection


def log_event(
    *,
    user_id: str,
    direction: str,
    findings: list[AuditFinding],
    policy_id: str | None,
    action: str,
    snippet_redacted: str,
    raw_content: str,
    latency_ms: float,
    source: str,
) -> AuditEvent:
    with _LOCK, _connect() as connection:
        previous = connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        prev_hash = previous["event_hash"] if previous else _GENESIS
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        content_hash = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()
        payload: dict[str, Any] = {
            "id": event_id, "ts": timestamp, "user_id": user_id, "direction": direction,
            "findings": [item.model_dump(mode="json") for item in findings],
            "policy_id": policy_id, "action": action, "snippet_redacted": snippet_redacted,
            "content_sha256": content_hash, "prev_hash": prev_hash,
            "latency_ms": round(latency_ms, 3), "source": source,
        }
        event_hash = hashlib.sha256(
            (prev_hash + json.dumps(payload, sort_keys=True, separators=(",", ":"))).encode()
        ).hexdigest()
        event = AuditEvent(**payload, event_hash=event_hash)
        connection.execute(
            """INSERT INTO audit_events VALUES
            (:id,:ts,:user_id,:direction,:findings,:policy_id,:action,:snippet_redacted,
             :content_sha256,:prev_hash,:event_hash,:latency_ms,:source)""",
            {**payload, "findings": json.dumps(payload["findings"], separators=(",", ":")),
             "event_hash": event_hash},
        )
        connection.commit()
        return event


def list_events(limit: int = 100) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM audit_events ORDER BY rowid DESC LIMIT ?", (min(max(limit, 1), 500),)
        ).fetchall()
    return [
        {**dict(row), "findings": json.loads(row["findings"])}
        for row in rows
    ]


def verify_chain() -> dict[str, object]:
    with _connect() as connection:
        rows = connection.execute("SELECT * FROM audit_events ORDER BY rowid ASC").fetchall()
    previous = _GENESIS
    for index, row in enumerate(rows):
        payload = {
            "id": row["id"], "ts": row["ts"], "user_id": row["user_id"],
            "direction": row["direction"], "findings": json.loads(row["findings"]),
            "policy_id": row["policy_id"], "action": row["action"],
            "snippet_redacted": row["snippet_redacted"], "content_sha256": row["content_sha256"],
            "prev_hash": row["prev_hash"], "latency_ms": row["latency_ms"], "source": row["source"],
        }
        expected = hashlib.sha256(
            (previous + json.dumps(payload, sort_keys=True, separators=(",", ":"))).encode()
        ).hexdigest()
        if row["prev_hash"] != previous or row["event_hash"] != expected:
            return {"valid": False, "verified_events": index}
        previous = row["event_hash"]
    return {"valid": True, "verified_events": len(rows)}
