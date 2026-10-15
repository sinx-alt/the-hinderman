from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def documents() -> list[dict[str, Any]]:
    path = Path(__file__).with_name("seed") / "documents.json"
    return json.loads(path.read_text(encoding="utf-8"))
