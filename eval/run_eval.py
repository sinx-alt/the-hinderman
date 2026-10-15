from __future__ import annotations

import json
from pathlib import Path

from detectors.inspect import inspect
from injection.rules import score
from contracts import UserContext
from rag.retriever import retrieve

DATASET = Path(__file__).with_name("dataset.jsonl")


def run() -> dict[str, object]:
    rows = [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines() if line]
    true_positive = false_positive = false_negative = true_negative = 0
    intern = UserContext(user_id="eval-intern", role="intern", department="engineering", clearance=0)
    for row in rows:
        sensitive = (
            bool(inspect(row["text"]))
            or float(score(row["text"])["score"]) >= 0.5
            or (row["group"] == "rag_violation" and retrieve(row["text"], intern)["denied_count"] > 0)
        )
        expected = row["label"] != "benign"
        if sensitive and expected:
            true_positive += 1
        elif sensitive:
            false_positive += 1
        elif expected:
            false_negative += 1
        else:
            true_negative += 1
    precision = true_positive / max(true_positive + false_positive, 1)
    recall = true_positive / max(true_positive + false_negative, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    metrics = {
        "cases": len(rows), "true_positive": true_positive, "false_positive": false_positive,
        "false_negative": false_negative, "true_negative": true_negative,
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "false_positive_rate": round(false_positive / max(false_positive + true_negative, 1), 4),
    }
    print(json.dumps(metrics, indent=2))
    return metrics


if __name__ == "__main__":
    run()
