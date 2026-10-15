from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from contracts import UserContext
from injection.indirect_scanner import scan_document
from rag.seed_data import documents

_DOCUMENTS = Path(__file__).with_name("seed") / "documents.json"
_STOPWORDS = {
    "a", "an", "and", "are", "as", "for", "how", "i", "in", "is", "it", "me",
    "of", "on", "or", "the", "to", "was", "what", "who", "with",
    "restricted",
}


def _tokens(value: str) -> set[str]:
    return {
        token for token in re.findall(r"[a-z0-9]+", value.lower())
        if token not in _STOPWORDS
    }


def retrieve(query: str, user: UserContext, k: int = 4) -> dict[str, Any]:
    if os.getenv("RAG_BACKEND", "keyword").lower() == "chroma":
        return _retrieve_chroma(query, user, k)
    source_documents = documents()
    query_tokens = _tokens(query)
    eligible: list[tuple[int, dict[str, Any]]] = []
    denied: list[str] = []
    for document in source_documents:
        document_tokens = _tokens(document["title"] + " " + document["text"])
        overlap = len(query_tokens & document_tokens)
        if overlap == 0:
            continue
        allowed = (
            user.role in document["roles"]
            and user.clearance >= document["min_clearance"]
            and (document["department"] == "public" or user.department == document["department"] or user.role == "admin")
        )
        if not allowed:
            denied.append(document["id"])
            continue
        eligible.append((overlap, document))
    eligible.sort(key=lambda item: item[0], reverse=True)
    chunks: list[dict[str, Any]] = []
    for _, document in eligible[:max(1, min(k, 10))]:
        findings = scan_document(document["text"])
        if findings:
            continue
        chunks.append({"doc_id": document["id"], "title": document["title"], "text": document["text"]})
    return {"chunks": chunks, "denied_count": len(denied), "denied_doc_ids": denied}


def _is_allowed(document: dict[str, Any], user: UserContext) -> bool:
    return (
        user.role in document["roles"]
        and user.clearance >= document["min_clearance"]
        and (document["department"] == "public" or user.department == document["department"] or user.role == "admin")
    )


def _retrieve_chroma(query: str, user: UserContext, k: int) -> dict[str, Any]:
    from rag.chroma_store import collection

    store = collection()
    result = store.query(
        query_texts=[query],
        n_results=min(max(store.count(), 1), 100),
        include=["documents", "metadatas", "distances"],
    )
    chunks: list[dict[str, Any]] = []
    denied: list[str] = []
    ids = (result.get("ids") or [[]])[0]
    texts = (result.get("documents") or [[]])[0]
    metadata = (result.get("metadatas") or [[]])[0]
    for doc_id, text, meta in zip(ids, texts, metadata, strict=True):
        access = {
            "roles": str(meta["roles"]).split(","),
            "min_clearance": int(meta["min_clearance"]),
            "department": meta["department"],
        }
        if not _is_allowed(access, user):
            denied.append(doc_id)
            continue
        if scan_document(text):
            continue
        chunks.append({"doc_id": doc_id, "title": meta["title"], "text": text})
        if len(chunks) >= max(1, min(k, 10)):
            break
    return {"chunks": chunks, "denied_count": len(denied), "denied_doc_ids": denied}


def accessible_documents(user: UserContext) -> list[dict[str, str]]:
    source_documents = documents()
    return [
        {"id": doc["id"], "title": doc["title"], "department": doc["department"]}
        for doc in source_documents if _is_allowed(doc, user)
    ]
