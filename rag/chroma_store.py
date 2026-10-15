from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from rag.seed_data import documents


@lru_cache(maxsize=1)
def collection() -> Any:
    try:
        import chromadb
        from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
    except ImportError as exc:
        raise RuntimeError("Install requirements-rag.txt to enable ChromaDB retrieval") from exc
    embedding = SentenceTransformerEmbeddingFunction(
        model_name=os.getenv("RAG_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    )
    client = chromadb.PersistentClient(path=os.getenv("CHROMA_PATH", "data/chroma"))
    return client.get_or_create_collection(
        name="hinderman_documents",
        embedding_function=embedding,
        metadata={"hnsw:space": "cosine"},
    )


def ingest() -> int:
    store = collection()
    existing = store.get()
    if existing["ids"]:
        store.delete(ids=existing["ids"])
    source_documents = documents()
    store.add(
        ids=[item["id"] for item in source_documents],
        documents=[item["text"] for item in source_documents],
        metadatas=[
            {
                "title": item["title"],
                "department": item["department"],
                "min_clearance": item["min_clearance"],
                "roles": ",".join(item["roles"]),
            }
            for item in source_documents
        ],
    )
    return len(source_documents)
