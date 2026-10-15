from rag.chroma_store import ingest

if __name__ == "__main__":
    print(f"Ingested {ingest()} ACL-tagged documents into ChromaDB.")
