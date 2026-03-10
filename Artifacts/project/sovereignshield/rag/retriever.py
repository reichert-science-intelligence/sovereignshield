"""
RAG retriever for SovereignShield — ChromaDB-backed knowledge base of compliance
violations and their remediation fixes. Uses sentence-transformers for embeddings
and cosine similarity for retrieval.
"""
from __future__ import annotations

import os
import tempfile
from typing import Any, Optional, cast
from uuid import uuid4

_COLLECTION_NAME: str = "sovereign_compliance_kb"
_PERSIST_DIR: str = (
    "/tmp/chroma_db"
    if os.name != "nt"
    else os.path.join(tempfile.gettempdir(), "chroma_db")
)
_collection: Optional[Any] = None

chromadb: Optional[Any] = None
embedding_functions: Optional[Any] = None
try:
    import chromadb as _chromadb
    from chromadb.utils import embedding_functions as _ef_mod
except ImportError:
    pass
else:
    chromadb = _chromadb
    embedding_functions = _ef_mod

if chromadb is not None and embedding_functions is not None:
    try:
        _ef = cast(Any, embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        ))
        _client = chromadb.PersistentClient(path=_PERSIST_DIR)
        _collection = _client.get_or_create_collection(
            name=_COLLECTION_NAME,
            embedding_function=_ef,
            metadata={"hnsw:space": "cosine"},  # Supported in ChromaDB 0.4.x–1.x
        )
    except Exception:
        _collection = None


def embed_and_store(
    violation_text: str,
    fix_code: str,
    metadata: dict[str, str],
) -> bool:
    """
    Embed a violation and store it in the knowledge base with its fix.

    Args:
        violation_text: The violation description (stored as document).
        fix_code: The remediation code (stored in metadata).
        metadata: Additional metadata (regulatory_context, confidence_score, etc.).

    Returns:
        True on success, False on failure (e.g., ChromaDB/sentence-transformers unavailable).
    """
    if _collection is None:
        return False
    try:
        doc_id = str(uuid4())
        combined_metadata: dict[str, str | float] = {
            "fix_code": fix_code,
            **metadata,
        }
        # ChromaDB metadata values must be str, int, float, or bool
        normalized: dict[str, str | int | float | bool] = {}
        for k, v in combined_metadata.items():
            if isinstance(v, (str, int, float, bool)):
                normalized[k] = v
            else:
                normalized[k] = str(v)
        _collection.add(
            ids=[doc_id],
            documents=[violation_text],
            metadatas=[normalized],
        )
        return True
    except Exception:
        return False


def retrieve_similar(
    violation_text: str,
    threshold: float = 0.85,
) -> tuple[str | None, float]:
    """
    Retrieve the most similar stored violation and its fix if above threshold.

    Args:
        violation_text: Query text (violation description to match).
        threshold: Minimum similarity score (0–1) to return a hit.

    Returns:
        (fix_code, similarity_score) if a hit above threshold exists,
        (None, 0.0) if collection is empty or no hit above threshold.
    """
    if _collection is None:
        return (None, 0.0)
    try:
        count = _collection.count()
        if count == 0:
            return (None, 0.0)
        results = _collection.query(
            query_texts=[violation_text],
            n_results=1,
            include=["metadatas", "distances"],
        )
        distances = results.get("distances")
        metadatas = results.get("metadatas")
        if not distances or not distances[0]:
            return (None, 0.0)
        distance: float = float(distances[0][0])
        similarity: float = 1.0 - distance
        if similarity < threshold:
            return (None, 0.0)
        if metadatas and metadatas[0]:
            meta = metadatas[0][0]
            fix_code = meta.get("fix_code") if isinstance(meta, dict) else None
            if isinstance(fix_code, str):
                return (fix_code, similarity)
        return (None, 0.0)
    except Exception:
        return (None, 0.0)


def kb_count() -> int:
    """Return the number of documents in the RAG knowledge base."""
    if _collection is None:
        return 0
    try:
        return cast(int, _collection.count())
    except Exception:
        return 0
