"""ChromaDB-backed vector store.

Wraps ``langchain_chroma.Chroma`` (LangChain's Chroma integration) so chunks are
added and searched through the same interface the rest of LangChain uses, while
we keep direct control of two things that matter for security:

* **ids** - the Chroma document id *is* our chunk id, so citations can be
  verified against exactly what was retrieved.
* **metadata filters** - ``where`` clauses are pushed down to Chroma so
  unauthorized chunks are never even scored.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import chromadb
from langchain_chroma import Chroma
from langchain_core.embeddings import Embeddings

from enterprise_rag.config import Settings
from enterprise_rag.models import Chunk
from enterprise_rag.retrieval.embeddings import build_embeddings

logger = logging.getLogger(__name__)

# Chroma caps a single ``get`` call, so read in pages.
_PAGE_SIZE = 1000


def _clean_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Chroma accepts only str/int/float/bool metadata values."""
    clean: dict[str, Any] = {}
    for key, value in metadata.items():
        if value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            clean[key] = value
        elif isinstance(value, (list, tuple, set)):
            clean[key] = ", ".join(str(item) for item in value)
        else:
            clean[key] = str(value)
    return clean


def _distance_to_similarity(distance: float) -> float:
    """Cosine distance (0..2) -> similarity (0..1)."""
    return max(0.0, min(1.0, 1.0 - distance))


def _to_chunk(document: Any) -> Chunk:
    metadata = dict(document.metadata or {})
    return Chunk(
        chunk_id=str(document.id or metadata.get("chunk_id", "")),
        doc_id=str(metadata.get("doc_id", "")),
        text=document.page_content or "",
        metadata=metadata,
    )


class VectorStore:
    """Persistent chunk store with ACL-aware similarity search."""

    def __init__(
        self,
        settings: Settings,
        *,
        embeddings: Embeddings | None = None,
        client: chromadb.api.ClientAPI | None = None,
    ) -> None:
        self.settings = settings
        self.embeddings = embeddings or build_embeddings(settings)
        path = Path(settings.chroma_path)
        path.mkdir(parents=True, exist_ok=True)
        self._client = client or chromadb.PersistentClient(path=str(path))
        self._store = self._new_store()

    def _new_store(self) -> Chroma:
        return Chroma(
            client=self._client,
            collection_name=self.settings.chroma_collection,
            embedding_function=self.embeddings,
            collection_metadata={"hnsw:space": "cosine"},
        )

    # ------------------------------------------------------------- writing
    def add_chunks(self, chunks: Sequence[Chunk]) -> int:
        """Upsert chunks (id = chunk id, so re-ingestion is idempotent)."""
        if not chunks:
            return 0
        self._store.add_texts(
            texts=[chunk.text for chunk in chunks],
            metadatas=[_clean_metadata(chunk.metadata) for chunk in chunks],
            ids=[chunk.chunk_id for chunk in chunks],
        )
        return len(chunks)

    def delete_documents(self, doc_ids: Sequence[str]) -> None:
        """Remove every chunk belonging to the given documents."""
        for doc_id in doc_ids:
            try:
                self._store.delete(where={"doc_id": doc_id})
            except Exception:  # pragma: no cover - defensive
                logger.exception("Failed to delete chunks for %s", doc_id)

    def reset(self) -> None:
        """Drop and recreate the collection."""
        with contextlib.suppress(Exception):
            self._client.delete_collection(self.settings.chroma_collection)
        self._store = self._new_store()

    # ------------------------------------------------------------- reading
    def count(self) -> int:
        try:
            return len(self.fetch_all())
        except Exception:  # pragma: no cover - defensive
            return 0

    def search(
        self, query: str, *, k: int, where: dict[str, Any] | None = None
    ) -> tuple[list[tuple[Chunk, float]], bool]:
        """Similarity search.

        Returns ``(results, filter_fallback)``. ``filter_fallback`` is True when
        the ACL ``where`` clause could not be applied by Chroma and the query ran
        unfiltered - the caller MUST still post-filter in Python (it does).
        """
        fallback = False
        try:
            hits = self._store.similarity_search_with_score(
                query, k=max(1, k), filter=where or None
            )
        except Exception as exc:
            if where is None:
                raise
            logger.warning(
                "ACL filter rejected by Chroma (%s); falling back to post-filter only", exc
            )
            fallback = True
            hits = self._store.similarity_search_with_score(query, k=max(1, k))

        # Chroma returns cosine *distance*; convert to a similarity in [0, 1].
        return [
            (_to_chunk(document), _distance_to_similarity(float(distance)))
            for document, distance in hits
        ], fallback

    def fetch_all(self, *, limit: int | None = None) -> list[Chunk]:
        """Every stored chunk (used to build the in-memory BM25 index)."""
        chunks: list[Chunk] = []
        offset = 0
        while True:
            page = self._store.get(
                include=["metadatas", "documents"], limit=_PAGE_SIZE, offset=offset
            )
            ids = page.get("ids") or []
            documents = page.get("documents") or []
            metadatas = page.get("metadatas") or []
            for index, chunk_id in enumerate(ids):
                text = documents[index] if index < len(documents) else ""
                metadata = metadatas[index] if index < len(metadatas) else {}
                chunks.append(
                    Chunk(
                        chunk_id=str(chunk_id),
                        doc_id=str((metadata or {}).get("doc_id", "")),
                        text=text or "",
                        metadata=dict(metadata or {}),
                    )
                )
            if len(ids) < _PAGE_SIZE:
                break
            offset += _PAGE_SIZE
            if limit is not None and len(chunks) >= limit:
                break
        return chunks[:limit] if limit else chunks

    def doc_ids(self) -> set[str]:
        return {chunk.doc_id for chunk in self.fetch_all() if chunk.doc_id}


__all__ = ["VectorStore"]
