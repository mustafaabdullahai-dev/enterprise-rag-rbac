"""Shared data structures for ingestion, retrieval and guardrails.

Kept in one module so retrieval, guardrails and the graph can share types
without importing each other (no circular imports).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Chunk:
    """A retrievable unit of text with its ACL-bearing metadata."""

    chunk_id: str
    doc_id: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)
    ordinal: int = 0

    @property
    def citation(self) -> str:
        return f"[{self.doc_id}#{self.chunk_id}]"

    @property
    def doc_title(self) -> str:
        return str(self.metadata.get("doc_title", self.doc_id))

    @property
    def section(self) -> str:
        return str(self.metadata.get("section", ""))


@dataclass(frozen=True, slots=True)
class RetrievedChunk:
    """A chunk returned by the retriever, with its fused relevance score."""

    chunk: Chunk
    score: float = 0.0
    source: str = "fused"

    @property
    def text(self) -> str:
        return self.chunk.text

    @property
    def doc_id(self) -> str:
        return self.chunk.doc_id

    @property
    def chunk_id(self) -> str:
        return self.chunk.chunk_id

    @property
    def metadata(self) -> dict[str, Any]:
        return self.chunk.metadata

    @property
    def citation(self) -> str:
        return self.chunk.citation

    def as_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "doc_id": self.doc_id,
            "doc_title": self.chunk.doc_title,
            "section": self.chunk.section,
            "classification": self.metadata.get("classification", ""),
            "score": round(self.score, 4),
            "source": self.source,
            "citation": self.citation,
            # Source excerpt so the UI can show (and the evaluator can score)
            # exactly what was used. The chunk is already ACL-approved.
            "text": self.chunk.text[:1200],
        }


@dataclass(frozen=True, slots=True)
class WithheldDocument:
    """A document the retriever blocked, kept for the audit trail."""

    doc_id: str
    title: str
    classification: str
    rule: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "title": self.title,
            "classification": self.classification,
            "rule": self.rule,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    """Everything the retriever observed while answering one query."""

    chunks: tuple[RetrievedChunk, ...] = ()
    withheld: tuple[WithheldDocument, ...] = ()
    candidates: int = 0
    authorized_chunks: int = 0
    strategies: tuple[str, ...] = ()
    filter_fallback: bool = False
    timings_ms: dict[str, float] = field(default_factory=dict)

    @property
    def doc_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(c.doc_id for c in self.chunks))

    @property
    def is_empty(self) -> bool:
        return not self.chunks

    def as_dict(self) -> dict[str, Any]:
        return {
            "chunks": [c.as_dict() for c in self.chunks],
            "withheld": [w.as_dict() for w in self.withheld],
            "candidates": self.candidates,
            "authorized_chunks": self.authorized_chunks,
            "strategies": list(self.strategies),
            "filter_fallback": self.filter_fallback,
            "timings_ms": {k: round(v, 2) for k, v in self.timings_ms.items()},
        }


@dataclass(frozen=True, slots=True)
class Citation:
    """A citation parsed out of a generated answer."""

    doc_id: str
    chunk_id: str
    verified: bool
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "chunk_id": self.chunk_id,
            "verified": self.verified,
            "reason": self.reason,
        }


__all__ = [
    "Chunk",
    "Citation",
    "RetrievalResult",
    "RetrievedChunk",
    "WithheldDocument",
]
