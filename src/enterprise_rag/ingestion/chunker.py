"""Chunking: structure-aware splitting that keeps citations precise.

Two strategies are used together because enterprise corpora are heterogeneous:

* **Prose** (Markdown, PDF pages, DOCX sections) is split with LangChain's
  ``RecursiveCharacterTextSplitter``.
* **Records** (spreadsheet rows, JSON records) are never split - a row is
  already an atomic, citable unit, and splitting it would corrupt the values a
  reader needs to verify the answer.

Every chunk carries the full ACL metadata for its document plus the source
location, so retrieval, filtering and citation verification all work on the
same flat metadata record.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from langchain_text_splitters import RecursiveCharacterTextSplitter

from enterprise_rag.config import Settings
from enterprise_rag.ingestion.loaders import LoadedDocument, LoadedUnit
from enterprise_rag.models import Chunk
from enterprise_rag.security.acl import DocumentACL

# Units that must stay whole.
ATOMIC_UNITS = {"row", "record", "schema", "table", "table_row"}

PROSE_SEPARATORS = ["\n\n## ", "\n\n### ", "\n\n", "\n", ". ", " ", ""]


@dataclass(frozen=True, slots=True)
class ChunkingStats:
    """Bookkeeping returned alongside the chunks."""

    chunks: int
    split_units: int
    atomic_units: int
    characters: int


class DocumentChunker:
    """Turns a loaded document into ACL-tagged, citable chunks."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._splitter = RecursiveCharacterTextSplitter(
            chunk_size=settings.chunk_size,
            chunk_overlap=settings.chunk_overlap,
            separators=PROSE_SEPARATORS,
            keep_separator=True,
            length_function=len,
        )

    def chunk(
        self, document: LoadedDocument, acl: DocumentACL, *, ingested_at: str | None = None
    ) -> tuple[list[Chunk], ChunkingStats]:
        ingested = ingested_at or datetime.now(UTC).isoformat(timespec="seconds")
        base_metadata = {
            **acl.to_metadata(),
            "source_path": document.source_path,
            "status": "active",
            "ingested_at": ingested,
        }

        chunks: list[Chunk] = []
        split_units = 0
        atomic_units = 0
        ordinal = 0

        for unit in document.units:
            kind = str(unit.metadata.get("unit", "section"))
            pieces = self._split_unit(unit)
            if len(pieces) > 1:
                split_units += 1
            elif kind in ATOMIC_UNITS:
                atomic_units += 1

            for piece_index, text in enumerate(pieces):
                if len(text.strip()) < self.settings.min_chunk_chars and kind not in ATOMIC_UNITS:
                    continue
                ordinal += 1
                if acl.canary and self.settings.embed_canary:
                    # Tripwire: if this text ever reaches a principal who is not
                    # authorised for the document, the output guard sees the canary
                    # and blocks the response.
                    text = f"{text.rstrip()}\n[document-ref: {acl.canary}]"
                chunk_id = _chunk_id(document.doc_id, unit.ref, piece_index, text)
                metadata = {
                    **base_metadata,
                    **{k: v for k, v in unit.metadata.items() if k != "record"},
                    "ref": unit.ref,
                    "unit": kind,
                    "chunk_index": piece_index,
                    "ordinal": ordinal,
                    "content_hash": hashlib.sha1(text.encode("utf-8")).hexdigest()[:16],
                }
                chunks.append(
                    Chunk(
                        chunk_id=chunk_id,
                        doc_id=document.doc_id,
                        text=text.strip(),
                        metadata=metadata,
                        ordinal=ordinal,
                    )
                )

        stats = ChunkingStats(
            chunks=len(chunks),
            split_units=split_units,
            atomic_units=atomic_units,
            characters=sum(len(c.text) for c in chunks),
        )
        return chunks, stats

    def _split_unit(self, unit: LoadedUnit) -> list[str]:
        kind = str(unit.metadata.get("unit", "section"))
        text = unit.text.strip()
        if kind in ATOMIC_UNITS or len(text) <= self.settings.chunk_size:
            return [text] if text else []
        return [piece for piece in self._splitter.split_text(text) if piece.strip()]


def _chunk_id(doc_id: str, ref: str, piece_index: int, text: str) -> str:
    digest = hashlib.sha1(f"{doc_id}|{ref}|{piece_index}|{text[:96]}".encode())
    return digest.hexdigest()[:10]


__all__ = ["ATOMIC_UNITS", "ChunkingStats", "DocumentChunker"]
