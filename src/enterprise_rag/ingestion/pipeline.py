"""Ingestion pipeline: files in, ACL-tagged vectors out.

Order of operations for every document:

``load -> classify (manifest / path policy / PII escalation) -> chunk ->
 embed -> upsert into ChromaDB with ACL metadata -> catalog + audit``

The pipeline is the only place that writes to the vector store, which keeps the
security-critical metadata write in one auditable code path: a chunk can never
reach the index without an ACL attached by the classifier.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from enterprise_rag.audit.log import AuditLog
from enterprise_rag.config import Settings
from enterprise_rag.ingestion.catalog import CatalogEntry, DocumentCatalog
from enterprise_rag.ingestion.chunker import DocumentChunker
from enterprise_rag.ingestion.classifier import ClassificationOutcome, SensitivityClassifier
from enterprise_rag.ingestion.loaders import (
    LoaderError,
    iter_corpus_files,
    load_document,
)
from enterprise_rag.retrieval.embeddings import DiskCachedEmbeddings
from enterprise_rag.retrieval.vector_store import VectorStore

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class IngestedDocument:
    """One document processed by the pipeline."""

    doc_id: str
    title: str
    relative_path: str
    doc_format: str
    classification: str
    chunks: int
    characters: int
    classification_source: str
    escalated: bool
    contains_pii: bool
    canary: str | None
    findings: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "doc_id": self.doc_id,
            "title": self.title,
            "path": self.relative_path,
            "format": self.doc_format,
            "classification": self.classification,
            "chunks": self.chunks,
            "characters": self.characters,
            "classified_by": self.classification_source,
            "escalated": self.escalated,
            "contains_pii": self.contains_pii,
            "canary": self.canary,
            "findings": list(self.findings),
        }


@dataclass(frozen=True, slots=True)
class IngestionReport:
    """Summary of an ingestion run."""

    documents: tuple[IngestedDocument, ...] = ()
    errors: tuple[dict[str, str], ...] = ()
    deleted: tuple[str, ...] = ()
    total_chunks: int = 0
    by_classification: dict[str, int] = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""
    dry_run: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "documents": [d.as_dict() for d in self.documents],
            "errors": list(self.errors),
            "deleted": list(self.deleted),
            "total_documents": len(self.documents),
            "total_chunks": self.total_chunks,
            "by_classification": self.by_classification,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "dry_run": self.dry_run,
        }

    def to_markdown(self) -> str:
        breakdown = ", ".join(f"{k}={v}" for k, v in sorted(self.by_classification.items()))
        escalated = sum(1 for d in self.documents if d.escalated)
        lines = [
            "## Ingestion report",
            "",
            f"- Documents: **{len(self.documents)}**",
            f"- Chunks: **{self.total_chunks}**",
            f"- By classification: {breakdown}",
            f"- Escalated by content inspection: **{escalated}**",
        ]
        if self.errors:
            lines.append(f"- Errors: **{len(self.errors)}**")
        lines += [
            "",
            "| Document | Classification | Chunks | Classified by | PII |",
            "| --- | --- | --- | --- | --- |",
        ]
        for doc in self.documents:
            pii = ", ".join(doc.findings) if doc.contains_pii else ""
            lines.append(
                f"| `{doc.doc_id}` | {doc.classification} | {doc.chunks} | "
                f"{doc.classification_source} | {pii} |"
            )
        return "\n".join(lines)


class IngestionPipeline:
    """File -> chunks -> vectors, with classification and audit."""

    def __init__(
        self,
        settings: Settings,
        store: VectorStore,
        *,
        classifier: SensitivityClassifier | None = None,
        chunker: DocumentChunker | None = None,
        catalog: DocumentCatalog | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.classifier = classifier or SensitivityClassifier.from_file(settings)
        self.chunker = chunker or DocumentChunker(settings)
        self.catalog = (
            catalog if catalog is not None else DocumentCatalog.load(settings.catalog_path)
        )
        self.audit = audit

    # ------------------------------------------------------------------ run
    def run(
        self,
        paths: Sequence[Path] | None = None,
        *,
        reset: bool = False,
        dry_run: bool = False,
    ) -> IngestionReport:
        """Ingest the corpus (or an explicit file list) into the vector store."""
        started = datetime.now(UTC)
        files = list(paths) if paths else list(iter_corpus_files(self.settings.corpus_path))
        if reset and not dry_run:
            self.store.reset()
            # Clear in place: callers (AppContext) hold a reference to this catalog
            # object, and rebinding it would leave them with a stale, empty view.
            self.catalog.entries.clear()
            self.catalog.generated_at = ""

        documents: list[IngestedDocument] = []
        errors: list[dict[str, str]] = []
        for path in files:
            try:
                document = self.ingest_file(path, dry_run=dry_run)
            except LoaderError as exc:
                errors.append({"path": str(path), "error": str(exc)})
                logger.warning("Skipped %s: %s", path, exc)
                continue
            documents.append(document)

        deleted: list[str] = []
        if not dry_run:
            deleted = self._prune_missing({d.doc_id for d in documents})
            self.catalog.save(self.settings.catalog_path)
            self._flush_embeddings()

        report = IngestionReport(
            documents=tuple(documents),
            errors=tuple(errors),
            deleted=tuple(deleted),
            total_chunks=sum(d.chunks for d in documents),
            by_classification=_count_by(documents, lambda d: d.classification),
            started_at=started.isoformat(timespec="seconds"),
            finished_at=datetime.now(UTC).isoformat(timespec="seconds"),
            dry_run=dry_run,
        )
        self._audit(report, dry_run=dry_run)
        return report

    def ingest_file(self, path: Path, *, dry_run: bool = False) -> IngestedDocument:
        """Load, classify, chunk and index a single file."""
        document = load_document(path, corpus_root=self.settings.corpus_path)
        relative = _relative(path, self.settings.corpus_path)
        outcome = self.classifier.classify(document, relative)
        chunks, stats = self.chunker.chunk(document, outcome.acl)

        if not dry_run:
            self.store.add_chunks(chunks)
            self.catalog.replace(
                document.doc_id,
                CatalogEntry(
                    acl=outcome.acl,
                    chunk_count=stats.chunks,
                    classification_source=outcome.source,
                    findings=outcome.findings,
                    relative_path=relative,
                ),
            )
            if self.audit is not None:
                self.audit.record(
                    actor="system:ingestion",
                    action="ingestion.document",
                    outcome="success",
                    severity="warning" if outcome.escalated else "info",
                    details={
                        "doc_id": document.doc_id,
                        "path": relative,
                        "format": document.doc_format,
                        "classification": outcome.acl.classification.value,
                        "classified_by": outcome.source,
                        "escalated": outcome.escalated,
                        "chunks": stats.chunks,
                        "contains_pii": outcome.acl.contains_pii,
                        "canary_issued": bool(outcome.acl.canary),
                    },
                )

        return IngestedDocument(
            doc_id=document.doc_id,
            title=document.title,
            relative_path=relative,
            doc_format=document.doc_format,
            classification=outcome.acl.classification.value,
            chunks=stats.chunks,
            characters=stats.characters,
            classification_source=outcome.source,
            escalated=outcome.escalated,
            contains_pii=outcome.acl.contains_pii,
            canary=outcome.acl.canary,
            findings=outcome.findings,
        )

    def classify_only(self, path: Path) -> ClassificationOutcome:
        """Classify a file without indexing it (used by the admin preview)."""
        document = load_document(path, corpus_root=self.settings.corpus_path)
        return self.classifier.classify(document, _relative(path, self.settings.corpus_path))

    # -------------------------------------------------------------- internals
    def _prune_missing(self, keep: set[str]) -> list[str]:
        """Remove catalog + vector entries for documents that no longer exist."""
        removed = self.catalog.prune(keep)
        if removed:
            self.store.delete_documents(removed)
            if self.audit is not None:
                self.audit.record(
                    actor="system:ingestion",
                    action="ingestion.deleted",
                    outcome="success",
                    severity="warning",
                    details={"doc_ids": removed, "reason": "source file removed"},
                )
        return removed

    def _flush_embeddings(self) -> None:
        embeddings = getattr(self.store, "embeddings", None)
        if isinstance(embeddings, DiskCachedEmbeddings):
            embeddings.flush()

    def _audit(self, report: IngestionReport, *, dry_run: bool) -> None:
        if self.audit is None:
            return
        self.audit.record(
            actor="system:ingestion",
            action="ingestion.completed",
            outcome="success",
            severity="warning" if report.errors else "info",
            details={
                "documents": len(report.documents),
                "chunks": report.total_chunks,
                "deleted": list(report.deleted),
                "errors": list(report.errors),
                "by_classification": report.by_classification,
                "dry_run": dry_run,
            },
        )


def _relative(path: Path, root: Path) -> str:
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return Path(path).name


def _count_by(
    documents: Iterable[IngestedDocument], key: Callable[[IngestedDocument], str]
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for document in documents:
        name = key(document)
        counts[name] = counts.get(name, 0) + 1
    return counts


__all__ = ["IngestedDocument", "IngestionPipeline", "IngestionReport"]
