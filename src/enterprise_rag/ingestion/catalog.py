"""The document catalog: the authoritative list of what exists and who may read it.

The catalog is what lets the system answer "what *could* have been retrieved?"
without touching the vector store, which matters for three jobs:

* showing the permissions matrix in the compliance console,
* resolving canary tokens for the output tripwire,
* recording withheld-document decisions in the audit trail.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from enterprise_rag.security.acl import DocumentACL
from enterprise_rag.security.identity import Classification


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    """One document in the catalog."""

    acl: DocumentACL
    chunk_count: int = 0
    classification_source: str = "path-policy"
    findings: tuple[str, ...] = ()
    relative_path: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.acl.doc_id,
            "title": self.acl.title,
            "department": self.acl.department,
            "classification": self.acl.classification.value,
            "allowed_roles": sorted(self.acl.allowed_roles),
            "allowed_departments": sorted(self.acl.allowed_departments),
            "doc_format": self.acl.doc_format,
            "contains_pii": self.acl.contains_pii,
            "pii_types": list(self.acl.pii_types),
            "canary": self.acl.canary,
            "reason": self.acl.reason,
            "classification_source": self.classification_source,
            "chunk_count": self.chunk_count,
            "findings": list(self.findings),
            "relative_path": self.relative_path,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> CatalogEntry:
        acl = DocumentACL(
            doc_id=str(raw["doc_id"]),
            title=str(raw.get("title", raw["doc_id"])),
            department=str(raw.get("department", "unknown")),
            classification=Classification(raw.get("classification", "internal")),
            allowed_roles=frozenset(raw.get("allowed_roles", [])),
            allowed_departments=frozenset(raw.get("allowed_departments", [])),
            doc_format=str(raw.get("doc_format", "")),
            canary=raw.get("canary"),
            contains_pii=bool(raw.get("contains_pii", False)),
            pii_types=tuple(raw.get("pii_types", [])),
            reason=str(raw.get("reason", "")),
        )
        return cls(
            acl=acl,
            chunk_count=int(raw.get("chunk_count", 0)),
            classification_source=str(raw.get("classification_source", "path-policy")),
            findings=tuple(raw.get("findings", [])),
            relative_path=str(raw.get("relative_path", "")),
        )


@dataclass
class DocumentCatalog:
    """In-memory catalog with JSON persistence."""

    entries: dict[str, CatalogEntry] = field(default_factory=dict)
    generated_at: str = ""

    # ------------------------------------------------------------ mutation
    def replace(self, doc_id: str, entry: CatalogEntry) -> None:
        self.entries[doc_id] = entry

    def extend(self, entries: Iterable[CatalogEntry]) -> None:
        for entry in entries:
            self.replace(entry.acl.doc_id, entry)

    def prune(self, keep: set[str]) -> list[str]:
        """Drop entries whose doc_id is not in ``keep``; returns removed ids."""
        removed = [doc_id for doc_id in self.entries if doc_id not in keep]
        for doc_id in removed:
            self.entries.pop(doc_id, None)
        return removed

    # ------------------------------------------------------------ accessors
    def get(self, doc_id: str) -> CatalogEntry | None:
        return self.entries.get(doc_id)

    def all(self) -> list[CatalogEntry]:
        return sorted(self.entries.values(), key=lambda e: e.acl.doc_id)

    def acls(self) -> list[DocumentACL]:
        return [entry.acl for entry in self.all()]

    def canaries(self) -> dict[str, str]:
        return {e.acl.doc_id: e.acl.canary for e in self.all() if e.acl.canary}

    def restricted_doc_ids(self) -> set[str]:
        return {
            entry.acl.doc_id
            for entry in self.all()
            if entry.acl.classification.value in {"confidential", "restricted"}
        }

    def by_classification(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self.all():
            key = entry.acl.classification.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def matrix(self) -> list[dict[str, Any]]:
        """Compact view used by the compliance console."""
        return [
            {
                "doc_id": e.acl.doc_id,
                "title": e.acl.title,
                "department": e.acl.department,
                "classification": e.acl.classification.value,
                "grants": sorted(
                    e.acl.allowed_roles | {f"dept:{d}" for d in e.acl.allowed_departments}
                ),
                "format": e.acl.doc_format,
                "chunks": e.chunk_count,
                "pii": list(e.acl.pii_types),
                "source": e.classification_source,
            }
            for e in self.all()
        ]

    def __len__(self) -> int:
        return len(self.entries)

    # ------------------------------------------------------------ persistence
    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at or datetime.now(UTC).isoformat(timespec="seconds"),
            "documents": [entry.as_dict() for entry in self.all()],
        }

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.generated_at = self.generated_at or datetime.now(UTC).isoformat(timespec="seconds")
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> DocumentCatalog:
        path = Path(path)
        if not path.exists():
            return cls()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:  # pragma: no cover - corrupted catalog
            return cls()
        catalog = cls(generated_at=str(payload.get("generated_at", "")))
        for raw in payload.get("documents", []):
            try:
                entry = CatalogEntry.from_dict(raw)
            except (KeyError, TypeError):  # pragma: no cover - bad row
                continue
            catalog.replace(entry.acl.doc_id, entry)
        return catalog


__all__ = ["CatalogEntry", "DocumentCatalog"]
