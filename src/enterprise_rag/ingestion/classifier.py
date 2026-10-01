"""Sensitivity classification: how documents get their ACL in the first place.

Three sources are combined, in descending order of authority:

1. **Manifest** (``data/corpus/_manifest.json``) - the explicit label coming from
   the source system / DLP tool. Authoritative when present.
2. **Path policy** - folder-based defaults (``hr/**`` is restricted, ...). This is
   what makes the system safe for documents nobody remembered to label: an
   unlabelled file in ``hr/`` is still restricted.
3. **Content inspection** - PII discovery can only *escalate* a classification,
   never downgrade it. A spreadsheet of salaries that ends up in ``public/`` is
   still treated as confidential, and the escalation is reported.

Classification is deliberately conservative: unlabelled, unknown paths default
to ``internal`` with the owning department only, never to ``public``.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

from enterprise_rag.config import Settings
from enterprise_rag.guardrails.policies import detect_pii_types
from enterprise_rag.ingestion.loaders import LoadedDocument
from enterprise_rag.security.acl import ANY_STAFF, DocumentACL
from enterprise_rag.security.identity import Classification


@dataclass(frozen=True, slots=True)
class PathPolicy:
    """Folder-based default ACL."""

    pattern: str
    classification: Classification
    roles: frozenset[str] = frozenset()
    departments: frozenset[str] = frozenset()
    reason: str = ""


PATH_POLICIES: tuple[PathPolicy, ...] = (
    PathPolicy(
        "public/**",
        Classification.PUBLIC,
        frozenset({ANY_STAFF}),
        frozenset(),
        "Published to all staff.",
    ),
    PathPolicy(
        "engineering/**",
        Classification.INTERNAL,
        frozenset({"manager", "executive"}),
        frozenset({"engineering", "security"}),
        "Engineering handbook material: all engineers plus leadership.",
    ),
    PathPolicy(
        "sales/**",
        Classification.INTERNAL,
        frozenset({"manager", "executive"}),
        frozenset({"sales"}),
        "Sales enablement material.",
    ),
    PathPolicy(
        "finance/**",
        Classification.CONFIDENTIAL,
        frozenset({"finance_analyst", "executive"}),
        frozenset({"finance", "executive"}),
        "Financial data: finance staff and leadership only.",
    ),
    PathPolicy(
        "hr/**",
        Classification.RESTRICTED,
        frozenset({"hr_business_partner", "executive", "compliance_officer"}),
        frozenset({"hr", "executive"}),
        "Employee data: HR, leadership and compliance only.",
    ),
    PathPolicy(
        "legal/**",
        Classification.RESTRICTED,
        frozenset({"legal_counsel", "executive", "compliance_officer"}),
        frozenset({"legal", "executive"}),
        "Privileged legal material.",
    ),
)

DEFAULT_POLICY = PathPolicy(
    "**",
    Classification.INTERNAL,
    frozenset(),
    frozenset(),
    "Unlabelled path: defaulted to internal, owning department only.",
)

# Ranking used by escalation logic.
_RANK: dict[Classification, int] = {
    Classification.PUBLIC: 1,
    Classification.INTERNAL: 2,
    Classification.CONFIDENTIAL: 3,
    Classification.RESTRICTED: 4,
}
_RANK_TO_CLASS = {value: key for key, value in _RANK.items()}

# PII that forces a document up to at least the given classification.
PII_ESCALATION: dict[str, Classification] = {
    "PII-004": Classification.RESTRICTED,  # payment cards
    "PII-003": Classification.RESTRICTED,  # national IDs
    "PII-005": Classification.RESTRICTED,  # IBAN
    "PII-006": Classification.CONFIDENTIAL,  # payroll references
    "PII-007": Classification.CONFIDENTIAL,  # dates of birth
    "PII-002": Classification.CONFIDENTIAL,  # phone numbers
    "PII-001": Classification.INTERNAL,  # emails (directory data)
}

# Published contact details are not a reason to hide an otherwise public document.
CONTACT_PII: frozenset[str] = frozenset({"PII-001", "PII-002"})


@dataclass(frozen=True, slots=True)
class ClassificationOutcome:
    """The ACL plus an explanation of how it was derived."""

    acl: DocumentACL
    source: str
    findings: tuple[str, ...] = ()
    escalated: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.acl.doc_id,
            "title": self.acl.title,
            "classification": self.acl.classification.value,
            "allowed_roles": sorted(self.acl.allowed_roles),
            "allowed_departments": sorted(self.acl.allowed_departments),
            "source": self.source,
            "escalated": self.escalated,
            "contains_pii": self.acl.contains_pii,
            "pii_types": list(self.acl.pii_types),
            "findings": list(self.findings),
            "reason": self.acl.reason,
        }


class SensitivityClassifier:
    """Derives a document ACL from manifest, path policy and content."""

    def __init__(self, settings: Settings, manifest: dict[str, Any] | None = None) -> None:
        self.settings = settings
        self.manifest: dict[str, Any] = manifest or {}

    # -------------------------------------------------------------- loading
    @classmethod
    def from_file(cls, settings: Settings) -> SensitivityClassifier:
        """Load ``_manifest.json`` from the corpus root when present."""
        path = settings.corpus_path / "_manifest.json"
        if not path.exists():
            return cls(settings, {})
        import json

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:  # pragma: no cover - malformed manifest
            return cls(settings, {})
        return cls(settings, payload if isinstance(payload, dict) else {})

    # ----------------------------------------------------------- classifying
    def classify(self, document: LoadedDocument, relative_path: str) -> ClassificationOutcome:
        findings: list[str] = []
        entry = self._manifest_entry(relative_path)
        policy = self._path_policy(relative_path)

        if entry is not None:
            classification = Classification(entry.get("classification", "internal"))
            roles = frozenset(entry.get("roles", []))
            departments = frozenset(entry.get("departments", []))
            reason = str(entry.get("reason", "Declared in the corpus manifest."))
            source = "manifest"
            canary = entry.get("canary")
        elif policy is not None:
            classification = policy.classification
            roles = policy.roles
            departments = policy.departments
            reason = policy.reason
            source = "path-policy"
            canary = None
            findings.append(f"Matched path policy '{policy.pattern}'.")
        else:
            classification = DEFAULT_POLICY.classification
            roles = DEFAULT_POLICY.roles
            departments = DEFAULT_POLICY.departments
            reason = DEFAULT_POLICY.reason
            source = "default"
            canary = None
            findings.append("No manifest entry and no folder policy matched.")

        # --- content inspection: escalate only ---------------------------
        pii_types = tuple(detect_pii_types(document.text[:40_000]))
        escalated = False
        if pii_types:
            required = max(
                (PII_ESCALATION.get(code, Classification.INTERNAL) for code in pii_types),
                key=lambda c: _RANK[c],
            )
            if _RANK[required] > _RANK[classification]:
                if classification is Classification.PUBLIC and set(pii_types) <= CONTACT_PII:
                    findings.append(
                        f"Published contact details ({', '.join(pii_types)}) - no escalation, "
                        "the document is classified public."
                    )
                else:
                    findings.append(
                        f"Escalated {classification.value} -> {required.value} "
                        f"after detecting {', '.join(pii_types)}."
                    )
                    classification = required
                    escalated = True
            if not roles and not departments:
                findings.append(
                    "No owner grant declared; restricting to compliance and leadership."
                )
                roles = frozenset({"compliance_officer", "executive"})
                escalated = True

        if canary is None and _RANK[classification] >= _RANK[Classification.CONFIDENTIAL]:
            canary = self._make_canary(document.doc_id)

        acl = DocumentACL(
            doc_id=document.doc_id,
            title=document.title,
            department=_owning_department(relative_path),
            classification=classification,
            allowed_roles=roles,
            allowed_departments=departments,
            source_path=document.source_path,
            doc_format=document.doc_format,
            canary=str(canary) if canary else None,
            contains_pii=bool(pii_types),
            pii_types=pii_types,
            reason=reason,
        )
        return ClassificationOutcome(
            acl=acl,
            source=source,
            findings=tuple(findings),
            escalated=escalated,
            extra={"relative_path": relative_path},
        )

    # ------------------------------------------------------------- helpers
    def _manifest_entry(self, relative_path: str) -> dict[str, Any] | None:
        """Match an explicit manifest entry (exact path, then glob patterns).

        The manifest ``default`` block is deliberately *not* an override: it only
        applies when no folder policy matches, so a published public document
        cannot be downgraded by a catch-all entry.
        """
        entries = self.manifest.get("documents", self.manifest)
        if not isinstance(entries, dict):
            return None
        if isinstance(entries.get(relative_path), dict):
            return dict(entries[relative_path])
        for pattern, value in entries.items():
            if pattern in {"documents", "default"} or not isinstance(value, dict):
                continue
            if fnmatch.fnmatch(relative_path, pattern):
                return dict(value)
        return None

    @staticmethod
    def _path_policy(relative_path: str) -> PathPolicy | None:
        """Folder policy for a path, or ``None`` when nothing matches."""
        normalized = relative_path.replace("\\", "/").lstrip("./")
        for policy in PATH_POLICIES:
            if fnmatch.fnmatch(normalized, policy.pattern) or fnmatch.fnmatch(
                normalized, policy.pattern.rstrip("/*") + "/*"
            ):
                return policy
        return None

    def _make_canary(self, doc_id: str) -> str:
        import hashlib

        suffix = (
            hashlib.sha1(f"{doc_id}:{self.settings.secret_key}".encode()).hexdigest()[:8].upper()
        )
        return f"{self.settings.canary_prefix}{doc_id.upper().replace('-', '')}-{suffix}"


def _owning_department(relative_path: str) -> str:
    head = re.split(r"[/\\]", relative_path.strip("./"), maxsplit=1)[0].lower()
    return head if head and head.isalpha() else "unknown"


__all__ = [
    "ClassificationOutcome",
    "DEFAULT_POLICY",
    "PATH_POLICIES",
    "PathPolicy",
    "SensitivityClassifier",
]
