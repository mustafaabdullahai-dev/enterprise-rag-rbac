"""Authorization: document ACLs and the deny-by-default decision engine.

Three layers of enforcement are used across the system and all of them live here
so the policy is written once:

1. **Query-time filter** - ``chroma_where`` builds a metadata filter that stops
   ChromaDB from ever returning chunks the principal cannot read.
2. **Result-time filter** - ``filter_metadata`` re-checks every returned chunk in
   Python. Even a buggy/missing vector filter cannot leak.
3. **Citation check** - ``authorize_metadata`` validates each document a model
   cites before the answer is released.

Rule IDs (``ACL-xx``) are recorded in the audit log so refusals are explainable.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from enterprise_rag.security.identity import Classification, Department, User

ANY_STAFF = "*"


@dataclass(frozen=True, slots=True)
class DocumentACL:
    """Access-control metadata attached to every ingested document."""

    doc_id: str
    title: str
    department: str
    classification: Classification = Classification.INTERNAL
    allowed_roles: frozenset[str] = frozenset()
    allowed_departments: frozenset[str] = frozenset()
    source_path: str = ""
    doc_format: str = ""
    canary: str | None = None
    contains_pii: bool = False
    pii_types: tuple[str, ...] = ()
    reason: str = ""

    def __post_init__(self) -> None:
        # Defensive: accept a plain string so JSON round-trips cannot break the PDP.
        if isinstance(self.classification, str):
            object.__setattr__(self, "classification", Classification(self.classification))

    @property
    def is_public(self) -> bool:
        return self.classification is Classification.PUBLIC

    @property
    def grants_any_staff(self) -> bool:
        return ANY_STAFF in self.allowed_roles

    def to_metadata(self) -> dict[str, Any]:
        """Flat, ChromaDB-safe metadata representation of this ACL."""
        meta: dict[str, Any] = {
            "doc_id": self.doc_id,
            "doc_title": self.title,
            "doc_department": self.department,
            "doc_format": self.doc_format,
            "classification": self.classification.value,
            "acl_any_staff": self.grants_any_staff,
            "contains_pii": self.contains_pii,
            "pii_types": ",".join(self.pii_types),
        }
        for role in sorted(self.allowed_roles - {ANY_STAFF}):
            meta[f"acl_role_{role}"] = True
        for dept in sorted(self.allowed_departments):
            meta[f"acl_dept_{dept}"] = True
        if self.canary:
            meta["canary"] = self.canary
        return meta

    @classmethod
    def from_metadata(cls, meta: Mapping[str, Any]) -> DocumentACL:
        """Rebuild an ACL from flat chunk metadata (inverse of ``to_metadata``)."""
        roles = {k[len("acl_role_") :] for k, v in meta.items() if k.startswith("acl_role_") and v}
        if meta.get("acl_any_staff"):
            roles.add(ANY_STAFF)
        depts = {k[len("acl_dept_") :] for k, v in meta.items() if k.startswith("acl_dept_") and v}
        return cls(
            doc_id=str(meta.get("doc_id", "")),
            title=str(meta.get("doc_title", "")),
            department=str(meta.get("doc_department", "")),
            classification=Classification(meta.get("classification", "internal")),
            allowed_roles=frozenset(roles),
            allowed_departments=frozenset(depts),
            source_path=str(meta.get("source_path", "")),
            doc_format=str(meta.get("doc_format", "")),
            canary=str(meta["canary"]) if meta.get("canary") else None,
            contains_pii=bool(meta.get("contains_pii", False)),
            pii_types=tuple(t for t in str(meta.get("pii_types", "")).split(",") if t),
        )


@dataclass(frozen=True, slots=True)
class AccessDecision:
    """Outcome of an authorization check, with an explainable rule id."""

    allowed: bool
    rule: str
    reason: str
    required_clearance: int = 1
    user_clearance: int = 1
    required_roles: frozenset[str] = field(default_factory=frozenset)

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.allowed


class Authorizer:
    """Deny-by-default policy decision point (PDP)."""

    def authorize(self, user: User, acl: DocumentACL) -> AccessDecision:
        """Decide whether ``user`` may read a document described by ``acl``."""
        need = acl.classification.min_clearance

        if not user.active:
            return AccessDecision(
                False, "ACL-00", "Account is disabled.", need, user.clearance, acl.allowed_roles
            )

        if acl.is_public:
            return AccessDecision(
                True, "ACL-01", "Document is classified public.", need, user.clearance
            )

        role_grant = bool(acl.allowed_roles & user.role_names)
        staff_grant = acl.grants_any_staff
        dept_grant = user.department.value in acl.allowed_departments

        if not (role_grant or staff_grant or dept_grant):
            return AccessDecision(
                False,
                "ACL-05",
                "No role, department or all-staff grant for this document.",
                need,
                user.clearance,
                acl.allowed_roles,
            )

        if user.clearance < need:
            return AccessDecision(
                False,
                "ACL-02",
                (
                    f"Clearance {user.clearance} is below the "
                    f"{acl.classification.value} requirement ({need})."
                ),
                need,
                user.clearance,
                acl.allowed_roles,
            )

        rule = "ACL-03" if (role_grant or staff_grant) else "ACL-04"
        return AccessDecision(
            True,
            rule,
            f"Granted via {rule} at clearance {user.clearance} >= {need}.",
            need,
            user.clearance,
            acl.allowed_roles,
        )

    # --------------------------------------------------------------- helpers
    def authorize_metadata(self, user: User, meta: Mapping[str, Any]) -> AccessDecision:
        """Authorize a raw chunk-metadata mapping (used for retrieval + citations)."""
        return self.authorize(user, DocumentACL.from_metadata(meta))

    def filter_metadata(
        self, user: User, chunks: list[Mapping[str, Any]]
    ) -> tuple[list[Mapping[str, Any]], list[tuple[Mapping[str, Any], AccessDecision]]]:
        """Split chunks into (allowed, denied-with-decision) using hard checks."""
        allowed: list[Mapping[str, Any]] = []
        denied: list[tuple[Mapping[str, Any], AccessDecision]] = []
        for chunk in chunks:
            decision = self.authorize_metadata(user, chunk)
            if decision.allowed:
                allowed.append(chunk)
            else:
                denied.append((chunk, decision))
        return allowed, denied

    def visible_doc_ids(self, user: User, catalog: list[DocumentACL]) -> set[str]:
        """Documents in ``catalog`` the principal may read."""
        return {acl.doc_id for acl in catalog if self.authorize(user, acl).allowed}

    def chroma_where(self, user: User) -> dict[str, Any]:
        """Build a ChromaDB ``where`` filter that pre-blocks unauthorized chunks.

        This is layer 1 of 3. It is an optimisation and a defence-in-depth
        measure - never the only check.
        """
        grants: list[dict[str, Any]] = [{"acl_any_staff": {"$eq": True}}]
        for role in sorted(user.role_names):
            grants.append({f"acl_role_{role}": {"$eq": True}})
        grants.append({f"acl_dept_{user.department.value}": {"$eq": True}})

        clauses: list[dict[str, Any]] = [
            {"classification": self._in_or_eq(Classification.levels_visible_to(user.clearance))},
            {"status": {"$eq": "active"}},
        ]
        clauses.append(grants[0] if len(grants) == 1 else {"$or": grants})
        return {"$and": clauses}

    @staticmethod
    def _in_or_eq(values: list[str]) -> dict[str, Any]:
        """ChromaDB rejects ``$in`` with a single value, so fall back to ``$eq``."""
        return {"$eq": values[0]} if len(values) == 1 else {"$in": values}


def department_of(value: str) -> Department:  # pragma: no cover - small helper
    return Department(value)


__all__ = ["ANY_STAFF", "AccessDecision", "Authorizer", "DocumentACL"]
