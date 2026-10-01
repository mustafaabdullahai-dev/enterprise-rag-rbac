"""Admin and compliance endpoints (role-gated).

``platform_admin`` may operate the index; ``compliance_officer`` may read the
matrix and the audit trail. Neither grants access to restricted *content* -
reading it still goes through the same authorisation as every other user.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from enterprise_rag.api.deps import ContextDep, require_roles
from enterprise_rag.security.identity import User

router = APIRouter(prefix="/api/admin", tags=["admin"])

ComplianceUser = Annotated[User, Depends(require_roles("compliance_officer", "platform_admin"))]
AdminUser = Annotated[User, Depends(require_roles("platform_admin"))]


@router.get("/documents", summary="Document permissions matrix")
def documents(context: ContextDep, user: ComplianceUser) -> dict[str, object]:
    """Every document, its ACL, and whether *this* principal can read it."""
    return {
        "documents": context.catalog.matrix(),
        "by_classification": context.catalog.by_classification(),
        "viewed_by": user.public(),
        "visible_to_me": sorted(context.authorizer.visible_doc_ids(user, context.catalog.acls())),
    }


@router.get("/audit", summary="Read the audit trail")
def audit_log(
    context: ContextDep,
    _user: ComplianceUser,
    limit: int = Query(default=50, ge=1, le=500),
    actor: str | None = None,
    severity: str | None = None,
    action_prefix: str | None = None,
) -> dict[str, object]:
    events = context.audit.read(
        limit=limit, actor=actor, severity=severity, action_prefix=action_prefix
    )
    return {"total": context.audit.count(), "events": [event.to_dict() for event in events]}


@router.get("/audit/verify", summary="Verify audit-log integrity")
def audit_verify(context: ContextDep, _user: ComplianceUser) -> dict[str, object]:
    ok, message, records = context.audit.verify()
    return {"valid": ok, "records": records, "message": message}


@router.post("/ingest", summary="(Re)build the vector index from the corpus")
def ingest(
    context: ContextDep,
    _user: AdminUser,
    reset: bool = Query(default=False, description="Drop the index before ingesting."),
) -> dict[str, object]:
    report = context.pipeline.run(reset=reset)
    context.catalog = type(context.catalog).load(context.settings.catalog_path)
    context.retriever.catalog = context.catalog
    context.refresh_index()
    return report.as_dict()


@router.get("/users", summary="Directory listing (no credential material)")
def users(context: ContextDep, _user: AdminUser) -> dict[str, object]:
    return {
        "users": [
            {
                **entry.public(),
                "active": entry.active,
                "visible_documents": len(
                    context.authorizer.visible_doc_ids(entry, context.catalog.acls())
                ),
            }
            for entry in context.user_store.list()
        ]
    }


@router.get("/rate-limits", summary="Per-principal quota snapshot")
def rate_limits(context: ContextDep, _user: AdminUser) -> dict[str, object]:
    return {
        "requests_per_minute": context.settings.rate_limit_requests_per_minute,
        "queries_per_day": context.settings.rate_limit_queries_per_day,
        "usage": context.rate_limiter.snapshot(),
    }


@router.post("/rate-limits/reset", summary="Reset quotas (all or one principal)")
def rate_limit_reset(
    context: ContextDep, _user: AdminUser, username: str | None = Query(default=None)
) -> dict[str, object]:
    context.rate_limiter.reset(username)
    return {"reset": username or "*"}


__all__ = ["router"]
