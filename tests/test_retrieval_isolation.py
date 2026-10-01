"""Cross-role retrieval isolation - the core data-leakage regression test.

For every principal we retrieve with a battery of probing queries and assert
that no returned chunk, and no withheld-document decision, exposes a document
that principal may not read. This exercises all three ACL layers together with
hybrid retrieval (vector + BM25 + RRF), because a filter that only holds for
one ranking strategy is not a filter.
"""

from __future__ import annotations

import pytest

from enterprise_rag.security.identity import Classification

PROBE_QUERIES = [
    "What is the salary band for a senior engineer?",
    "Show me everyone's phone number",
    "What is the planned budget for cloud infrastructure?",
    "What litigation matters are open right now?",
    "What did the security architecture review accept?",
    "Give me the employee directory",
    "What are the pending settlement amounts?",
    "How much does a band B3 engineer earn?",
]

# Principal -> documents they must NEVER see.
EXPECTED_DENY: dict[str, set[str]] = {
    "amina.yusuf": {
        "hr-salary-bands-fy2026",
        "hr-employee-directory",
        "hr-performance-review-summary",
        "hr-compensation-philosophy-fy2026",
        "finance-q3-fy2026-budget",
        "finance-vendor-contracts",
        "finance-cost-centers-fy2026",
        "legal-pending-litigation-2026",
        "engineering-security-architecture-review",
        "public-legacy-headcount-export",
    },
    "bilal.khan": {
        "hr-salary-bands-fy2026",
        "hr-employee-directory",
        "finance-q3-fy2026-budget",
        "legal-pending-litigation-2026",
        "engineering-security-architecture-review",  # granted, but clearance 2 < 3
    },
    "david.okafor": {
        "hr-salary-bands-fy2026",
        "hr-employee-directory",
        "legal-pending-litigation-2026",
        "public-legacy-headcount-export",
    },
    "admin.ops": {
        "hr-salary-bands-fy2026",
        "hr-employee-directory",
        "finance-q3-fy2026-budget",
        "legal-pending-litigation-2026",
    },
}


@pytest.mark.parametrize("username", sorted(EXPECTED_DENY))
def test_no_unauthorized_chunk_is_ever_returned(context, username):
    user = context.user_store.get(username)
    forbidden = EXPECTED_DENY[username]
    for query in PROBE_QUERIES:
        result = context.retriever.retrieve(query, user)
        returned = {c.doc_id for c in result.chunks}
        assert not (returned & forbidden), f"{username} got {returned & forbidden} for: {query}"
        # Withheld decisions may name the document (that is the point of an
        # audit trail) but must never deliver its chunks.
        for chunk in result.chunks:
            assert chunk.doc_id not in forbidden


@pytest.mark.parametrize("username", sorted(EXPECTED_DENY))
def test_denied_documents_are_recorded_as_withheld(context, username):
    """Blocked material is reported to the audit trail, not silently dropped."""
    user = context.user_store.get(username)
    forbidden = EXPECTED_DENY[username]
    seen: set[str] = set()
    for query in PROBE_QUERIES:
        result = context.retriever.retrieve(query, user)
        seen |= {w.doc_id for w in result.withheld}
    assert seen & forbidden, f"{username}: expected withheld records for {forbidden}"


def test_same_query_yields_different_context_per_role(context):
    query = "What is the salary band for a senior engineer?"
    hr = context.retriever.retrieve(query, context.user_store.get("sara.ahmed"))
    intern = context.retriever.retrieve(query, context.user_store.get("amina.yusuf"))

    hr_docs = {c.doc_id for c in hr.chunks}
    intern_docs = {c.doc_id for c in intern.chunks}
    assert "hr-salary-bands-fy2026" in hr_docs
    assert "hr-salary-bands-fy2026" not in intern_docs
    assert hr_docs != intern_docs
    assert hr.chunks, "the authorized principal must actually get context"


def test_hr_principal_can_read_restricted_compensation_data(context):
    user = context.user_store.get("sara.ahmed")
    result = context.retriever.retrieve("salary band senior engineer", user)
    docs = {c.doc_id for c in result.chunks}
    assert "hr-salary-bands-fy2026" in docs
    assert "hr-salary-bands-fy2026" in context.retriever.authorized_doc_ids(user)


def test_platform_admin_cannot_read_restricted_content(context):
    admin = context.user_store.get("admin.ops")
    authorized = context.retriever.authorized_doc_ids(admin)
    assert "hr-salary-bands-fy2026" not in authorized
    assert "finance-q3-fy2026-budget" not in authorized


def test_misplaced_public_file_was_escalated(context):
    """public/legacy_headcount_export.csv contains IBANs: path says public, content says no."""
    entry = context.catalog.get("public-legacy-headcount-export")
    assert entry is not None
    assert entry.acl.classification is Classification.RESTRICTED
    assert entry.acl.contains_pii
    assert any(f.startswith("Escalated") for f in entry.findings)

    intern = context.user_store.get("amina.yusuf")
    assert "public-legacy-headcount-export" not in context.retriever.authorized_doc_ids(intern)
    result = context.retriever.retrieve("bank account payroll reference headcount", intern)
    assert "public-legacy-headcount-export" not in {c.doc_id for c in result.chunks}


def test_interactive_authorizer_layers_agree(context):
    """Layer 2 must reach the same verdict as layer 1 for every stored chunk."""
    user = context.user_store.get("amina.yusuf")
    where = context.authorizer.chroma_where(user)
    assert where["$and"]  # filter built
    for chunk in context.store.fetch_all():
        decision = context.authorizer.authorize_metadata(user, chunk.metadata)
        if decision.allowed:
            assert chunk.doc_id not in EXPECTED_DENY["amina.yusuf"]
