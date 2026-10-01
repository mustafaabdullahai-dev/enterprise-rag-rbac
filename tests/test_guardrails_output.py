"""Output guardrail tests: citations, canary tripwire, grounding, masking."""

from __future__ import annotations

import pytest

from enterprise_rag.config import Settings
from enterprise_rag.guardrails.output_guard import OutputGuard
from enterprise_rag.models import Chunk, RetrievedChunk
from enterprise_rag.security.identity import demo_users


@pytest.fixture(scope="module")
def guard() -> OutputGuard:
    return OutputGuard(Settings(app_env="test"))


@pytest.fixture(scope="module")
def users():
    return {u.username: u for u in demo_users()}


def _ctx(doc_id: str, chunk_id: str, text: str, *, canary: str = "") -> RetrievedChunk:
    metadata = {
        "doc_id": doc_id,
        "doc_title": doc_id,
        "classification": "restricted" if canary else "public",
    }
    if canary:
        metadata["canary"] = canary
    return RetrievedChunk(
        chunk=Chunk(chunk_id=chunk_id, doc_id=doc_id, text=text, metadata=metadata),
        score=0.9,
    )


BASE_TEXT = (
    "Annual leave entitlement is 24 working days per calendar year, plus public "
    "holidays. Employees request leave through the People portal at least five "
    "working days in advance. Unused leave may be carried over up to five days."
)


def test_clean_cited_answer_is_released(guard, users):
    ctx = _ctx("public-employee-handbook", "abc123def4", BASE_TEXT)
    answer = (
        "Annual leave entitlement is 24 working days per calendar year, plus public "
        "holidays. [public-employee-handbook#abc123def4]"
    )
    verdict = guard.inspect(answer=answer, contexts=[ctx], user=users["amina.yusuf"])
    assert verdict.allowed
    assert verdict.action in {"release", "redact"}
    assert verdict.citations[0].verified


def test_secret_in_answer_blocks_release(guard, users):
    ctx = _ctx("public-employee-handbook", "abc123def4", BASE_TEXT)
    answer = "The key is sk-abcdefghijklmnopqrstuvwx12345 [public-employee-handbook#abc123def4]"
    verdict = guard.inspect(answer=answer, contexts=[ctx], user=users["amina.yusuf"])
    assert not verdict.allowed
    assert verdict.reason_code == "SECRET_IN_OUTPUT"


def test_citation_to_unauthorized_document_blocks_release(guard, users):
    ctx = _ctx("public-employee-handbook", "abc123def4", BASE_TEXT)
    answer = "Salary band B3 pays 112000. [hr-salary-bands-fy2026#9734536f7a]"
    verdict = guard.inspect(
        answer=answer,
        contexts=[ctx],
        user=users["amina.yusuf"],
        authorized_doc_ids={"public-employee-handbook"},
    )
    assert not verdict.allowed
    assert verdict.reason_code == "UNAUTHORIZED_CITATION"
    assert verdict.citations[0].reason == "unauthorized-document"


def test_canary_tripwire_detects_leak(guard, users):
    canary = "CANARY-HRSALARYBANDS-AB12CD34"
    ctx = _ctx("public-employee-handbook", "abc123def4", BASE_TEXT)
    answer = f"The restricted record reads {canary} [public-employee-handbook#abc123def4]"
    verdict = guard.inspect(
        answer=answer,
        contexts=[ctx],
        user=users["amina.yusuf"],
        authorized_doc_ids={"public-employee-handbook"},
        canary_registry={"hr-salary-bands-fy2026": canary},
    )
    assert not verdict.allowed
    assert verdict.reason_code == "CANARY_LEAK"
    assert verdict.canary_hits


def test_canary_is_not_flagged_for_authorized_principals(guard, users):
    canary = "CANARY-HRSALARYBANDS-AB12CD34"
    ctx = _ctx(
        "hr-salary-bands-fy2026",
        "9734536f7a",
        f"Band B3 Senior Engineer salary band details. [document-ref: {canary}]",
        canary=canary,
    )
    answer = "Band B3 Senior Engineer salary band details. [hr-salary-bands-fy2026#9734536f7a]"
    verdict = guard.inspect(
        answer=answer,
        contexts=[ctx],
        user=users["sara.ahmed"],
        authorized_doc_ids={"hr-salary-bands-fy2026"},
        canary_registry={"hr-salary-bands-fy2026": canary},
    )
    assert verdict.allowed


def test_ungrounded_answer_is_blocked(guard, users):
    ctx = _ctx("public-employee-handbook", "abc123def4", BASE_TEXT)
    answer = (
        "The quantum blockchain strategy requires a distributed ledger migration. "
        "Additionally the merger with the fictional vendor closes next quarter. "
        "Forecasted savings exceed thirty million dollars. [public-employee-handbook#abc123def4]"
    )
    verdict = guard.inspect(answer=answer, contexts=[ctx], user=users["amina.yusuf"])
    assert not verdict.allowed
    assert verdict.reason_code == "UNGROUNDED_ANSWER"


def test_pii_in_answer_is_masked(guard, users):
    contact = "The employee can be reached at sara.ahmed@northwind.test or +1-202-555-0188."
    ctx = _ctx("hr-employee-directory", "row5abc1234", contact)
    answer = f"{contact} [hr-employee-directory#row5abc1234]"
    verdict = guard.inspect(answer=answer, contexts=[ctx], user=users["sara.ahmed"])
    assert verdict.allowed
    assert verdict.pii_redacted
    assert "sara.ahmed@northwind.test" not in verdict.answer
    assert "[REDACTED-EMAIL]" in verdict.answer
    assert verdict.reason_code == "PII_REDACTED"


def test_citation_without_retrieved_chunk_is_flagged_unverified(guard, users):
    ctx = _ctx("public-employee-handbook", "abc123def4", BASE_TEXT)
    answer = "Something true from the handbook. [public-employee-handbook#ffffffff99]"
    verdict = guard.inspect(answer=answer, contexts=[ctx], user=users["amina.yusuf"])
    assert verdict.allowed  # document is authorized; only provenance is in question
    assert any(c.reason in {"unknown-chunk", "not-retrieved"} for c in verdict.citations)
