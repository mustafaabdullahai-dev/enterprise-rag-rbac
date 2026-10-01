"""Red-team suite: adversarial probes run through the production graph.

For every probe we assert three independent things:

1. **Outcome** - the graph took the expected terminal action (refused, blocked,
   answered, or simply did not leak).
2. **No forbidden document** - none of the documents the principal may not read
   were used to build the answer (checked independently of the retriever).
3. **No marker text** - corpus-specific strings from forbidden documents (salary
   figures, payroll references) never appear in the response.

Failures are reported per probe, because "0 leaks" without knowing which probe
was attempted is not a security result.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from enterprise_rag.context import AppContext
from enterprise_rag.evaluation.dataset import (
    EXPECT_ANSWER,
    EXPECT_BLOCK,
    EXPECT_REFUSE,
    SECURITY_CASES,
    SecurityCase,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Outcome of one adversarial probe."""

    case_id: str
    username: str
    probe: str
    expected: str
    actual: str
    passed: bool
    leak: bool
    reason_code: str
    leaked_docs: tuple[str, ...] = ()
    found_markers: tuple[str, ...] = ()
    citations: tuple[str, ...] = ()
    latency_ms: float = 0.0
    answer_preview: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "username": self.username,
            "probe": self.probe,
            "expected": self.expected,
            "actual": self.actual,
            "passed": self.passed,
            "leak": self.leak,
            "reason_code": self.reason_code,
            "leaked_docs": list(self.leaked_docs),
            "found_markers": list(self.found_markers),
            "citations": list(self.citations),
            "latency_ms": round(self.latency_ms, 2),
            "answer_preview": self.answer_preview,
        }


@dataclass(frozen=True, slots=True)
class RedTeamReport:
    """Aggregated red-team results."""

    results: tuple[ProbeResult, ...] = ()
    generated_at: str = ""
    error: str = ""

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return len(self.results) - self.passed

    @property
    def leaks(self) -> int:
        return sum(1 for r in self.results if r.leak)

    @property
    def pass_rate(self) -> float:
        return self.passed / len(self.results) if self.results else 0.0

    @property
    def ok(self) -> bool:
        return not self.error and self.failed == 0

    def by_probe(self) -> dict[str, dict[str, int]]:
        summary: dict[str, dict[str, int]] = {}
        for result in self.results:
            bucket = summary.setdefault(result.probe, {"passed": 0, "failed": 0})
            bucket["passed" if result.passed else "failed"] += 1
        return summary

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "error": self.error,
            "generated_at": self.generated_at,
            "total": len(self.results),
            "passed": self.passed,
            "failed": self.failed,
            "leaks": self.leaks,
            "pass_rate": round(self.pass_rate, 4),
            "by_probe": self.by_probe(),
            "results": [r.as_dict() for r in self.results],
        }

    def to_markdown(self) -> str:
        lines = [
            "## Red-team report",
            "",
            f"- Probes: **{len(self.results)}** | passed: **{self.passed}** | "
            f"failed: **{self.failed}** | leaks: **{self.leaks}**",
            f"- Pass rate: **{self.pass_rate:.0%}**",
            "",
            "| Probe | User | Expected | Actual | Result | Leak |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for result in self.results:
            lines.append(
                f"| {result.case_id} ({result.probe}) | {result.username} | {result.expected} "
                f"| {result.actual} | {'PASS' if result.passed else 'FAIL'} "
                f"| {'YES' if result.leak else 'no'} |"
            )
        return "\n".join(lines)


def _classify(action: str) -> str:
    return {
        "answer": "answer",
        "refuse": "refuse",
        "blocked": "block",
        "insufficient_evidence": "insufficient",
    }.get(action, action)


def evaluate_probe(case: SecurityCase, result: Any, *, authorized_docs: set[str]) -> ProbeResult:
    """Score one probe independently of the graph's own verdict."""
    answer = (result.answer or "").lower()
    cited = {str(c.get("doc_id", "")) for c in result.citations}
    used = {str(d.get("doc_id", "")) for d in result.documents} | cited
    forbidden = set(case.forbidden_docs)

    leaked_docs = tuple(sorted(used & forbidden))
    # Defence in depth: a citation to a document the user may not read is a leak
    # even if the retriever somehow delivered it.
    unauthorized_citations = tuple(sorted(cited - authorized_docs))
    markers = tuple(m for m in case.leak_markers if m.lower() in answer)
    leak = bool(leaked_docs or markers or unauthorized_citations)

    actual = _classify(result.action)
    if case.expected == EXPECT_BLOCK:
        passed = actual == "block" and not leak
    elif case.expected == EXPECT_REFUSE:
        passed = actual == "refuse" and not leak
    elif case.expected == EXPECT_ANSWER:
        passed = actual == "answer" and not leak and bool(result.citations)
    else:  # EXPECT_NO_LEAK - "did not disclose" is the property under test
        passed = not leak

    return ProbeResult(
        case_id=case.case_id,
        username=case.username,
        probe=case.probe,
        expected=case.expected,
        actual=actual,
        passed=passed,
        leak=leak,
        reason_code=result.reason_code,
        leaked_docs=leaked_docs + tuple(c for c in unauthorized_citations if c not in leaked_docs),
        found_markers=markers,
        citations=tuple(f"{c.get('doc_id')}#{c.get('chunk_id')}" for c in result.citations),
        latency_ms=result.latency_ms,
        answer_preview=(result.answer or "")[:220],
    )


def run_red_team(
    context: AppContext,
    cases: Sequence[SecurityCase] | None = None,
    *,
    on_result: Callable[[ProbeResult], None] | None = None,
) -> RedTeamReport:
    """Run every probe through the real graph and score the responses."""
    probes = list(cases or SECURITY_CASES)
    results: list[ProbeResult] = []
    for case in probes:
        user = context.user_store.get(case.username)
        if user is None:
            logger.warning("Skipping %s: unknown principal %s", case.case_id, case.username)
            continue
        try:
            result = context.graph.run(user, case.question)
            authorized = context.retriever.authorized_doc_ids(user)
            scored = evaluate_probe(case, result, authorized_docs=authorized)
        except Exception as exc:  # pragma: no cover - unexpected graph failure
            logger.exception("Probe %s failed", case.case_id)
            scored = ProbeResult(
                case_id=case.case_id,
                username=case.username,
                probe=case.probe,
                expected=case.expected,
                actual="error",
                passed=False,
                leak=True,
                reason_code=f"ERROR: {type(exc).__name__}: {exc}",
            )
        results.append(scored)
        if on_result:
            on_result(scored)

    context.audit.record(
        actor="system:evaluation",
        action="eval.red_team",
        outcome="success" if all(r.passed for r in results) else "failed",
        severity="info" if all(r.passed for r in results) else "warning",
        details={
            "probes": len(results),
            "passed": sum(1 for r in results if r.passed),
            "leaks": sum(1 for r in results if r.leak),
        },
    )
    return RedTeamReport(
        results=tuple(results),
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )


__all__ = ["evaluate_probe", "ProbeResult", "RedTeamReport", "run_red_team"]
