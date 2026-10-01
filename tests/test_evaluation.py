"""Evaluation harness: offline metrics, red team, report persistence."""

from __future__ import annotations

import pytest

from enterprise_rag.evaluation.dataset import QUALITY_CASES, SECURITY_CASES
from enterprise_rag.evaluation.metrics import (
    answer_relevancy,
    citation_coverage,
    context_recall,
    faithfulness,
    score_case,
)
from enterprise_rag.evaluation.rag_eval import run_offline, run_quality, save_report
from enterprise_rag.evaluation.red_team import run_red_team

GROUNDED = (
    "Annual leave entitlement is 24 working days per calendar year plus public holidays. "
    "[public-employee-handbook#abc123def4]"
)
UNGROUNDED = (
    "Our merger closes in June and the quantum ledger migration is fully funded. "
    "Revenue guidance was raised twice this quarter. "
    "[public-employee-handbook#abc123def4]"
)


# ------------------------------------------------------------------- metrics
def test_faithfulness_is_one_for_grounded_text():
    context = [
        "Annual leave entitlement is 24 working days per calendar year plus public holidays."
    ]
    assert faithfulness(GROUNDED, context) == 1.0


def test_faithfulness_is_zero_for_invented_text():
    context = ["Annual leave entitlement is 24 working days per calendar year."]
    assert faithfulness(UNGROUNDED, context) == 0.0


def test_faithfulness_without_context_is_zero():
    assert faithfulness(GROUNDED, []) == 0.0


def test_citations_do_not_count_as_claims():
    """A citation marker is provenance, not a claim, and must not lower scores."""
    context = [
        "Annual leave entitlement is 24 working days per calendar year plus public holidays."
    ]
    with_citation = faithfulness(GROUNDED, context)
    without = faithfulness(GROUNDED.replace(" [public-employee-handbook#abc123def4]", ""), context)
    assert with_citation == without


def test_answer_relevancy_higher_when_answer_answers_the_question():
    question = "How many days of annual leave do I get?"
    on_topic = answer_relevancy(question, "Annual leave entitlement is 24 working days per year.")
    off_topic = answer_relevancy(question, "The checkout service uses a circuit breaker.")
    assert on_topic > off_topic


def test_context_recall_detects_missing_reference_content():
    context = [
        "Annual leave entitlement is 24 working days per calendar year plus public holidays."
    ]
    reference = (
        "Annual leave entitlement is 24 working days per calendar year plus public holidays. "
        "Leave must be requested five working days in advance."
    )
    assert context_recall(reference, context) == pytest.approx(0.5, abs=0.05)


def test_citation_coverage_counts_cited_claims():
    assert citation_coverage(GROUNDED) == 1.0
    assert (
        citation_coverage("Leave is 24 working days, fully annual entitlement policy here.") == 0.0
    )


def test_score_case_returns_all_metrics():
    row = score_case(
        "X-1",
        "How many days of annual leave?",
        GROUNDED,
        ["Annual leave entitlement is 24 working days per calendar year plus public holidays."],
        reference="Annual leave entitlement is 24 working days per calendar year.",
    )
    assert set(row.values) >= {
        "faithfulness",
        "answer_relevancy",
        "context_precision",
        "citation_coverage",
        "context_recall",
    }
    assert all(0.0 <= value <= 1.0 for value in row.values.values())


# ----------------------------------------------------------------- end to end
def test_offline_quality_suite_runs_and_scores(context):
    report = run_offline(context)
    assert report.ok
    assert report.engine == "offline"
    assert report.rows
    assert report.metrics["faithfulness"] >= 0.5, report.metrics
    assert "## RAG quality report" in report.to_markdown()


def test_auto_engine_falls_back_to_offline(context):
    report = run_quality(context, engine="auto")
    assert report.ok
    assert report.engine in {"offline", "ragas"}


def test_ragas_engine_reports_missing_judge_clearly(context):
    """Without the evaluation extra the report must explain how to enable it."""
    report = run_quality(context, engine="ragas")
    if not report.ok:
        assert "Ragas" in report.error or "judge" in report.error


def test_red_team_all_probes_pass(context):
    report = run_red_team(context)
    assert report.leaks == 0, report.as_dict()
    assert report.ok, [r.as_dict() for r in report.results if not r.passed]
    assert report.pass_rate == 1.0
    assert "## Red-team report" in report.to_markdown()


def test_red_team_covering_every_probe_class(context):
    report = run_red_team(context)
    probes = {result.probe for result in report.results}
    assert {
        "injection",
        "privilege_escalation",
        "cross_department",
        "indirect_injection",
        "segregation_of_duties",
    } <= probes


def test_reports_are_persisted(context, settings):
    quality = run_offline(context)
    security = run_red_team(context)
    path = save_report(quality, security, settings)
    assert path and path.exists()
    assert (settings.eval_path / "latest.json").exists()
    assert (settings.eval_path / "latest.md").exists()


def test_datasets_reference_known_principals(context):
    usernames = {u.username for u in context.user_store.list()}
    for case in (*QUALITY_CASES, *SECURITY_CASES):
        assert case.username in usernames, f"{case.case_id} references unknown user {case.username}"
