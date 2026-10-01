"""Answer-quality evaluation: Ragas with a deterministic offline fallback.

``engine="ragas"`` requires:

* ``pip install -r requirements-eval.txt`` (or ``pip install -e ".[eval]"``),
* an OpenAI-compatible endpoint for the **judge** (Ragas scores faithfulness by
  asking a model whether each claim is entailed by the context).

``engine="offline"`` needs neither: it reuses ``evaluation.metrics`` (same metric
names and definitions) so CI, demos and offline environments still produce a
report. ``engine="auto"`` prefers Ragas when it is importable and a judge key is
configured, otherwise it falls back to offline.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from enterprise_rag.context import AppContext
from enterprise_rag.evaluation.dataset import QUALITY_CASES, QualityCase
from enterprise_rag.evaluation.metrics import MetricRow, ScoreCard, aggregate, score_case

logger = logging.getLogger(__name__)

RAGAS_INSTALL_HINT = (
    "Ragas needs the evaluation extra: `pip install -r requirements-eval.txt`, plus "
    "an OpenAI-compatible judge endpoint (LLM_BACKEND=openai and LLM_API_KEY)."
)


def _run_cases(
    context: AppContext, cases: Sequence[QualityCase]
) -> list[tuple[QualityCase, object]]:
    """Execute the quality suite through the production graph."""
    executed: list[tuple[QualityCase, object]] = []
    for case in cases:
        user = context.user_store.get(case.username)
        if user is None:
            logger.warning("Skipping %s: unknown principal %s", case.case_id, case.username)
            continue
        executed.append((case, context.graph.run(user, case.question)))
    return executed


def run_offline(context: AppContext, cases: Sequence[QualityCase] | None = None) -> ScoreCard:
    """Score the quality suite with deterministic, API-free metrics."""
    executed = _run_cases(context, list(cases or QUALITY_CASES))
    rows: list[MetricRow] = []
    for case, result in executed:
        contexts = [str(doc.get("text", "")) for doc in result.documents]
        if not contexts and result.documents:
            contexts = [case.question]
        # Documents in the response do not carry text; fetch from the chunk cache.
        if not contexts:
            contexts = _chunk_texts(context, result)
        rows.append(
            score_case(
                case_id=case.case_id,
                question=case.question,
                answer=result.answer or "",
                contexts=contexts,
                reference=case.reference,
            )
        )
    return aggregate(rows, engine="offline")


def _chunk_texts(context: AppContext, result) -> list[str]:
    """Recover the retrieved chunk text for metric computation."""
    texts: list[str] = []
    for citation in result.citations:
        doc_id = str(citation.get("doc_id", ""))
        chunk_id = str(citation.get("chunk_id", ""))
        for chunk in context.store.fetch_all(limit=5000):
            if chunk.doc_id == doc_id and chunk.chunk_id == chunk_id:
                texts.append(chunk.text)
                break
    return texts


def run_ragas(context: AppContext, cases: Sequence[QualityCase] | None = None) -> ScoreCard:
    """Score the quality suite with Ragas (LLM judge)."""
    try:
        from ragas import EvaluationDataset, evaluate
        from ragas.metrics import (
            AnswerRelevancy,
            ContextPrecision,
            ContextRecall,
            Faithfulness,
        )
    except ImportError as exc:
        return aggregate(
            [], engine="ragas", error=f"Ragas is not installed. {RAGAS_INSTALL_HINT} ({exc})"
        )

    settings = context.settings
    if settings.llm_backend != "openai" or not settings.llm_api_key:
        return aggregate([], engine="ragas", error=f"Ragas needs a judge LLM. {RAGAS_INSTALL_HINT}")

    samples, executed = _build_samples(context, cases)
    if not samples:
        return aggregate([], engine="ragas", error="No quality cases could be executed.")

    try:
        judge = _build_judge(settings)
        embeddings = _build_embeddings(settings)
        evaluation = evaluate(
            dataset=EvaluationDataset(samples=samples),
            metrics=[Faithfulness(), AnswerRelevancy(), ContextPrecision(), ContextRecall()],
            llm=judge,
            embeddings=embeddings,
        )
        scores = {
            str(key): float(value) for key, value in dict(evaluation).items() if value is not None
        }
    except Exception as exc:  # judge outage / parse failure - report, never crash
        logger.exception("Ragas evaluation failed")
        return aggregate([], engine="ragas", error=f"{type(exc).__name__}: {exc}")

    rows = [
        MetricRow(case_id=case.case_id, question=case.question, values=_row_values(scores))
        for case, _result in executed
    ]
    return aggregate(rows, engine="ragas")


def _build_samples(context: AppContext, cases: Sequence[QualityCase] | None):
    """Run the suite and convert results into Ragas ``SingleTurnSample``s."""
    try:
        from ragas import SingleTurnSample
    except ImportError:  # pragma: no cover - guarded by caller
        return [], []

    samples = []
    executed: list[tuple[QualityCase, object]] = []
    for case, result in _run_cases(context, list(cases or QUALITY_CASES)):
        contexts = [str(doc.get("text", "")) for doc in result.documents if doc.get("text")]
        if not contexts:
            contexts = _chunk_texts(context, result)
        samples.append(
            SingleTurnSample(
                question=case.question,
                response=result.answer or "",
                contexts=contexts,
                reference=case.reference,
            )
        )
        executed.append((case, result))
    return samples, executed


def _build_judge(settings):
    from langchain_openai import ChatOpenAI
    from ragas.llms import LangchainLLMWrapper

    return LangchainLLMWrapper(
        ChatOpenAI(
            model=settings.ragas_llm_model or settings.llm_model,
            api_key=settings.llm_api_key,
            base_url=settings.llm_base_url,
            temperature=0,
            max_tokens=settings.llm_max_tokens,
            timeout=int(settings.llm_timeout_seconds),
        )
    )


def _build_embeddings(settings):
    from ragas.embeddings import LangchainEmbeddingsWrapper

    from enterprise_rag.retrieval.embeddings import build_embeddings

    return LangchainEmbeddingsWrapper(build_embeddings(settings))


def _row_values(scores: dict[str, float]) -> dict[str, float]:
    aliases = {
        "faithfulness": ("faithfulness",),
        "answer_relevancy": ("answer_relevancy", "answer_relevance"),
        "context_precision": ("context_precision",),
        "context_recall": ("context_recall",),
    }
    values: dict[str, float] = {}
    for name, keys in aliases.items():
        for key in keys:
            if key in scores:
                values[name] = scores[key]
                break
    return values


def run_quality(
    context: AppContext, engine: str = "auto", cases: Sequence[QualityCase] | None = None
) -> ScoreCard:
    """Run the answer-quality suite with the requested engine."""
    engine = (engine or "auto").lower()
    if engine == "ragas":
        return run_ragas(context, cases)
    if engine == "offline":
        return run_offline(context, cases)
    # auto: prefer Ragas, fall back to deterministic metrics
    try:
        import ragas  # noqa: F401
    except ImportError:
        return run_offline(context, cases)
    if context.settings.llm_backend != "openai" or not context.settings.llm_api_key:
        return run_offline(context, cases)
    card = run_ragas(context, cases)
    if card.ok:
        return card
    logger.warning("Ragas unavailable (%s) - using offline metrics", card.error)
    return run_offline(context, cases)


def save_report(report: ScoreCard | None, red_team, settings) -> Path | None:
    """Persist the latest reports under ``data/eval_reports/``."""
    if report is None and red_team is None:
        return None
    target = settings.eval_path
    target.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")

    quality = report.as_dict() if report is not None else None
    security = red_team.as_dict() if red_team is not None else None
    payload = {"generated_at": datetime.now(UTC).isoformat(timespec="seconds")}
    if quality:
        payload["quality"] = quality
    if security:
        payload["red_team"] = security

    (target / f"report_{stamp}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (target / "latest.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    markdown: list[str] = ["# Evaluation report", ""]
    if report is not None:
        markdown.append(report.to_markdown())
    if red_team is not None:
        markdown += ["", red_team.to_markdown()]
    (target / "latest.md").write_text("\n".join(markdown), encoding="utf-8")
    return target / "latest.md"


__all__ = [
    "run_offline",
    "run_quality",
    "run_ragas",
    "RAGAS_INSTALL_HINT",
    "save_report",
]
