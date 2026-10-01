"""Deterministic, dependency-free RAG metrics.

These mirror the definitions used by `Ragas <https://ragas.io>`_ so that:

* the project can score itself in CI and in demos with **no API key**;
* the same metric names mean the same thing when you switch engines
  (``--engine ragas``) for a run with an LLM judge.

Metric definitions (both engines):

``faithfulness``
    Share of answer claims that are supported by the retrieved context.
``answer_relevancy``
    How well the answer addresses the question (bidirectional semantic overlap).
``context_precision``
    How much of what was retrieved is actually relevant to the question.
``context_recall``
    How much of the reference answer is covered by the retrieved context.
``citation_coverage``
    Share of answer statements carrying a citation (this project's own metric).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from enterprise_rag.textutil import (
    content_tokens,
    overlap_ratio,
    split_sentences,
)

MIN_CLAIM_TOKENS = 4
MAX_CLAIM_LEN = 320


@dataclass(frozen=True, slots=True)
class MetricRow:
    """Metric values for a single evaluated case."""

    case_id: str
    question: str
    values: dict[str, float] = field(default_factory=dict)
    notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "question": self.question,
            **{k: round(v, 4) for k, v in self.values.items()},
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class ScoreCard:
    """Aggregate metrics plus the per-case rows behind them."""

    engine: str
    rows: tuple[MetricRow, ...] = ()
    metrics: dict[str, float] = field(default_factory=dict)
    error: str = ""
    generated_at: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "ok": self.ok,
            "error": self.error,
            "generated_at": self.generated_at,
            "metrics": {k: round(v, 4) for k, v in self.metrics.items()},
            "cases": [row.as_dict() for row in self.rows],
        }

    def to_markdown(self) -> str:
        lines = [f"## RAG quality report ({self.engine})", ""]
        if not self.ok:
            return f"{lines}\n**Error:** {self.error}"
        lines.append("| Metric | Score |")
        lines.append("| --- | --- |")
        for name, value in sorted(self.metrics.items()):
            lines.append(f"| {name} | {value:.3f} |")
        lines += [
            "",
            "| Case | " + " | ".join(sorted(self.metrics)) + " |",
            "| --- | " + " | ".join("---" for _ in self.metrics) + " |",
        ]
        for row in self.rows:
            cells = " | ".join(f"{row.values.get(k, 0.0):.3f}" for k in sorted(self.metrics))
            lines.append(f"| {row.case_id} | {cells} |")
        return "\n".join(lines)


def aggregate(rows: Sequence[MetricRow], engine: str, *, error: str = "") -> ScoreCard:
    """Mean of every metric key across rows (ignoring empty rows)."""
    keys: set[str] = set()
    for row in rows:
        keys.update(row.values)
    metrics = {
        key: (
            sum(row.values[key] for row in rows if key in row.values)
            / max(1, sum(1 for row in rows if key in row.values))
        )
        for key in keys
    }
    from datetime import UTC, datetime

    return ScoreCard(
        engine=engine,
        rows=tuple(rows),
        metrics=metrics,
        error=error,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )


# --------------------------------------------------------------------------- #
# Metric implementations
# --------------------------------------------------------------------------- #
def claims(answer: str) -> list[str]:
    """Answer statements big enough to make a factual claim (citations removed)."""
    from enterprise_rag.guardrails.output_guard import CITATION_RE

    cleaned = CITATION_RE.sub(" ", answer or "")
    return [
        sentence.strip()[:MAX_CLAIM_LEN]
        for sentence in split_sentences(cleaned)
        if len(content_tokens(sentence)) >= MIN_CLAIM_TOKENS
    ]


def faithfulness(answer: str, contexts: Sequence[str]) -> float:
    """Share of answer claims entailed by the retrieved context."""
    sentences = claims(answer)
    if not sentences:
        return 0.0
    corpus = content_tokens(" \n ".join(contexts))
    if not corpus:
        return 0.0
    supported = 0
    for sentence in sentences:
        tokens = content_tokens(sentence)
        if overlap_ratio(tokens, corpus) >= 0.6:
            supported += 1
    return supported / len(sentences)


def answer_relevancy(question: str, answer: str) -> float:
    """Bidirectional overlap between the question and the answer."""
    q_tokens = content_tokens(question)
    a_tokens = content_tokens(answer)
    if not q_tokens or not a_tokens:
        return 0.0
    forward = overlap_ratio(q_tokens, a_tokens)
    backward = overlap_ratio(a_tokens, q_tokens)
    return (forward + backward) / 2


def context_precision(question: str, contexts: Sequence[str]) -> float:
    """Relevance-weighted share of retrieved context that answers the question."""
    q_tokens = content_tokens(question)
    if not contexts or not q_tokens:
        return 0.0
    relevant = 0.0
    for rank, context in enumerate(contexts, start=1):
        coverage = overlap_ratio(q_tokens, content_tokens(context))
        if coverage >= 0.25:
            relevant += 1.0 / rank
    return min(1.0, relevant / len(contexts))


def context_recall(reference: str, contexts: Sequence[str]) -> float:
    """Share of reference statements present in the retrieved context."""
    sentences = claims(reference)
    if not sentences:
        return 0.0
    corpus = content_tokens(" \n ".join(contexts))
    found = sum(
        1 for sentence in sentences if overlap_ratio(content_tokens(sentence), corpus) >= 0.6
    )
    return found / len(sentences)


def citation_coverage(answer: str) -> float:
    """Share of factual answer statements carrying a ``[doc#chunk]`` citation.

    Trailing citations are first merged into the statement they belong to:
    ``"...public holidays. [doc#id]"`` is one claim with a citation, not a claim
    without one followed by a citation-only fragment.
    """
    import re

    citation_re = re.compile(r"\[[A-Za-z0-9][A-Za-z0-9_\-]{1,48}#[0-9a-f]{6,16}\]")
    merged = re.sub(
        r"([.!?])\s*(\[[A-Za-z0-9][A-Za-z0-9_\-]{1,48}#[0-9a-f]{6,16}\])", r" \2", answer or ""
    )
    sentences = [
        sentence.strip()
        for sentence in split_sentences(merged)
        if len(content_tokens(sentence)) >= MIN_CLAIM_TOKENS
    ]
    if not sentences:
        return 0.0
    cited = sum(1 for sentence in sentences if citation_re.search(sentence))
    return cited / len(sentences)


def score_case(
    case_id: str,
    question: str,
    answer: str,
    contexts: Sequence[str],
    reference: str = "",
) -> MetricRow:
    """Compute every metric for one case."""
    values = {
        "faithfulness": faithfulness(answer, contexts),
        "answer_relevancy": answer_relevancy(question, answer),
        "context_precision": context_precision(question, contexts),
        "citation_coverage": citation_coverage(answer),
    }
    if reference:
        values["context_recall"] = context_recall(reference, contexts)
    return MetricRow(case_id=case_id, question=question, values=values)


__all__ = [
    "aggregate",
    "answer_relevancy",
    "claims",
    "citation_coverage",
    "context_precision",
    "context_recall",
    "faithfulness",
    "MetricRow",
    "ScoreCard",
    "score_case",
]
