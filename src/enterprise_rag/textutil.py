"""Small, dependency-free text utilities shared by the guards and the evaluator.

Keeping one implementation avoids the classic failure mode where the grounding
check and the evaluation metric disagree about what "supported by the context"
means.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

_WORD_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_\-]+|\d[\d.,]*")
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+|\n{1,}")

STOPWORDS: frozenset[str] = frozenset(
    [
        "a",
        "an",
        "the",
        "and",
        "or",
        "but",
        "if",
        "then",
        "than",
        "that",
        "this",
        "these",
        "those",
        "of",
        "in",
        "on",
        "at",
        "to",
        "for",
        "from",
        "by",
        "with",
        "without",
        "into",
        "over",
        "under",
        "again",
        "further",
        "once",
        "here",
        "there",
        "all",
        "any",
        "both",
        "each",
        "few",
        "more",
        "most",
        "other",
        "some",
        "such",
        "no",
        "nor",
        "not",
        "only",
        "own",
        "same",
        "so",
        "too",
        "very",
        "can",
        "will",
        "just",
        "should",
        "could",
        "would",
        "may",
        "might",
        "must",
        "shall",
        "do",
        "does",
        "did",
        "doing",
        "have",
        "has",
        "had",
        "having",
        "be",
        "been",
        "being",
        "is",
        "are",
        "was",
        "were",
        "am",
        "i",
        "you",
        "he",
        "she",
        "it",
        "we",
        "they",
        "them",
        "their",
        "our",
        "your",
        "my",
        "me",
        "us",
        "as",
        "about",
        "above",
        "below",
        "during",
        "before",
        "after",
        "up",
        "down",
        "out",
        "off",
        "between",
        "because",
        "while",
        "when",
        "where",
        "which",
        "who",
        "whom",
        "what",
        "how",
        "why",
    ]
)


def tokenize(text: str) -> list[str]:
    """Lower-cased word/number tokens."""
    return [t.lower() for t in _WORD_RE.findall(text)]


def content_tokens(text: str) -> set[str]:
    """Tokens that carry meaning (no stopwords, length > 2)."""
    return {t for t in tokenize(text) if t not in STOPWORDS and len(t) > 2}


def split_sentences(text: str) -> list[str]:
    """Naive sentence splitter good enough for grounding checks."""
    parts = [p.strip() for p in _SENTENCE_RE.split(text) if p.strip()]
    return parts


def jaccard(left: Iterable[str], right: Iterable[str]) -> float:
    """Jaccard similarity of two token collections."""
    a, b = set(left), set(right)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def overlap_ratio(needle: Iterable[str], haystack: Iterable[str]) -> float:
    """Fraction of ``needle`` tokens present in ``haystack`` (0..1)."""
    needle_set, haystack_set = set(needle), set(haystack)
    if not needle_set:
        return 0.0
    return len(needle_set & haystack_set) / len(needle_set)


def truncate(text: str, limit: int, *, suffix: str = "…") -> str:
    """Hard-truncate ``text`` to ``limit`` characters."""
    if limit <= 0 or len(text) <= limit:
        return text
    return text[: max(0, limit - len(suffix))].rstrip() + suffix


def normalize_rrf(scores: dict[str, float]) -> dict[str, float]:
    """Scale fused scores into 0..1 (max becomes 1.0)."""
    if not scores:
        return {}
    top = max(scores.values())
    if top <= 0:
        return {k: 0.0 for k in scores}
    return {k: v / top for k, v in scores.items()}


__all__ = [
    "content_tokens",
    "jaccard",
    "normalize_rrf",
    "overlap_ratio",
    "split_sentences",
    "STOPWORDS",
    "tokenize",
    "truncate",
]
