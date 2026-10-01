"""A small BM25 implementation used for hybrid (lexical + vector) retrieval.

Vector search with hashing embeddings is good at "what is this about" but weak on
rare exact tokens - an employee ID, a system name, a currency code. BM25 covers
exactly that gap. Both rankings are fused with Reciprocal Rank Fusion, which is
robust because it uses ranks rather than incomparable scores.

Pure Python on purpose: no extra dependency, fully deterministic, and easy to
audit - which matters when the retrieval path is a security boundary.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence

from enterprise_rag.textutil import tokenize

K1 = 1.5
B = 0.75


class BM25Index:
    """Okapi BM25 over an in-memory corpus of ``(id, text)`` pairs."""

    def __init__(self, documents: Sequence[tuple[str, str]]) -> None:
        self.ids: list[str] = []
        self.term_frequencies: list[Counter[str]] = []
        self.lengths: list[int] = []
        self.document_frequency: Counter[str] = Counter()

        for doc_id, text in documents:
            tokens = _terms(text)
            counts = Counter(tokens)
            self.ids.append(doc_id)
            self.term_frequencies.append(counts)
            self.lengths.append(len(tokens))
            for term in counts:
                self.document_frequency[term] += 1

        self.total_docs = len(self.ids)
        self.average_length = sum(self.lengths) / self.total_docs if self.total_docs else 0.0

    def search(self, query: str, k: int = 20) -> list[tuple[str, float]]:
        """Return ``(doc_id, score)`` for the top ``k`` documents."""
        if not self.total_docs:
            return []
        terms = _terms(query)
        if not terms:
            return []

        scores: list[tuple[str, float]] = []
        for index, doc_id in enumerate(self.ids):
            score = self._score(terms, index)
            if score > 0:
                scores.append((doc_id, score))
        scores.sort(key=lambda item: item[1], reverse=True)
        return scores[:k]

    def _score(self, terms: Sequence[str], index: int) -> float:
        counts = self.term_frequencies[index]
        length = self.lengths[index] or 1
        score = 0.0
        for term in set(terms):
            frequency = counts.get(term, 0)
            if not frequency:
                continue
            df = self.document_frequency.get(term, 0)
            idf = math.log(1 + (self.total_docs - df + 0.5) / (df + 0.5))
            denominator = frequency + K1 * (1 - B + B * length / (self.average_length or 1))
            score += idf * (frequency * (K1 + 1)) / denominator
        return score


def _terms(text: str) -> list[str]:
    return [token for token in tokenize(text) if len(token) > 1]


__all__ = ["BM25Index"]
