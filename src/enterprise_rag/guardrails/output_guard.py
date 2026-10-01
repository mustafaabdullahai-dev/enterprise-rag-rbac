"""Output guardrails: what we refuse to hand back to the user.

Five checks run on every generated answer, in order:

1. **Secret scan** - credential patterns block the answer outright; there is no
   legitimate reason for a knowledge assistant to emit an API key.
2. **Citation verification** - every ``[doc#chunk]`` marker must point at a chunk
   that (a) was actually retrieved and (b) the user is authorized to read.
   A citation to anything else is treated as a leak attempt.
3. **Canary tripwire** - restricted documents carry a unique canary token. If a
   canary ever surfaces in an answer to a principal who is not authorized for
   that document, the answer is blocked and the event is logged as critical.
   This catches memorisation and pipeline bugs that ACL filtering alone misses.
4. **Grounding** - a sentence-level support check against the retrieved context
   blocks answers that drift away from their sources (anti-hallucination gate).
5. **PII masking** - emails, phone numbers, national IDs, cards, IBANs and
   payroll references are masked on the way out.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from enterprise_rag.config import Settings
from enterprise_rag.guardrails.policies import (
    REFUSAL_BLOCKED,
    REFUSAL_INSUFFICIENT_EVIDENCE,
    SECRET_RULES,
    Finding,
    redact_pii,
    scan,
)
from enterprise_rag.models import Citation, RetrievedChunk
from enterprise_rag.security.identity import User
from enterprise_rag.textutil import content_tokens, overlap_ratio, split_sentences

CITATION_RE = re.compile(r"\[([A-Za-z0-9][A-Za-z0-9_\-]{1,48})#([0-9a-f]{6,16})\]")
RELEASED = ("release", "redact")
Action = Literal["release", "redact", "block"]

# A sentence is "supported" when this fraction of its content words appears in
# the retrieved context.
SUPPORT_THRESHOLD = 0.6
BLOCK_UNSUPPORTED_RATIO = 0.67
MIN_SENTENCE_TOKENS = 4


@dataclass(frozen=True, slots=True)
class OutputVerdict:
    """Result of the output guardrail pass."""

    action: Action
    answer: str
    findings: tuple[Finding, ...] = ()
    citations: tuple[Citation, ...] = ()
    unsupported: tuple[str, ...] = ()
    canary_hits: tuple[str, ...] = ()
    pii_redacted: bool = False
    reason_code: str = "OK"
    refusal: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.action in {"release", "redact"}

    def as_dict(self, *, include_snippets: bool = False) -> dict[str, Any]:
        return {
            "action": self.action,
            "reason_code": self.reason_code,
            "citations": [c.as_dict() for c in self.citations],
            "unsupported": list(self.unsupported[:5]),
            "canary_hits": list(self.canary_hits),
            "pii_redacted": self.pii_redacted,
            "findings": [f.as_dict(include_snippet=include_snippets) for f in self.findings],
            "details": self.details,
        }


class OutputGuard:
    """Final gate between the model and the user."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def inspect(
        self,
        *,
        answer: str,
        contexts: Sequence[RetrievedChunk],
        user: User,
        authorized_doc_ids: set[str] | None = None,
        canary_registry: Mapping[str, str] | None = None,
    ) -> OutputVerdict:
        findings: list[Finding] = []
        text = answer or ""
        authorized = set(
            authorized_doc_ids if authorized_doc_ids is not None else {c.doc_id for c in contexts}
        )

        # 1 - secrets --------------------------------------------------------
        secret_findings = scan(text, SECRET_RULES)
        if secret_findings:
            findings.extend(secret_findings)
            return OutputVerdict(
                action="block",
                answer=REFUSAL_BLOCKED,
                findings=tuple(findings),
                reason_code="SECRET_IN_OUTPUT",
                refusal=REFUSAL_BLOCKED,
            )

        # 2 - citations ------------------------------------------------------
        citations = self._verify_citations(text, contexts, authorized)
        dangling = [c for c in citations if not c.verified]
        if any(c.reason == "unauthorized-document" for c in dangling):
            findings.append(
                Finding(
                    "OUT-002",
                    "Citation to unauthorized document",
                    "critical",
                    80,
                    "Model referenced a document outside the requester's ACL.",
                    dangling[0].doc_id,
                )
            )
            return OutputVerdict(
                action="block",
                answer=REFUSAL_BLOCKED,
                findings=tuple(findings),
                citations=tuple(citations),
                reason_code="UNAUTHORIZED_CITATION",
                refusal=REFUSAL_BLOCKED,
            )

        # 3 - canary tripwire -------------------------------------------------
        canary_hits = self._canary_tripwire(text, authorized, canary_registry or {})
        if canary_hits:
            findings.append(
                Finding(
                    "OUT-003",
                    "Canary token leaked",
                    "critical",
                    90,
                    "Restricted-document canary appeared in an answer to an "
                    "unauthorized principal.",
                    ", ".join(canary_hits[:2]),
                )
            )
            return OutputVerdict(
                action="block",
                answer=REFUSAL_BLOCKED,
                findings=tuple(findings),
                citations=tuple(citations),
                canary_hits=tuple(canary_hits),
                reason_code="CANARY_LEAK",
                refusal=REFUSAL_BLOCKED,
            )

        # 4 - grounding / anti-hallucination ---------------------------------
        unsupported = self._unsupported_sentences(text, contexts)
        sentences = [
            s for s in split_sentences(text) if len(content_tokens(s)) >= MIN_SENTENCE_TOKENS
        ]
        ratio = len(unsupported) / len(sentences) if sentences else 0.0
        if unsupported:
            findings.append(
                Finding(
                    "OUT-004",
                    "Unsupported statements",
                    "warning",
                    25,
                    f"{len(unsupported)} of {len(sentences)} sentence(s) not grounded in context.",
                    unsupported[0][:80],
                )
            )
        if sentences and ratio >= BLOCK_UNSUPPORTED_RATIO:
            return OutputVerdict(
                action="block",
                answer=REFUSAL_INSUFFICIENT_EVIDENCE,
                findings=tuple(findings),
                citations=tuple(citations),
                unsupported=tuple(unsupported),
                reason_code="UNGROUNDED_ANSWER",
                refusal=REFUSAL_INSUFFICIENT_EVIDENCE,
                details={"unsupported_ratio": round(ratio, 3)},
            )

        # 5 - PII masking -----------------------------------------------------
        redacted, pii_findings = (
            redact_pii(text) if self.settings.redact_pii_in_output else (text, [])
        )
        if pii_findings:
            findings.extend(pii_findings)

        return OutputVerdict(
            action="redact" if pii_findings else "release",
            answer=redacted,
            findings=tuple(findings),
            citations=tuple(citations),
            unsupported=tuple(unsupported),
            pii_redacted=bool(pii_findings),
            reason_code="PII_REDACTED" if pii_findings else "OK",
            details={
                "sentences": len(sentences),
                "unsupported_ratio": round(ratio, 3),
                "verified_citations": sum(1 for c in citations if c.verified),
            },
        )

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _verify_citations(
        text: str, contexts: Sequence[RetrievedChunk], authorized: set[str]
    ) -> list[Citation]:
        """Resolve each citation against retrieved chunks and the ACL."""
        retrieved = {(c.doc_id, c.chunk_id) for c in contexts}
        retrieved_docs = {c.doc_id for c in contexts}
        citations: list[Citation] = []
        seen: set[tuple[str, str]] = set()
        for match in CITATION_RE.finditer(text):
            doc_id, chunk_id = match.group(1), match.group(2)
            if (doc_id, chunk_id) in seen:
                continue
            seen.add((doc_id, chunk_id))
            if doc_id not in authorized:
                citations.append(Citation(doc_id, chunk_id, False, "unauthorized-document"))
            elif (doc_id, chunk_id) in retrieved:
                citations.append(Citation(doc_id, chunk_id, True, "ok"))
            elif doc_id in retrieved_docs:
                citations.append(Citation(doc_id, chunk_id, False, "unknown-chunk"))
            else:
                citations.append(Citation(doc_id, chunk_id, False, "not-retrieved"))
        return citations

    @staticmethod
    def _canary_tripwire(text: str, authorized: set[str], registry: Mapping[str, str]) -> list[str]:
        """Return canaries present in ``text`` whose document is not authorized."""
        hits: list[str] = []
        for doc_id, canary in registry.items():
            if not canary or doc_id in authorized:
                continue
            if canary in text:
                hits.append(f"{doc_id}:{canary}")
        return hits

    @staticmethod
    def _unsupported_sentences(text: str, contexts: Sequence[RetrievedChunk]) -> list[str]:
        """Sentence-level grounding check against the retrieved context.

        Citation markers are removed first: ``[hr-salary-bands#abc123]`` is
        provenance, not content, and counting it as an answer token would drag
        every well-cited sentence below the support threshold.
        """
        clean_text = CITATION_RE.sub(" ", text)
        if not contexts:
            return [
                sentence
                for sentence in split_sentences(clean_text)
                if len(content_tokens(sentence)) >= MIN_SENTENCE_TOKENS
            ]
        context_tokens = content_tokens(" \n ".join(c.text for c in contexts))
        unsupported: list[str] = []
        for sentence in split_sentences(clean_text):
            tokens = content_tokens(sentence)
            if len(tokens) < MIN_SENTENCE_TOKENS:
                continue
            if overlap_ratio(tokens, context_tokens) < SUPPORT_THRESHOLD:
                unsupported.append(sentence)
        return unsupported


__all__ = ["CITATION_RE", "OutputGuard", "OutputVerdict", "RELEASED"]
