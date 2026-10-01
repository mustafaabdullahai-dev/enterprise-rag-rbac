"""Retrieval with mandatory, layered authorization.

Authorization is enforced three times on the way to an answer, so a single bug
cannot leak data:

1. **Push-down filter** - ``Authorizer.chroma_where`` restricts the Chroma query
   itself, so unauthorized chunks are never scored or returned.
2. **Post-filter** - every chunk that comes back is re-authorized in Python
   against its own metadata. This layer holds even if layer 1 was skipped
   (e.g. Chroma rejected the filter - the store reports ``filter_fallback``).
3. **Citation check** - the output guard verifies that each ``[doc#chunk]`` the
   model cites was retrieved *and* is authorized.

Evidence retrieval is hybrid: vector search fused with BM25 via Reciprocal Rank
Fusion, which catches both semantic paraphrases and exact rare tokens (employee
IDs, system names, currency codes).

Blocked documents are not silently dropped: they are reported as
``WithheldDocument`` records and written to the audit log, because "we refused"
is a security event worth recording.
"""

from __future__ import annotations

import logging
import time

from enterprise_rag.audit.log import AuditLog
from enterprise_rag.config import Settings
from enterprise_rag.ingestion.catalog import DocumentCatalog
from enterprise_rag.models import Chunk, RetrievalResult, RetrievedChunk, WithheldDocument
from enterprise_rag.retrieval.bm25 import BM25Index
from enterprise_rag.retrieval.vector_store import VectorStore
from enterprise_rag.security.acl import AccessDecision, Authorizer
from enterprise_rag.security.identity import Classification, User
from enterprise_rag.textutil import normalize_rrf

logger = logging.getLogger(__name__)

# Never emit more than this many "withheld" audit records for a single query.
MAX_WITHHELD_AUDIT_EVENTS = 5


class EnterpriseRetriever:
    """ACL-enforcing hybrid retriever."""

    def __init__(
        self,
        settings: Settings,
        store: VectorStore,
        *,
        authorizer: Authorizer | None = None,
        catalog: DocumentCatalog | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.authorizer = authorizer or Authorizer()
        self.catalog = catalog
        self.audit = audit
        self._bm25: BM25Index | None = None
        self._chunk_map: dict[str, Chunk] = {}
        self._index_version = -1

    # -------------------------------------------------------------- indexing
    def refresh(self, *, force: bool = False) -> None:
        """Rebuild the in-memory BM25 index from the vector store."""
        chunks = self.store.fetch_all()
        version = len(chunks)
        if not force and self._bm25 is not None and version == self._index_version:
            return
        self._chunk_map = {chunk.chunk_id: chunk for chunk in chunks}
        self._bm25 = BM25Index([(chunk.chunk_id, chunk.text) for chunk in chunks])
        self._index_version = version
        logger.debug("BM25 index rebuilt over %d chunks", len(chunks))

    def authorized_doc_ids(self, user: User) -> set[str]:
        """Document ids the principal may read (catalog-backed when available)."""
        if self.catalog is not None and len(self.catalog):
            return self.authorizer.visible_doc_ids(user, self.catalog.acls())
        return {
            chunk.doc_id
            for chunk in self.store.fetch_all()
            if self.authorizer.authorize_metadata(user, chunk.metadata).allowed
        }

    def query_token_idf(self, tokens: set[str]) -> dict[str, float]:
        """Inverse-document-frequency weight for each query token.

        Used by the graph's relevance gate: a match on a rare, distinctive term
        ("litigation") should count far more than a match on a generic one
        ("review", "security"), otherwise every security document looks like an
        answer to every security question.
        """
        import math

        if self._bm25 is None or not self._bm25.total_docs:
            return {token: 1.0 for token in tokens}
        total = self._bm25.total_docs
        return {
            token: math.log(1 + total / (1 + self._bm25.document_frequency.get(token, 0)))
            for token in tokens
        }

    # ------------------------------------------------------------- retrieval
    def retrieve(self, query: str, user: User, *, k: int | None = None) -> RetrievalResult:
        """Retrieve the best authorized chunks for ``query`` as ``user``."""
        top_k = k or self.settings.retrieval_top_k
        candidates = max(top_k, self.settings.retrieval_candidates)
        timings: dict[str, float] = {}
        withheld: dict[str, WithheldDocument] = {}
        strategies: list[str] = []

        self.refresh()

        # --- layer 1: push-down ACL filter -------------------------------
        started = time.perf_counter()
        where = self.authorizer.chroma_where(user)
        vector_hits, filter_fallback = self.store.search(query, k=candidates, where=where)
        timings["vector_ms"] = (time.perf_counter() - started) * 1000
        strategies.append("vector")
        if filter_fallback:
            strategies.append("acl-filter-fallback")

        # --- layer 2: post-filter every returned chunk --------------------
        allowed_vector = self._split(vector_hits, withheld, user)

        # --- lexical ranking over the same corpus -------------------------
        lexical_hits: list[tuple[Chunk, float]] = []
        if self.settings.use_bm25 and self._bm25 is not None:
            started = time.perf_counter()
            for chunk_id, score in self._bm25.search(query, k=candidates * 2):
                chunk = self._chunk_map.get(chunk_id)
                if chunk is None:
                    continue
                decision = self.authorizer.authorize_metadata(user, chunk.metadata)
                if decision.allowed:
                    lexical_hits.append((chunk, score))
                else:
                    self._remember_withheld(withheld, chunk, decision)
            timings["bm25_ms"] = (time.perf_counter() - started) * 1000
            strategies.append("bm25")

        # --- fuse with Reciprocal Rank Fusion -----------------------------
        started = time.perf_counter()
        fused = self._fuse([allowed_vector, lexical_hits])
        # Sort by fused score only - tuples containing Chunk objects are not orderable.
        ordered = sorted(fused.items(), key=lambda item: item[1][1], reverse=True)
        timings["fuse_ms"] = (time.perf_counter() - started) * 1000

        selected: list[RetrievedChunk] = []
        seen_ids: set[str] = set()
        seen_text: set[str] = set()

        def consider(chunk_id: str) -> None:
            if chunk_id in seen_ids or len(selected) >= top_k:
                return
            entry = fused.get(chunk_id)
            if entry is None:
                return
            chunk, fused_score, source = entry
            if fused_score < self.settings.min_relevance_score:
                return
            if chunk.text[:160] in seen_text:
                return
            seen_ids.add(chunk_id)
            seen_text.add(chunk.text[:160])
            selected.append(RetrievedChunk(chunk=chunk, score=fused_score, source=source))

        # Reserve the head of each individual ranking: a document that is the top
        # lexical match must not be crowded out purely because it was missing
        # from the (noisier) semantic ranking. This is what keeps exact-key
        # lookups (employee IDs, cost centres, case numbers) working.
        for ranking in (allowed_vector, lexical_hits):
            if ranking:
                consider(ranking[0][0].chunk_id)
        for chunk_id, _entry in ordered:
            if len(selected) >= top_k:
                break
            consider(chunk_id)

        result = RetrievalResult(
            chunks=tuple(selected),
            withheld=tuple(sorted(withheld.values(), key=lambda w: w.classification, reverse=True)),
            candidates=len(vector_hits) + len(lexical_hits),
            authorized_chunks=len(allowed_vector) + len(lexical_hits),
            strategies=tuple(dict.fromkeys(strategies)),
            filter_fallback=filter_fallback,
            timings_ms=timings,
        )
        self._audit_retrieval(query, user, result)
        return result

    # ------------------------------------------------------------- internals
    def _split(
        self,
        hits: list[tuple[Chunk, float]],
        withheld: dict[str, WithheldDocument],
        user: User,
    ) -> list[tuple[Chunk, float]]:
        """Layer 2: keep only chunks the principal may read."""
        allowed: list[tuple[Chunk, float]] = []
        for chunk, score in hits:
            decision = self.authorizer.authorize_metadata(user, chunk.metadata)
            if decision.allowed:
                allowed.append((chunk, score))
            else:
                self._remember_withheld(withheld, chunk, decision)
        return allowed

    @staticmethod
    def _remember_withheld(
        withheld: dict[str, WithheldDocument], chunk: Chunk, decision: AccessDecision
    ) -> None:
        if chunk.doc_id in withheld:
            return
        withheld[chunk.doc_id] = WithheldDocument(
            doc_id=chunk.doc_id,
            title=chunk.doc_title,
            classification=str(chunk.metadata.get("classification", "internal")),
            rule=decision.rule,
            reason=decision.reason,
        )

    def _fuse(
        self, rankings: list[list[tuple[Chunk, float]]]
    ) -> dict[str, tuple[Chunk, float, str]]:
        """Reciprocal Rank Fusion over multiple rankings (+ normalisation)."""
        raw: dict[str, float] = {}
        chunks: dict[str, Chunk] = {}
        origin: dict[str, str] = {}
        for label, ranking in zip(("vector", "bm25"), rankings, strict=False):
            for rank, (chunk, _score) in enumerate(ranking, start=1):
                raw[chunk.chunk_id] = raw.get(chunk.chunk_id, 0.0) + 1.0 / (
                    self.settings.rrf_k + rank
                )
                chunks[chunk.chunk_id] = chunk
                origin.setdefault(chunk.chunk_id, label)

        normalized = normalize_rrf(raw)
        fused: dict[str, tuple[Chunk, float, str]] = {}
        for chunk_id, score in normalized.items():
            in_vector = any(c.chunk_id == chunk_id for c, _ in rankings[0]) if rankings else False
            in_bm25 = (
                any(c.chunk_id == chunk_id for c, _ in rankings[1]) if len(rankings) > 1 else False
            )
            label = "vector+bm25" if (in_vector and in_bm25) else origin.get(chunk_id, "fused")
            fused[chunk_id] = (chunks[chunk_id], score, label)
        return fused

    def _audit_retrieval(self, query: str, user: User, result: RetrievalResult) -> None:
        if self.audit is None:
            return
        try:
            self.audit.record(
                actor=user.username,
                action="retrieval.completed",
                outcome="success",
                severity="info",
                details={
                    "query_hash": _query_fingerprint(query),
                    "returned_chunks": len(result.chunks),
                    "documents": sorted({c.doc_id for c in result.chunks}),
                    "strategies": list(result.strategies),
                    "filter_fallback": result.filter_fallback,
                },
            )
            protected = {Classification.CONFIDENTIAL.value, Classification.RESTRICTED.value}
            for index, doc in enumerate(result.withheld):
                if index >= MAX_WITHHELD_AUDIT_EVENTS:
                    break
                self.audit.record(
                    actor=user.username,
                    action="retrieval.denied",
                    outcome="denied",
                    severity="warning" if doc.classification in protected else "info",
                    details={
                        "doc_id": doc.doc_id,
                        "classification": doc.classification,
                        "rule": doc.rule,
                        "reason": doc.reason,
                        "query_hash": _query_fingerprint(query),
                    },
                )
        except Exception:  # pragma: no cover - audit must never break retrieval
            logger.exception("Audit write failed during retrieval")


def _query_fingerprint(query: str) -> str:
    """Store a hash rather than the raw question: the log itself must not leak."""
    import hashlib

    return hashlib.sha256(query.encode("utf-8")).hexdigest()[:16]


__all__ = ["EnterpriseRetriever", "MAX_WITHHELD_AUDIT_EVENTS"]
