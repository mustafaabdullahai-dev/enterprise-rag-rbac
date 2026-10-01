"""The LangGraph workflow.

    START
      |
  guard_input ──(block/refuse)──────────────┐
      | allow                                │
    retrieve                                 │
      |                                      │
    grade ──(no relevant context)────────────┤
      | ok                                   │
   generate ──(retry, max 1)──┐              │
      |                       │              │
   verify_citations ──────────┘              │
      | verified                             │
  output_guard ──(leak / ungrounded)─────────┤
      | released                             │
   finalize ────────────────────────────────>END

Every node that can terminate writes ``action`` and ``reason_code``; ``finalize``
then records the outcome in the audit log. Nodes only ever *narrow* what is
returned - the input guard cannot widen access, retrieval cannot bypass the ACL,
the output guard cannot un-block a leak - so a compromise in one layer is not
enough to disclose restricted data.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

from langgraph.graph import END, START, StateGraph

from enterprise_rag.audit.log import AuditLog
from enterprise_rag.config import Settings
from enterprise_rag.graph.state import (
    ACTION_ANSWER,
    ACTION_BLOCKED,
    ACTION_INSUFFICIENT,
    ACTION_REFUSE,
    QueryResult,
    QueryState,
)
from enterprise_rag.guardrails.input_guard import InputGuard
from enterprise_rag.guardrails.output_guard import CITATION_RE, OutputGuard
from enterprise_rag.guardrails.policies import (
    REFUSAL_INSUFFICIENT_EVIDENCE,
)
from enterprise_rag.ingestion.catalog import DocumentCatalog
from enterprise_rag.llm.prompts import build_prompt
from enterprise_rag.llm.provider import EnterpriseLLM
from enterprise_rag.models import RetrievedChunk
from enterprise_rag.retrieval.retriever import EnterpriseRetriever
from enterprise_rag.security.identity import User
from enterprise_rag.textutil import content_tokens

logger = logging.getLogger(__name__)

RETRY_SUFFIX = (
    "\n\nIMPORTANT: your previous attempt did not include citations. Every factual "
    "sentence MUST end with [doc_id#chunk_id] taken from the context headers above.\n"
)

# Relevance gate for the context. A chunk qualifies when it matches either:
#   * at least two of the question's content words, or
#   * one *rare* content word (low document frequency in this corpus).
#
# The second clause matters: "Which litigation matters are open?" shares only
# one term with a register titled "Pending Litigation Register", and that single
# term is rare, which is strong evidence. Without it, the same question would
# either be answered from an unrelated document (matching the generic word
# "review") or refused because three filler words ("currently", "open") appear
# nowhere in the corpus.
MIN_MATCHED_TOKENS = 2
RARE_TOKEN_IDF = 2.5


@dataclass
class GraphDeps:
    """Collaborators the graph needs (injected so tests can substitute fakes)."""

    settings: Settings
    retriever: EnterpriseRetriever
    llm: EnterpriseLLM
    input_guard: InputGuard
    output_guard: OutputGuard
    audit: AuditLog | None = None
    catalog: DocumentCatalog | None = None


class QueryGraph:
    """Builds and runs the RBAC-aware RAG workflow."""

    def __init__(self, deps: GraphDeps) -> None:
        self.deps = deps
        self.settings = deps.settings
        self.retriever = deps.retriever
        self.llm = deps.llm
        self.input_guard = deps.input_guard
        self.output_guard = deps.output_guard
        self.audit = deps.audit
        self.catalog = deps.catalog
        self._llm_lock = threading.Lock()
        self.graph = self._build()

    # ---------------------------------------------------------------- build
    def _build(self) -> Any:
        builder = StateGraph(QueryState)
        builder.add_node("guard_input", self.guard_input)
        builder.add_node("retrieve", self.retrieve)
        builder.add_node("grade", self.grade)
        builder.add_node("generate", self.generate)
        builder.add_node("verify_citations", self.verify_citations)
        builder.add_node("output_guard", self.output_guard_node)
        builder.add_node("finalize", self.finalize)

        builder.add_edge(START, "guard_input")
        builder.add_conditional_edges(
            "guard_input",
            self._route_after_input,
            {"retrieve": "retrieve", "finalize": "finalize"},
        )
        builder.add_edge("retrieve", "grade")
        builder.add_conditional_edges(
            "grade",
            self._route_after_grade,
            {"generate": "generate", "finalize": "finalize"},
        )
        builder.add_edge("generate", "verify_citations")
        builder.add_conditional_edges(
            "verify_citations",
            self._route_after_verify,
            {"generate": "generate", "output_guard": "output_guard", "finalize": "finalize"},
        )
        builder.add_conditional_edges(
            "output_guard",
            self._route_after_output,
            {"finalize": "finalize"},
        )
        builder.add_edge("finalize", END)
        return builder.compile()

    # ---------------------------------------------------------------- nodes
    def guard_input(self, state: QueryState) -> QueryState:
        """Screen the request before anything is retrieved or sent to a model."""
        started = time.perf_counter()
        user = state["user"]
        verdict = self.input_guard.evaluate(state["query"], user)

        update: QueryState = {
            # Snippets stay in the response trace (the requester's own input) but
            # are stripped before the audit write in _record().
            "input_report": verdict.as_dict(include_snippets=True),
            "risk_score": verdict.risk_score,
            "sanitized_query": verdict.sanitized_query or state["query"],
            "topics": list(verdict.topics),
            "missing_grants": list(verdict.missing_grants),
            "attempts": 0,
            "citations": [],
        }
        detail = {"risk": verdict.risk_score, "reason": verdict.reason_code}

        if verdict.action == "block":
            update.update(
                action=ACTION_BLOCKED, answer=verdict.refusal, reason_code=verdict.reason_code
            )
            self._record(user, "chat.blocked", "blocked", "critical", state, verdict.as_dict())
        elif verdict.action == "refuse":
            update.update(
                action=ACTION_REFUSE, answer=verdict.refusal, reason_code=verdict.reason_code
            )
            self._record(user, "chat.refused", "denied", "warning", state, verdict.as_dict())
        else:
            self._record(
                user, "chat.received", "success", "info", state, {"risk": verdict.risk_score}
            )

        return self._traced(state, "guard_input", started, update, detail=detail)

    def retrieve(self, state: QueryState) -> QueryState:
        """ACL-filtered hybrid retrieval (see retrieval.EnterpriseRetriever)."""
        started = time.perf_counter()
        user = state["user"]
        result = self.retriever.retrieve(state["sanitized_query"], user)

        contexts = self._apply_context_budget(list(result.chunks))
        report = result.as_dict()
        report["used_chunks"] = len(contexts)
        update: QueryState = {
            "retrieval": result,
            "contexts": contexts,
            "retrieval_report": report,
        }

        if not contexts:
            update.update(
                action=ACTION_INSUFFICIENT,
                answer=REFUSAL_INSUFFICIENT_EVIDENCE,
                reason_code="NO_AUTHORIZED_CONTEXT",
            )
        return self._traced(
            state,
            "retrieve",
            started,
            update,
            detail={
                "chunks": len(contexts),
                "withheld": len(result.withheld),
                "strategies": list(result.strategies),
            },
        )

    def grade(self, state: QueryState) -> QueryState:
        """Relevance gate: does *some* retrieved source address the question?

        Evidence rule (see ``MIN_MATCHED_TOKENS`` / ``RARE_TOKEN_IDF``): a source
        qualifies by matching two content words, or by matching one rare word.
        """
        started = time.perf_counter()
        if state.get("action"):
            return self._traced(state, "grade", started, {}, detail={"skipped": True})

        contexts: list[RetrievedChunk] = list(state.get("contexts") or [])
        query_tokens = content_tokens(state.get("sanitized_query", ""))
        weights = self.retriever.query_token_idf(query_tokens)
        total = sum(weights.values()) or 1.0

        best_coverage, best_matches, best_idf, best_doc = 0.0, 0, 0.0, ""
        for chunk in contexts:
            chunk_tokens = content_tokens(chunk.text)
            matched = [token for token in query_tokens if token in chunk_tokens]
            coverage = sum(weights[token] for token in matched) / total
            strongest = max((weights[token] for token in matched), default=0.0)
            if len(matched) >= best_matches or (
                len(matched) == best_matches and coverage > best_coverage
            ):
                best_coverage, best_matches, best_idf, best_doc = (
                    coverage,
                    len(matched),
                    strongest,
                    chunk.doc_id,
                )

        qualified = (best_matches >= MIN_MATCHED_TOKENS or best_idf >= RARE_TOKEN_IDF) and bool(
            contexts
        )

        update: QueryState = {"strict": False}
        if not qualified:
            update.update(
                action=ACTION_INSUFFICIENT,
                answer=REFUSAL_INSUFFICIENT_EVIDENCE,
                reason_code="LOW_CONTEXT_RELEVANCE",
            )
        return self._traced(
            state,
            "grade",
            started,
            update,
            detail={
                "coverage": round(best_coverage, 3),
                "matched_terms": best_matches,
                "strongest_idf": round(best_idf, 2),
                "best_doc": best_doc,
            },
        )

    def generate(self, state: QueryState) -> QueryState:
        """Call the model with the fenced, authorised context."""
        started = time.perf_counter()
        if state.get("action"):
            return self._traced(state, "generate", started, {}, detail={"skipped": True})

        contexts: list[RetrievedChunk] = list(state.get("contexts") or [])
        prompt = build_prompt(state.get("sanitized_query", ""), contexts)
        if state.get("strict"):
            prompt += RETRY_SUFFIX

        attempts = int(state.get("attempts") or 0) + 1
        text, report = self._invoke_llm(prompt)
        update: QueryState = {
            "llm_text": text,
            "llm_report": report,
            "strict": False,
            "attempts": attempts,
        }

        if not text.strip() or text.strip().upper().startswith("INSUFFICIENT_EVIDENCE"):
            update.update(
                action=ACTION_INSUFFICIENT,
                answer=REFUSAL_INSUFFICIENT_EVIDENCE,
                reason_code="MODEL_INSUFFICIENT_EVIDENCE",
            )
        return self._traced(
            state,
            "generate",
            started,
            update,
            detail={"attempt": attempts, "chars": len(text), "backend": report.get("backend")},
        )

    def verify_citations(self, state: QueryState) -> QueryState:
        """Cheap pre-check: an answer with no citation is not releaseable."""
        started = time.perf_counter()
        if state.get("action"):
            return self._traced(state, "verify_citations", started, {}, detail={"skipped": True})

        text = state.get("llm_text", "")
        found = list(dict.fromkeys(CITATION_RE.findall(text)))
        update: QueryState = {
            "citations": [{"doc_id": doc, "chunk_id": chunk} for doc, chunk in found]
        }

        if not found:
            attempts = int(state.get("attempts") or 0)
            if attempts <= self.settings.max_graph_retries:
                update.update(strict=True, reason_code="RETRY_MISSING_CITATIONS")
            else:
                update.update(
                    action=ACTION_INSUFFICIENT,
                    answer=REFUSAL_INSUFFICIENT_EVIDENCE,
                    reason_code="NO_CITATIONS",
                )
        return self._traced(
            state,
            "verify_citations",
            started,
            update,
            detail={"citations": len(found), "retry": bool(update.get("strict"))},
        )

    def output_guard_node(self, state: QueryState) -> QueryState:
        """Citation verification, canary tripwire, grounding and PII masking."""
        started = time.perf_counter()
        if state.get("action"):
            return self._traced(state, "output_guard", started, {}, detail={"skipped": True})

        user = state["user"]
        contexts: list[RetrievedChunk] = list(state.get("contexts") or [])
        verdict = self.output_guard.inspect(
            answer=state.get("llm_text", ""),
            contexts=contexts,
            user=user,
            authorized_doc_ids=self.retriever.authorized_doc_ids(user),
            canary_registry=self.catalog.canaries() if self.catalog else {},
        )

        update: QueryState = {
            "output_report": verdict.as_dict(include_snippets=True),
            "citations": [c.as_dict() for c in verdict.citations],
        }
        blocked_codes = {"SECRET_IN_OUTPUT", "UNAUTHORIZED_CITATION", "CANARY_LEAK"}

        if verdict.allowed:
            update.update(
                action=ACTION_ANSWER, answer=verdict.answer, reason_code=verdict.reason_code
            )
            if verdict.pii_redacted:
                self._record(
                    user, "chat.answer_redacted", "success", "warning", state, verdict.as_dict()
                )
            else:
                self._record(user, "chat.answered", "success", "info", state, verdict.as_dict())
        else:
            update.update(
                action=ACTION_BLOCKED
                if verdict.reason_code in blocked_codes
                else ACTION_INSUFFICIENT,
                answer=verdict.answer or REFUSAL_INSUFFICIENT_EVIDENCE,
                reason_code=verdict.reason_code,
            )
            self._record(
                user, "chat.output_blocked", "blocked", "critical", state, verdict.as_dict()
            )

        return self._traced(
            state,
            "output_guard",
            started,
            update,
            detail={"action": verdict.action, "reason": verdict.reason_code},
        )

    def finalize(self, state: QueryState) -> QueryState:
        """Guarantee a terminal action/answer and close the audit trail."""
        started = time.perf_counter()
        action = state.get("action") or ACTION_INSUFFICIENT
        answer = state.get("answer") or REFUSAL_INSUFFICIENT_EVIDENCE
        update: QueryState = {
            "action": action,
            "answer": answer,
            "reason_code": state.get("reason_code", "OK"),
        }
        if action != ACTION_ANSWER:
            # A blocked/refused response must not present the citations of the
            # answer we decided *not* to release; they stay in the output report.
            update["citations"] = []
        user = state.get("user")
        if user is not None:
            self._record(
                user,
                "chat.completed",
                action,
                "info",
                state,
                {"action": action, "reason_code": update["reason_code"]},
            )
        return self._traced(state, "finalize", started, update, detail={"action": action})

    # -------------------------------------------------------------- routing
    def _route_after_input(self, state: QueryState) -> str:
        return "finalize" if state.get("action") else "retrieve"

    def _route_after_grade(self, state: QueryState) -> str:
        return "finalize" if state.get("action") else "generate"

    def _route_after_verify(self, state: QueryState) -> str:
        if state.get("action"):
            return "finalize"
        return "generate" if state.get("strict") else "output_guard"

    def _route_after_output(self, state: QueryState) -> str:  # noqa: ARG002 - fixed route
        return "finalize"

    # ------------------------------------------------------------------ run
    def run(
        self,
        user: User,
        query: str,
        *,
        session_id: str | None = None,
        request_id: str | None = None,
    ) -> QueryResult:
        """Execute the workflow once and return a structured result."""
        started = time.perf_counter()
        final = self.graph.invoke(
            self._initial_state(user, query, session_id=session_id, request_id=request_id),
            config={"recursion_limit": 24},
        )
        return self._to_result(final, latency_ms=(time.perf_counter() - started) * 1000)

    def stream(self, user: User, query: str, *, session_id: str | None = None):
        """Yield ``(node, update)`` events, then ``("result", QueryResult)``.

        Used by the SSE endpoint so the UI can show the guardrail trace live.
        """
        started = time.perf_counter()
        merged: dict[str, Any] = dict(
            self._initial_state(user, query, session_id=session_id, request_id=None)
        )
        for event in self.graph.stream(
            merged, config={"recursion_limit": 24}, stream_mode="updates"
        ):
            for node, update in event.items():
                merged.update(update or {})
                yield node, update or {}
        yield "result", self._to_result(merged, latency_ms=(time.perf_counter() - started) * 1000)

    # --------------------------------------------------------------- helpers
    def _initial_state(
        self, user: User, query: str, *, session_id: str | None, request_id: str | None
    ) -> QueryState:
        return QueryState(
            request_id=request_id or uuid.uuid4().hex[:12],
            session_id=session_id or f"sess-{uuid.uuid4().hex[:8]}",
            user=user,
            query=query,
            trace=[],
            started_at=time.perf_counter(),
            stage="start",
        )

    @staticmethod
    def _traced(
        state: QueryState,
        node: str,
        started: float,
        update: dict[str, Any],
        *,
        detail: dict[str, Any] | None = None,
    ) -> QueryState:
        trace = list(state.get("trace") or [])
        trace.append(
            {
                "node": node,
                "ms": round((time.perf_counter() - started) * 1000, 2),
                "detail": detail or {},
            }
        )
        merged: dict[str, Any] = dict(update)
        merged["trace"] = trace
        merged["stage"] = node
        return merged  # type: ignore[return-value]

    def _invoke_llm(self, prompt: str) -> tuple[str, dict[str, Any]]:
        """Invoke the LangChain LLM runnable and capture provenance."""
        error: str | None = None
        text = ""
        with self._llm_lock:
            try:
                text = str(self.llm.invoke(prompt) or "")
            except Exception as exc:  # pragma: no cover - provider outage
                error = f"{type(exc).__name__}: {exc}"
                logger.warning("LLM invocation failed: %s", error)
            result = self.llm.last_result
        report: dict[str, Any] = {
            "backend": getattr(result, "backend", self.llm.backend),
            "model": getattr(result, "model", self.llm.model),
            "latency_ms": round(getattr(result, "latency_ms", 0.0), 2),
            "refused": bool(getattr(result, "refused", False)),
            "usage": getattr(result, "usage", None),
        }
        if error:
            report["error"] = error
        return text, report

    def _apply_context_budget(self, chunks: list[RetrievedChunk]) -> list[RetrievedChunk]:
        budget = self.settings.max_context_chars
        kept: list[RetrievedChunk] = []
        used = 0
        for chunk in chunks:
            size = len(chunk.text)
            if kept and used + size > budget:
                break
            kept.append(chunk)
            used += size
        return kept

    def _record(
        self,
        user: User,
        action: str,
        outcome: str,
        severity: str,
        state: QueryState,
        details: dict[str, Any],
    ) -> None:
        """Write an audit record that never contains the raw question text."""
        if self.audit is None:
            return
        try:
            self.audit.record(
                actor=user.username,
                action=action,
                outcome=outcome,
                severity=severity,
                details={
                    "request_id": state.get("request_id"),
                    "session_id": state.get("session_id"),
                    "query_hash": _fingerprint(state.get("query", "")),
                    **details,
                },
            )
        except Exception:  # pragma: no cover - audit must never break answering
            logger.exception("Audit write failed in %s", action)

    def _to_result(self, state: QueryState, *, latency_ms: float) -> QueryResult:
        user: User = state["user"]
        retrieval = state.get("retrieval")
        withheld = list(retrieval.withheld) if retrieval is not None else []
        return QueryResult(
            request_id=str(state.get("request_id", "")),
            session_id=str(state.get("session_id", "")),
            username=user.username,
            query=str(state.get("sanitized_query") or state.get("query", "")),
            action=str(state.get("action") or ACTION_INSUFFICIENT),
            answer=str(state.get("answer") or REFUSAL_INSUFFICIENT_EVIDENCE),
            reason_code=str(state.get("reason_code", "OK")),
            citations=tuple(state.get("citations") or []),
            documents=tuple(chunk.as_dict() for chunk in (state.get("contexts") or [])),
            withheld=tuple(w.as_dict() for w in withheld)
            if self.settings.expose_withheld_count
            else (),
            withheld_count=len(withheld),
            guardrails={
                "input": state.get("input_report", {}),
                "output": state.get("output_report", {}),
                "risk_score": state.get("risk_score", 0),
                "topics": state.get("topics", []),
                "missing_grants": state.get("missing_grants", []),
            },
            retrieval=state.get("retrieval_report", {}),
            llm=state.get("llm_report", {}),
            trace=tuple(state.get("trace") or []),
            latency_ms=latency_ms,
        )


def _fingerprint(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


__all__ = ["GraphDeps", "QueryGraph", "RETRY_SUFFIX"]
