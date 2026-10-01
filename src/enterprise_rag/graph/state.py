"""Graph state and the response object returned to callers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TypedDict

from enterprise_rag.models import RetrievalResult, RetrievedChunk
from enterprise_rag.security.identity import User

# Terminal actions the graph can end on.
ACTION_ANSWER = "answer"
ACTION_REFUSE = "refuse"
ACTION_BLOCKED = "blocked"
ACTION_INSUFFICIENT = "insufficient_evidence"


class QueryState(TypedDict, total=False):
    """State threaded through the LangGraph workflow.

    Live objects (``User``, ``RetrievedChunk``) are carried for convenience -
    this graph runs without a checkpointer, so no serialisation is required.
    """

    # request bookkeeping
    request_id: str
    session_id: str
    stage: str
    trace: list[dict[str, Any]]
    started_at: float

    # principal + query
    user: User
    query: str
    sanitized_query: str

    # input guardrail output
    input_report: dict[str, Any]
    risk_score: int
    topics: list[str]
    missing_grants: list[str]

    # retrieval
    retrieval: RetrievalResult
    contexts: list[RetrievedChunk]
    retrieval_report: dict[str, Any]
    strict: bool

    # generation
    llm_text: str
    llm_report: dict[str, Any]
    attempts: int

    # terminal
    action: str
    answer: str
    reason_code: str
    citations: list[dict[str, Any]]
    output_report: dict[str, Any]
    error: str


@dataclass(frozen=True, slots=True)
class QueryResult:
    """The graph's final answer plus the evidence about how it was produced."""

    request_id: str
    session_id: str
    username: str
    query: str
    action: str
    answer: str
    reason_code: str = "OK"
    citations: tuple[dict[str, Any], ...] = ()
    documents: tuple[dict[str, Any], ...] = ()
    withheld: tuple[dict[str, Any], ...] = ()
    withheld_count: int = 0
    guardrails: dict[str, Any] = field(default_factory=dict)
    retrieval: dict[str, Any] = field(default_factory=dict)
    llm: dict[str, Any] = field(default_factory=dict)
    trace: tuple[dict[str, Any], ...] = ()
    latency_ms: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "username": self.username,
            "query": self.query,
            "action": self.action,
            "answer": self.answer,
            "reason_code": self.reason_code,
            "citations": list(self.citations),
            "documents": list(self.documents),
            "withheld": list(self.withheld),
            "withheld_count": self.withheld_count,
            "guardrails": self.guardrails,
            "retrieval": self.retrieval,
            "llm": self.llm,
            "trace": list(self.trace),
            "latency_ms": round(self.latency_ms, 2),
        }


__all__ = [
    "ACTION_ANSWER",
    "ACTION_BLOCKED",
    "ACTION_INSUFFICIENT",
    "ACTION_REFUSE",
    "QueryResult",
    "QueryState",
]
