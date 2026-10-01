"""Chat endpoints: synchronous answers and a streaming guardrail trace."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from enterprise_rag.api.deps import ContextDep, CurrentUser
from enterprise_rag.graph.state import QueryResult
from enterprise_rag.security.rate_limit import RateLimitDecision

router = APIRouter(prefix="/api/chat", tags=["chat"])


class QueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=20000, examples=["What is our leave policy?"])
    session_id: str | None = Field(default=None, max_length=64)


def _rate_limit_headers(decision: RateLimitDecision) -> dict[str, str]:
    headers = {
        "X-RateLimit-Limit": str(decision.limit),
        "X-RateLimit-Remaining": str(max(0, decision.remaining)),
        "X-RateLimit-Used-Today": str(decision.used_today),
    }
    if not decision.allowed:
        headers["Retry-After"] = str(decision.retry_after)
    return headers


def _enforce_quota(context, key: str, label: str) -> dict[str, str]:
    decision = context.rate_limiter.consume(key)
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "message": "Request limit reached. Try again later.",
                "quota": label,
                "scope": decision.scope,  # per_minute | per_day
                "limit": decision.limit,
                "retry_after_seconds": decision.retry_after,
            },
            headers=_rate_limit_headers(decision),
        )
    return _rate_limit_headers(decision)


@router.post("/query", summary="Ask a question (RBAC + guardrails applied)")
def chat_query(payload: QueryRequest, context: ContextDep, user: CurrentUser) -> JSONResponse:
    headers = _enforce_quota(context, user.username, "queries")
    result: QueryResult = context.graph.run(user, payload.query, session_id=payload.session_id)
    body = result.as_dict()
    body["rate_limit"] = {
        "limit": context.settings.rate_limit_requests_per_minute,
        "remaining": int(headers.get("X-RateLimit-Remaining", 0)),
        "used_today": int(headers.get("X-RateLimit-Used-Today", 0)),
    }
    return JSONResponse(content=body, headers=headers)


@router.post("/stream", summary="Stream node-by-node guardrail trace (SSE)")
def chat_stream(payload: QueryRequest, context: ContextDep, user: CurrentUser) -> StreamingResponse:
    headers = _enforce_quota(context, user.username, "queries")

    def events():
        for node, update in context.graph.stream(
            user, payload.query, session_id=payload.session_id
        ):
            if node == "result":
                payload_obj = {"event": "result", "data": update.as_dict()}
            else:
                payload_obj = {
                    "event": "node",
                    "node": node,
                    "data": {
                        "stage": update.get("stage", node),
                        "trace": (update.get("trace") or [{}])[-1],
                        "action": update.get("action"),
                        "reason_code": update.get("reason_code"),
                    },
                }
            yield f"data: {json.dumps(payload_obj, default=str)}\n\n"
        yield f"data: {json.dumps({'event': 'end', 'headers': headers}, default=str)}\n\n"

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", **headers},
    )
