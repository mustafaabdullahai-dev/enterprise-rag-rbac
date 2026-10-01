"""Health and capability discovery (no authentication required)."""

from __future__ import annotations

from fastapi import APIRouter

from enterprise_rag import __version__
from enterprise_rag.api.deps import ContextDep

router = APIRouter(tags=["system"])


@router.get("/api/health", summary="Liveness/readiness probe")
def health(context: ContextDep) -> dict[str, object]:
    context.ensure_ready()
    ok, message, records = context.audit.verify()
    return {
        "status": "ok",
        "version": __version__,
        "index": {
            "documents": len(context.catalog),
            "chunks": context.store.count(),
            "by_classification": context.catalog.by_classification(),
        },
        "backends": {
            "llm": context.llm.backend,
            "embedding": context.settings.embedding_backend,
            "vector_store": "chromadb",
        },
        "audit": {"records": records, "chain_valid": ok, "message": message},
    }


@router.get("/api/about", summary="Limits, capabilities and demo accounts")
def about(context: ContextDep) -> dict[str, object]:
    settings = context.settings
    return {
        "app": settings.app_name,
        "environment": settings.app_env,
        "capabilities": {
            "formats": ["pdf", "csv", "tsv", "xlsx", "docx", "markdown", "text", "json"],
            "guardrails": {
                "input": [
                    "prompt_injection",
                    "jailbreak",
                    "system_prompt_extraction",
                    "pii_masking",
                    "secret_paste",
                    "exfiltration",
                    "privileged_topic_probe",
                ],
                "output": [
                    "citation_verification",
                    "canary_tripwire",
                    "grounding_check",
                    "pii_masking",
                    "secret_scan",
                ],
            },
            "evaluation": ["ragas", "offline_faithfulness", "answer_relevance", "red_team"],
        },
        "limits": {
            "max_query_chars": settings.max_query_chars,
            "requests_per_minute": settings.rate_limit_requests_per_minute,
            "queries_per_day": settings.rate_limit_queries_per_day,
            "retrieval_top_k": settings.retrieval_top_k,
            "max_context_chars": settings.max_context_chars,
            "token_ttl_minutes": settings.token_ttl_minutes,
        },
        "demo_users": context.login_hint(),
    }
