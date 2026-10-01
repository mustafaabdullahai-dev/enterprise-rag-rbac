"""FastAPI entrypoint: lifespan wiring, routers, CORS and the demo console."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from enterprise_rag import __version__
from enterprise_rag.api.routes import admin, auth, chat, evaluation, health
from enterprise_rag.config import get_settings
from enterprise_rag.context import AppContext
from enterprise_rag.security.auth import AuthError

logger = logging.getLogger(__name__)


def _cors_origins(settings) -> list[str]:
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    return origins or ["http://localhost:5173"]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    # Tests may inject a fully built context (isolated temp dirs, no re-ingest).
    injected: AppContext | None = getattr(app.state, "injected_context", None)
    context = injected or AppContext.build(settings)
    app.state.context = context
    report = context.ensure_ready()
    context.audit.record(
        actor="system",
        action="system.startup",
        outcome="success",
        severity="info",
        details={
            "version": __version__,
            "environment": settings.app_env,
            "llm_backend": context.llm.backend,
            "embedding_backend": settings.embedding_backend,
            "documents": len(context.catalog),
            "chunks": context.store.count(),
            "auto_ingested": bool(report),
        },
    )
    yield
    context.audit.record(
        actor="system",
        action="system.shutdown",
        outcome="success",
        severity="info",
        details={},
    )


def create_app(context: AppContext | None = None) -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title="Enterprise RAG (RBAC + Guardrails)",
        description=(
            "Corporate knowledge assistant with role-based access control, prompt-injection "
            "and data-leakage guardrails, a tamper-evident audit trail, and Ragas-based "
            "answer evaluation."
        ),
        version=__version__,
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(settings),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.state.injected_context = context

    @application.exception_handler(AuthError)
    async def auth_error_handler(_request: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})

    application.include_router(health.router)
    application.include_router(auth.router)
    application.include_router(chat.router)
    application.include_router(admin.router)
    application.include_router(evaluation.router)

    index = Path(settings.frontend_path) / "index.html"
    if index.exists():

        @application.get("/", include_in_schema=False)
        async def console() -> FileResponse:  # pragma: no cover - trivial route
            return FileResponse(index)

    return application


app = create_app()

__all__ = ["app", "create_app"]
