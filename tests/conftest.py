"""Shared fixtures.

The suite builds the corpus once (session scope), ingests it into a temporary
ChromaDB, and shares one ``AppContext`` across tests so the expensive work
happens exactly once. API tests inject the same context into the FastAPI app,
which means the HTTP tests exercise the identical graph the unit tests do.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:  # pragma: no cover - path bootstrap
    sys.path.insert(0, str(ROOT / "src"))
if str(ROOT) not in sys.path:  # pragma: no cover - lets tests import scripts.*
    sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def corpus_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Synthetic corporate corpus (generated once per test session)."""
    from enterprise_rag.demo_corpus import build_corpus

    root = tmp_path_factory.mktemp("corpus")
    build_corpus(root, force=True)
    return root


@pytest.fixture(scope="session")
def settings(tmp_path_factory: pytest.TempPathFactory, corpus_dir: Path):
    """Isolated settings: temp data dir, real corpus, limits relaxed."""
    from enterprise_rag.config import Settings

    data_dir = tmp_path_factory.mktemp("data")
    return Settings(
        data_dir=data_dir,
        corpus_dir=corpus_dir,
        app_env="test",
        embedding_cache_enabled=False,
        auto_ingest=False,
        # Rate limiting is exercised in its own test with a dedicated limiter.
        rate_limit_requests_per_minute=1000,
        rate_limit_queries_per_day=100000,
    )


@pytest.fixture(scope="session")
def context(settings):
    """Fully built application context with an ingested index."""
    from enterprise_rag.context import AppContext

    ctx = AppContext.build(settings)
    report = ctx.pipeline.run(reset=True)
    assert not report.errors, report.errors
    ctx.refresh_index()
    return ctx


@pytest.fixture(scope="session")
def app_client(context):
    """FastAPI TestClient wired to the shared context (runs the lifespan)."""
    from fastapi.testclient import TestClient

    from enterprise_rag.api.main import create_app

    with TestClient(create_app(context)) as client:
        yield client


@pytest.fixture()
def user_store(context):
    return context.user_store


@pytest.fixture()
def authorizer():
    from enterprise_rag.security.acl import Authorizer

    return Authorizer()
