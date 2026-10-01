# Enterprise RAG (RBAC + Guardrails) — container image.
#
# Runs fully offline by default: no API key, no model download.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

# Dependency layer (cached unless requirements change)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml README.md ./
COPY src ./src
COPY frontend ./frontend

# Pre-generate the synthetic corpus so the container starts ready to demo.
# Documents are regenerated only if the corpus is missing, so a mounted
# ./data directory keeps whatever you indexed yourself.
RUN python -m enterprise_rag.cli seed || true

RUN mkdir -p /app/data

ENV DATA_DIR=/app/data \
    APP_ENV=production \
    HOST=0.0.0.0 \
    PORT=8000

# SECRET_KEY is deliberately NOT baked in: supply it through `docker compose`, an
# orchestrator secret, or `docker run -e SECRET_KEY=...`. With APP_ENV=production
# the application refuses to start unless a non-default key is present.

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["sh", "-c", "uvicorn enterprise_rag.api.main:app --host 0.0.0.0 --port ${PORT}"]