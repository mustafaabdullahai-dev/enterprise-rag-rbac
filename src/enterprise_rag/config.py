"""Central configuration.

Every knob is environment-overridable (see ``.env.example``). Paths are resolved
relative to the project root so the app behaves the same from any CWD.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]

EmbeddingBackend = Literal["hash", "openai"]
LLMBackend = Literal["extractive", "openai"]


class Settings(BaseSettings):
    """Application settings loaded from environment variables / ``.env``."""

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------ app
    app_name: str = "Enterprise RAG (RBAC + Guardrails)"
    app_env: Literal["development", "production", "test"] = "development"
    log_level: str = "INFO"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    expose_demo_users: bool = True

    # ------------------------------------------------------------- security
    secret_key: str = "dev-only-insecure-key-change-me"
    token_ttl_minutes: int = 120
    # Roles allowed to manage the corpus / read the compliance console.
    admin_roles: str = "platform_admin"
    compliance_roles: str = "compliance_officer,platform_admin"

    # ---------------------------------------------------------------- paths
    data_dir: Path = Path("data")
    corpus_dir: Path | None = None
    chroma_dir: Path | None = None
    web_dir: Path | None = None
    audit_filename: str = "audit.jsonl"
    catalog_filename: str = "catalog.json"
    users_filename: str = "users.json"
    eval_dirname: str = "eval_reports"
    chroma_collection: str = "corporate_knowledge"

    # ------------------------------------------------------------ ingestion
    auto_ingest: bool = True
    chunk_size: int = 900
    chunk_overlap: int = 120
    min_chunk_chars: int = 40
    canary_prefix: str = "CANARY-"
    # Embed the document canary token in every chunk of confidential/restricted
    # documents, so a leak can be detected (not just prevented).
    embed_canary: bool = True

    # ------------------------------------------------------------ embedding
    embedding_backend: EmbeddingBackend = "hash"
    embedding_dim: int = 384
    embedding_model: str = "text-embedding-3-small"
    embedding_base_url: str = "https://api.openai.com/v1"
    embedding_api_key: str = ""
    embedding_batch_size: int = 64
    embedding_cache_enabled: bool = True

    # ------------------------------------------------------------------ llm
    llm_backend: LLMBackend = "extractive"
    llm_model: str = "llama-3.3-70b-versatile"
    llm_base_url: str = "https://api.groq.com/openai/v1"
    llm_api_key: str = ""
    llm_temperature: float = 0.0
    llm_max_tokens: int = 700
    llm_timeout_seconds: float = 45.0

    # ------------------------------------------------------------ retrieval
    retrieval_top_k: int = 6
    retrieval_candidates: int = 24
    min_relevance_score: float = 0.35
    use_bm25: bool = True
    rrf_k: int = 60
    max_context_chars: int = 9000

    # ----------------------------------------------------------- guardrails
    max_query_chars: int = 2000
    hard_query_chars: int = 6000
    guardrail_block_threshold: int = 60
    guardrail_refuse_threshold: int = 30
    redact_pii_in_output: bool = True
    expose_guardrail_trace: bool = True
    expose_withheld_count: bool = True
    max_graph_retries: int = 1

    # ---------------------------------------------------------- rate limits
    rate_limit_requests_per_minute: int = 20
    rate_limit_queries_per_day: int = 300

    # --------------------------------------------------------------- ragas
    ragas_llm_model: str = ""
    ragas_embedding_model: str = ""

    # ------------------------------------------------------------ validators
    @field_validator("data_dir", mode="after")
    @classmethod
    def _resolve_data_dir(cls, value: Path) -> Path:
        return value if value.is_absolute() else (PROJECT_ROOT / value)

    @field_validator("secret_key", mode="after")
    @classmethod
    def _guard_secret_key(cls, value: str, info) -> str:  # noqa: ANN001
        if info.data.get("app_env") == "production" and value.startswith("dev-only"):
            raise ValueError(
                "SECRET_KEY must be set to a strong random value when APP_ENV=production."
            )
        return value

    # ----------------------------------------------------------- properties
    @property
    def corpus_path(self) -> Path:
        return self.corpus_dir or (self.data_dir / "corpus")

    @property
    def chroma_path(self) -> Path:
        return self.chroma_dir or (self.data_dir / "chroma")

    @property
    def frontend_path(self) -> Path:
        return self.web_dir or (PROJECT_ROOT / "frontend")

    @property
    def audit_path(self) -> Path:
        return self.data_dir / "audit" / self.audit_filename

    @property
    def catalog_path(self) -> Path:
        return self.data_dir / self.catalog_filename

    @property
    def users_path(self) -> Path:
        return self.data_dir / self.users_filename

    @property
    def eval_path(self) -> Path:
        return self.data_dir / self.eval_dirname

    @property
    def embedding_cache_path(self) -> Path:
        return self.data_dir / "embedding_cache.json"

    @property
    def admin_role_set(self) -> set[str]:
        return {r.strip() for r in self.admin_roles.split(",") if r.strip()}

    @property
    def compliance_role_set(self) -> set[str]:
        return {r.strip() for r in self.compliance_roles.split(",") if r.strip()}

    def ensure_dirs(self) -> None:
        """Create runtime directories (safe to call repeatedly)."""
        for path in (self.data_dir, self.chroma_path, self.audit_path.parent, self.eval_path):
            path.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()


def reset_settings_cache() -> None:
    """Clear the settings cache (used by tests)."""
    get_settings.cache_clear()


settings = get_settings()

__all__ = ["PROJECT_ROOT", "Settings", "get_settings", "reset_settings_cache", "settings"]
