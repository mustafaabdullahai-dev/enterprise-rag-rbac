"""Embedding providers.

Two backends, chosen by ``EMBEDDING_BACKEND``:

* ``hash`` (default) - a deterministic, dependency-free feature-hashing embedder.
  It runs offline with no model download and no API key, which keeps the project
  reproducible for reviewers and fast in CI. Sub-word features (word unigrams,
  word bigrams, character 4-grams) give reasonable lexical-semantic matching for
  the small corporate corpora this system targets.
* ``openai`` - any OpenAI-compatible ``/embeddings`` endpoint (OpenAI, Azure
  OpenAI, Together, vLLM, Ollama, ...). Recommended for production: swap it in
  with two environment variables, no code changes.

Both implement LangChain's ``Embeddings`` interface, so they plug directly into
``langchain_chroma.Chroma``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
from collections import Counter
from pathlib import Path

import httpx
import numpy as np
from langchain_core.embeddings import Embeddings

from enterprise_rag.config import Settings
from enterprise_rag.textutil import tokenize

logger = logging.getLogger(__name__)

_DIGEST_SIZE = 8
_MASK = (1 << 64) - 1


class HashingEmbeddings(Embeddings):
    """Deterministic hashing embedder (offline, no model, no API key)."""

    def __init__(self, dim: int = 384) -> None:
        if dim < 32:
            raise ValueError("Embedding dimension must be at least 32.")
        self.dim = dim

    # ------------------------------------------------------------ interface
    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._vector(text) for text in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._vector(text)

    # ---------------------------------------------------------- internals
    def _vector(self, text: str) -> list[float]:
        features = self._features(text)
        if not features:
            return [0.0] * self.dim

        vector = np.zeros(self.dim, dtype=np.float32)
        for feature, weight in features.items():
            digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=_DIGEST_SIZE).digest()
            index = int.from_bytes(digest[:4], "little") % self.dim
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[index] += sign * (1.0 + math.log(weight))

        norm = float(np.linalg.norm(vector))
        if norm > 0:
            vector /= norm
        return [float(value) for value in vector]

    @staticmethod
    def _features(text: str) -> Counter[str]:
        tokens = [t for t in tokenize(text) if len(t) > 1]
        features: Counter[str] = Counter()
        for index, token in enumerate(tokens):
            features[token] += 1.0
            if index:
                features[f"{tokens[index - 1]}_{token}"] += 0.6
            if len(token) >= 5:
                for offset in range(len(token) - 3):
                    features[f"#{token[offset : offset + 4]}"] += 0.35
        return features


class OpenAICompatibleEmbeddings(Embeddings):
    """Embeddings from any OpenAI-compatible ``/embeddings`` endpoint."""

    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        api_key: str,
        timeout: float = 30.0,
        batch_size: int = 64,
    ) -> None:
        if not api_key:
            raise ValueError("EMBEDDING_API_KEY is required for the 'openai' backend.")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.batch_size = max(1, batch_size)
        self._client = httpx.Client(
            timeout=timeout,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        )

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for start in range(0, len(texts), self.batch_size):
            batch = texts[start : start + self.batch_size]
            vectors.extend(self._embed(batch))
        return vectors

    def embed_query(self, text: str) -> list[float]:
        return self._embed([text])[0]

    def _embed(self, batch: list[str]) -> list[list[float]]:
        response = self._client.post(
            f"{self.base_url}/embeddings", json={"model": self.model, "input": batch}
        )
        response.raise_for_status()
        payload = response.json()
        rows = sorted(payload["data"], key=lambda row: row.get("index", 0))
        return [[float(value) for value in row["embedding"]] for row in rows]


class DiskCachedEmbeddings(Embeddings):
    """Cache wrapper: hashing embeddings are cheap but not free, and the cache
    makes re-ingestion during development near-instant."""

    def __init__(self, inner: Embeddings, path: Path | None = None) -> None:
        self.inner = inner
        self.path = Path(path) if path else None
        self._cache: dict[str, list[float]] = {}
        self._dirty = False
        if self.path and self.path.exists():
            try:
                self._cache = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):  # pragma: no cover - bad cache
                self._cache = {}

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        missing = [t for t in texts if _key(t) not in self._cache]
        if missing:
            vectors = self.inner.embed_documents(missing)
            for text, vector in zip(missing, vectors, strict=True):
                self._cache[_key(text)] = vector
            self._dirty = True
        return [self._cache[_key(t)] for t in texts]

    def embed_query(self, text: str) -> list[float]:
        key = _key(text)
        if key not in self._cache:
            self._cache[key] = self.inner.embed_query(text)
            self._dirty = True
        return self._cache[key]

    def flush(self) -> None:
        if self.path and self._dirty:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._cache), encoding="utf-8")
            self._dirty = False


def _key(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def build_embeddings(settings: Settings) -> Embeddings:
    """Factory honouring ``EMBEDDING_BACKEND``."""
    if settings.embedding_backend == "openai":
        inner: Embeddings = OpenAICompatibleEmbeddings(
            model=settings.embedding_model,
            base_url=settings.embedding_base_url,
            api_key=settings.embedding_api_key,
            timeout=settings.llm_timeout_seconds,
            batch_size=settings.embedding_batch_size,
        )
    else:
        inner = HashingEmbeddings(dim=settings.embedding_dim)

    if settings.embedding_cache_enabled:
        logger.debug("Embedding cache enabled at %s", settings.embedding_cache_path)
        return DiskCachedEmbeddings(inner, settings.embedding_cache_path)
    return inner


__all__ = [
    "build_embeddings",
    "DiskCachedEmbeddings",
    "HashingEmbeddings",
    "OpenAICompatibleEmbeddings",
]
