"""LLM providers.

``LLM_BACKEND`` selects the engine:

* ``extractive`` (default) - a local, deterministic answerer that selects the
  sentences which actually answer the question and cites them. No API key, no
  network, no model download, and it can never fabricate a fact because it only
  ever emits sentences that came from the authorised context. Useful for CI,
  demos and as a grounded fallback when a hosted model is unavailable.
* ``openai`` - any OpenAI-compatible ``/chat/completions`` endpoint (OpenAI,
  Groq, Together, vLLM, Ollama, ...). Set ``LLM_BASE_URL``/``LLM_API_KEY``/
  ``LLM_MODEL`` and the same graph, guardrails and evaluation harness apply.

Both are exposed as a LangChain ``LLM`` runnable, so nodes in the LangGraph
workflow compose them with prompts and parsers like any other model.
"""

from __future__ import annotations

import logging
import math
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import httpx
from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.llms import LLM

from enterprise_rag.config import Settings
from enterprise_rag.llm.prompts import (
    CONTEXT_END,
    CONTEXT_START,
    ITEM_PREFIX,
    ITEM_SEPARATOR,
    QUESTION_END,
    QUESTION_START,
)
from enterprise_rag.textutil import content_tokens, split_sentences

logger = logging.getLogger(__name__)

# A sentence must score at least this fraction of the best sentence to be
# included. Measured on the golden set: 0.3 scored better than 0.6 on
# faithfulness, answer relevancy and citation coverage, because short answers
# under-cover the question - so this stays data-driven rather than guessed.
RELATIVE_SCORE_FLOOR = 0.3
MAX_EXTRACTIVE_SENTENCES = 5
MIN_SENTENCE_CHARS = 25
MIN_SENTENCE_TOKENS = 4

_ITEM_RE = re.compile(
    rf"^{re.escape(ITEM_PREFIX)}(\d+){re.escape(ITEM_SEPARATOR)}\s+(\S+)\s*\|\s*(.*)$"
)


@dataclass(frozen=True, slots=True)
class ContextItem:
    """One parsed context block from the prompt."""

    doc_id: str
    chunk_id: str
    title: str
    text: str

    @property
    def citation(self) -> str:
        return f"[{self.doc_id}#{self.chunk_id}]"


@dataclass(frozen=True, slots=True)
class LLMResult:
    """Model output plus provenance (used in the API response and the audit log)."""

    text: str
    backend: str
    model: str
    latency_ms: float
    refused: bool = False
    usage: dict[str, Any] | None = None


def parse_prompt(prompt: str) -> tuple[list[ContextItem], str]:
    """Split a grounded prompt back into context items and the question.

    Uses the *last* occurrence of each fence: the system prompt itself mentions
    ``<<<CONTEXT>>>`` when describing the rules, so the first occurrence is not
    the real fence.
    """
    context = ""
    question = ""
    start = prompt.rfind(CONTEXT_START)
    end = prompt.rfind(CONTEXT_END)
    if start != -1 and end > start:
        context = prompt[start + len(CONTEXT_START) : end]

    q_start = prompt.rfind(QUESTION_START)
    q_end = prompt.rfind(QUESTION_END)
    if q_start != -1 and q_end > q_start:
        question = prompt[q_start + len(QUESTION_START) : q_end]
    return _parse_items(context), question.strip()


def _parse_items(context: str) -> list[ContextItem]:
    items: list[ContextItem] = []
    current: dict[str, str] | None = None
    buffer: list[str] = []
    for line in context.splitlines():
        match = _ITEM_RE.match(line.strip())
        if match:
            if current is not None:
                items.append(_finish(current, buffer))
            current = {"doc_id": "", "chunk_id": "", "title": "", "_ref": match.group(2)}
            doc_id, _, chunk_id = match.group(2).partition("#")
            current["doc_id"] = doc_id
            current["chunk_id"] = chunk_id
            current["title"] = match.group(3).split("|")[0].strip()
            buffer = []
        elif current is not None:
            buffer.append(line)
    if current is not None:
        items.append(_finish(current, buffer))
    return items


def _finish(current: dict[str, str], buffer: list[str]) -> ContextItem:
    return ContextItem(
        doc_id=current["doc_id"],
        chunk_id=current["chunk_id"],
        title=current["title"],
        text="\n".join(buffer).strip(),
    )


class EnterpriseLLM(LLM):
    """LangChain ``LLM`` wrapper over the configured backend."""

    backend: str = "extractive"
    model: str = "extractive-local"
    base_url: str = ""
    api_key: str = ""
    temperature: float = 0.0
    max_tokens: int = 700
    timeout: float = 45.0
    last_result: LLMResult | None = None

    @property
    def _llm_type(self) -> str:
        return f"enterprise-{self.backend}"

    # --------------------------------------------------------------- calling
    def _call(
        self,
        prompt: str,
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> str:
        started = time.perf_counter()
        if self.backend == "openai":
            text, usage = self._call_openai(prompt, stop=stop)
        else:
            text, usage = self._call_extractive(prompt), None

        self.last_result = LLMResult(
            text=text,
            backend=self.backend,
            model=self.model,
            latency_ms=(time.perf_counter() - started) * 1000,
            refused=text.strip() == "" or text.strip().upper().startswith("INSUFFICIENT_EVIDENCE"),
            usage=usage,
        )
        return text

    # ------------------------------------------------------------- backends
    def _call_openai(
        self, prompt: str, *, stop: list[str] | None = None
    ) -> tuple[str, dict[str, Any] | None]:
        if not self.api_key:
            raise RuntimeError("LLM_API_KEY is required when LLM_BACKEND=openai.")
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if stop:
            payload["stop"] = stop
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(
                f"{self.base_url.rstrip('/')}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
        text = (data["choices"][0]["message"].get("content") or "").strip()
        return text, data.get("usage")

    @staticmethod
    def _is_answer_candidate(sentence: str) -> bool:
        """Reject headings/breadcrumbs: they are pointers, not statements."""
        if len(sentence) < MIN_SENTENCE_CHARS:
            return False
        if sentence.startswith("#") or " > " in sentence:
            return False
        if sentence.rstrip().endswith((":", "-")):
            return False
        return len(content_tokens(sentence)) >= MIN_SENTENCE_TOKENS

    def _call_extractive(self, prompt: str) -> str:
        """Answer by selecting and citing the best matching context sentences."""
        items, question = parse_prompt(prompt)
        if not items or not question:
            return "INSUFFICIENT_EVIDENCE"

        candidates: list[tuple[float, str, ContextItem]] = []
        for item in items:
            for sentence in split_sentences(item.text):
                sentence = sentence.strip()
                if not self._is_answer_candidate(sentence):
                    continue
                candidates.append((0.0, sentence, item))

        if not candidates:
            return "INSUFFICIENT_EVIDENCE"

        query_tokens = content_tokens(question)
        if not query_tokens:
            return "INSUFFICIENT_EVIDENCE"

        scored = self._score(candidates, query_tokens)
        if not scored:
            return "INSUFFICIENT_EVIDENCE"

        top = max(score for score, _, _ in scored)
        if top <= 0:
            return "INSUFFICIENT_EVIDENCE"

        selected: list[tuple[float, str, ContextItem]] = []
        for score, sentence, item in sorted(scored, key=lambda row: row[0], reverse=True):
            if score < top * RELATIVE_SCORE_FLOOR:
                continue
            if any(sentence.lower() in chosen[1].lower() for chosen in selected):
                continue
            selected.append((score, sentence, item))
            if len(selected) >= MAX_EXTRACTIVE_SENTENCES:
                break

        body = " ".join(f"{sentence} {item.citation}" for _, sentence, item in selected)
        return f"Based on your accessible sources: {body}"

    @staticmethod
    def _score(
        candidates: Sequence[tuple[float, str, ContextItem]], query_tokens: set[str]
    ) -> list[tuple[float, str, ContextItem]]:
        """Weight sentences by the rarity of the query terms they contain."""
        document_frequency: dict[str, int] = {}
        sentence_tokens: list[set[str]] = []
        for _, sentence, _ in candidates:
            tokens = content_tokens(sentence)
            sentence_tokens.append(tokens)
            for token in tokens:
                document_frequency[token] = document_frequency.get(token, 0) + 1

        total = max(1, len(candidates))
        scored: list[tuple[float, str, ContextItem]] = []
        for (_, sentence, item), tokens in zip(candidates, sentence_tokens, strict=True):
            shared = query_tokens & tokens
            if not shared:
                continue
            weight = sum(
                math.log(1 + total / (1 + document_frequency.get(token, 1))) for token in shared
            )
            coverage = len(shared) / len(query_tokens)
            length_penalty = 1 + 0.004 * max(0, len(tokens) - 40)
            scored.append((weight * (0.5 + coverage) / length_penalty, sentence, item))
        return scored


def build_llm(settings: Settings) -> EnterpriseLLM:
    """Factory honouring ``LLM_BACKEND``."""
    if settings.llm_backend == "openai":
        return EnterpriseLLM(
            backend="openai",
            model=settings.llm_model,
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
            timeout=settings.llm_timeout_seconds,
        )
    return EnterpriseLLM(backend="extractive", model="extractive-local")


__all__ = [
    "build_llm",
    "ContextItem",
    "EnterpriseLLM",
    "LLMResult",
    "parse_prompt",
]
