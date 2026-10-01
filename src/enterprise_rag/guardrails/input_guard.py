"""Input guardrails: what we refuse to send to a model in the first place.

Checks run in this order and each adds weighted findings to a risk score:

1. shape      - empty query, length caps (API safety limits)
2. PII        - masked before the query is embedded, logged or sent anywhere
3. injection  - instruction override / jailbreak / prompt extraction
4. secrets    - credentials pasted into the chat box
5. exfiltration and social engineering
6. topic      - is the requester asking about a domain they have no grant for?

The verdict is one of ``allow`` / ``refuse`` / ``block``. Only ``allow`` reaches
retrieval.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from enterprise_rag.config import Settings
from enterprise_rag.guardrails.policies import (
    EXFIL_RULES,
    INJECTION_RULES,
    PRIVILEGED_TOPICS,
    REFUSAL_BLOCKED,
    REFUSAL_EMPTY,
    REFUSAL_UNAUTHORIZED,
    SECRET_RULES,
    Finding,
    normalize,
    redact_pii,
    scan,
)
from enterprise_rag.security.identity import User
from enterprise_rag.textutil import truncate

Action = Literal["allow", "refuse", "block"]


@dataclass(frozen=True, slots=True)
class InputVerdict:
    """Result of the input guardrail pass."""

    action: Action
    risk_score: int
    sanitized_query: str
    findings: tuple[Finding, ...] = ()
    topics: tuple[str, ...] = ()
    missing_grants: tuple[str, ...] = ()
    reason_code: str = "OK"
    refusal: str = ""
    truncated: bool = False

    @property
    def allowed(self) -> bool:
        return self.action == "allow"

    def as_dict(self, *, include_snippets: bool = False) -> dict[str, Any]:
        return {
            "action": self.action,
            "risk_score": self.risk_score,
            "reason_code": self.reason_code,
            "topics": list(self.topics),
            "missing_grants": list(self.missing_grants),
            "truncated": self.truncated,
            "findings": [f.as_dict(include_snippet=include_snippets) for f in self.findings],
        }


class InputGuard:
    """Screens user input before it reaches retrieval or a model."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def evaluate(self, query: str, user: User) -> InputVerdict:
        findings: list[Finding] = []
        raw = (query or "").strip()

        if not raw:
            return InputVerdict(
                "refuse", 0, "", (), reason_code="EMPTY_QUERY", refusal=REFUSAL_EMPTY
            )

        text = normalize(raw)
        truncated = False
        if len(text) > self.settings.max_query_chars:
            if len(text) > self.settings.hard_query_chars:
                findings.append(
                    Finding(
                        "INP-002",
                        "Query exceeds hard size limit",
                        "warning",
                        65,
                        f"{len(text)} characters (limit {self.settings.hard_query_chars}).",
                        truncate(text, 60),
                    )
                )
            else:
                truncated = True
                findings.append(
                    Finding(
                        "INP-001",
                        "Query truncated",
                        "info",
                        5,
                        f"Trimmed to {self.settings.max_query_chars} characters.",
                    )
                )
                text = truncate(text, self.settings.max_query_chars, suffix="")

        # --- PII: mask, never block (masking is the correct control) --------
        text, pii_findings = redact_pii(text)
        findings.extend(pii_findings)

        # --- injection / jailbreak, credentials, exfiltration ---------------
        findings.extend(scan(text, INJECTION_RULES))
        findings.extend(scan(text, SECRET_RULES))
        findings.extend(scan(text, EXFIL_RULES))

        # --- privileged topic probing ---------------------------------------
        topics, missing = self._scan_topics(text, user, findings)

        # PII is handled by masking, so it must not push the query over a refusal
        # threshold - refusing after redacting would defeat the point.
        codes = {f.code for f in findings}
        risk = min(100, sum(f.weight for f in findings if not f.code.startswith("PII-")))
        critical = [
            f for f in findings if f.severity == "critical" and not f.code.startswith("PII-")
        ]

        if critical or risk >= self.settings.guardrail_block_threshold:
            return InputVerdict(
                "block",
                risk,
                text,
                tuple(findings),
                tuple(topics),
                tuple(missing),
                reason_code="QUERY_TOO_LONG" if codes == {"INP-002"} else "INJECTION_OR_SECRET",
                refusal=REFUSAL_BLOCKED,
                truncated=truncated,
            )

        if risk >= self.settings.guardrail_refuse_threshold:
            if "INP-002" in codes:
                reason = "QUERY_TOO_LONG"
            elif missing:
                reason = "UNAUTHORIZED_TOPIC"
            else:
                reason = "RISK_THRESHOLD"
            return InputVerdict(
                "refuse",
                risk,
                text,
                tuple(findings),
                tuple(topics),
                tuple(missing),
                reason_code=reason,
                refusal=REFUSAL_UNAUTHORIZED,
                truncated=truncated,
            )

        return InputVerdict(
            "allow",
            risk,
            text,
            tuple(findings),
            tuple(topics),
            (),
            reason_code="OK",
            truncated=truncated,
        )

    @staticmethod
    def _scan_topics(text: str, user: User, findings: list[Finding]) -> tuple[list[str], list[str]]:
        """Flag privileged topics the requester has no grant for."""
        topics: list[str] = []
        missing: list[str] = []
        for topic in PRIVILEGED_TOPICS:
            hits = topic.matches(text)
            if not hits:
                continue
            topics.append(topic.code)
            granted = user.has_role(*topic.roles) or user.department.value in topic.departments
            if granted:
                continue
            missing.append(topic.code)
            findings.append(
                Finding(
                    topic.code,
                    topic.label,
                    "warning",
                    topic.weight,
                    f"Requester has no grant for {topic.label}.",
                    ", ".join(hits[:3]),
                )
            )
        return topics, missing


__all__ = ["Action", "InputGuard", "InputVerdict"]
