"""Guardrail policies: the pattern and topic rules the guards enforce.

Everything regex-based lives here so the policy set is auditable in one place.
Matching is performed against a *normalised* view of the text (NFKC, zero-width
characters removed, whitespace collapsed) so trivial filter evasion - full-width
characters, invisible joiners, ``i g n o r e`` spacing - does not defeat it.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# --------------------------------------------------------------------------- #
# Finding model
# --------------------------------------------------------------------------- #
SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


@dataclass(frozen=True, slots=True)
class Finding:
    """A single guardrail observation."""

    code: str
    label: str
    severity: str = "warning"
    weight: int = 10
    detail: str = ""
    snippet: str = ""

    def as_dict(self, *, include_snippet: bool = False) -> dict[str, object]:
        """Serialise the finding.

        Snippets are excluded by default: the audit log must not copy user input
        (or document content) verbatim. They stay in the API trace, which only
        ever shows the requester their own text.
        """
        payload: dict[str, object] = {
            "code": self.code,
            "label": self.label,
            "severity": self.severity,
            "weight": self.weight,
            "detail": self.detail,
        }
        if include_snippet:
            payload["snippet"] = self.snippet[:120]
        return payload


@dataclass(frozen=True, slots=True)
class PatternRule:
    """A regex rule with a weight and severity."""

    code: str
    label: str
    regex: str
    weight: int = 40
    severity: str = "critical"
    detail: str = ""

    @property
    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.regex, re.IGNORECASE)


_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)


def normalize(text: str) -> str:
    """Normalise text for matching: NFKC, strip zero-width chars, collapse space."""
    folded = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return re.sub(r"[ \t\u00a0]+", " ", folded).strip()


def scan(text: str, rules: tuple[PatternRule, ...]) -> list[Finding]:
    """Apply ``rules`` to ``text`` and return one finding per matching rule."""
    haystack = normalize(text)
    findings: list[Finding] = []
    for rule in rules:
        match = rule.compiled.search(haystack)
        if match:
            findings.append(
                Finding(
                    code=rule.code,
                    label=rule.label,
                    severity=rule.severity,
                    weight=rule.weight,
                    detail=rule.detail,
                    snippet=match.group(0),
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# Prompt injection / jailbreak
# --------------------------------------------------------------------------- #
INJECTION_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "INJ-001",
        "Instruction override",
        r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(all\s+)?"
        r"(previous|prior|above|earlier|system|initial)\b[^.\n]{0,20}"
        r"\b(instruction|prompt|rule|direction|context)",
        75,
        "critical",
        "Attempt to override the system instructions.",
    ),
    PatternRule(
        "INJ-002",
        "System prompt extraction",
        r"\b(reveal|show|print|repeat|output|dump|leak|tell me)\b[^.\n]{0,30}"
        r"\b(your\s+)?(system\s+prompt|initial\s+prompt|instructions|guardrails?|"
        r"hidden\s+rules?|configuration)\b",
        75,
        "critical",
        "Attempt to exfiltrate the system prompt.",
    ),
    PatternRule(
        "INJ-003",
        "Persona hijack",
        r"\b(you are now|from now on you are|act as|pretend to be|simulate being|"
        r"roleplay as)\b[^.\n]{0,40}\b(dan|jailbroken|unrestricted|admin|root|"
        r"developer mode|no rules|without restrictions)",
        70,
        "critical",
        "Persona-based jailbreak attempt.",
    ),
    PatternRule(
        "INJ-004",
        "Guardrail bypass request",
        r"\b(bypass|disable|turn off|switch off|circumvent|remove)\b[^.\n]{0,30}"
        r"\b(security|safety|guardrail|filter|policy|restriction|acl|access control)\b",
        70,
        "critical",
        "Explicit request to disable safety controls.",
    ),
    PatternRule(
        "INJ-005",
        "Chat-template injection",
        r"(<\|[a-z_]+\|>|\[/?INST\]|<<SYS>>|^\s*###\s*(system|instruction)\b|\bsystem\s*:\s*)",
        65,
        "critical",
        "Delimiter/template injection markers detected.",
    ),
    PatternRule(
        "INJ-006",
        "Encoded payload",
        r"\b(base64|rot13|hex|atob|decode this|unscramble|reverse this string)\b[^.\n]{0,30}"
        r"\b(and (then )?(run|follow|execute|obey)|instructions?|prompt)\b",
        60,
        "critical",
        "Encoded instruction payload (filter evasion).",
    ),
    PatternRule(
        "INJ-008",
        "Operating-rule extraction",
        # "your own rules/instructions" - the assistant's, not company policy.
        # Asking about company rules ("the rules for expenses") must not match.
        r"\b(repeat|print|show|reveal|list|describe|tell|explain|output|dump|share|give)\b"
        r"[^.\n]{0,40}\b(your|your\s+own)\s+(operating\s+rules|system\s+rules|instructions|"
        r"guidelines|prompt)\b|\bprompt\s+layout\b",
        70,
        "critical",
        "Attempt to extract the assistant's operating rules.",
    ),
    PatternRule(
        "INJ-007",
        "Data-in-context instruction",
        r"\b(the\s+)?(document|file|policy|context|spreadsheet|note)\s+"
        r"(says|instructs|requires|tells you|orders)\b[^.\n]{0,40}"
        r"\b(ignore|reveal|send|email|export|grant|override|disclose)\b",
        45,
        "warning",
        "Possible indirect prompt injection inside retrieved content.",
    ),
)


# --------------------------------------------------------------------------- #
# Data-exfiltration / social engineering
# --------------------------------------------------------------------------- #
EXFIL_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "EXF-001",
        "Bulk data request",
        r"\b(dump|export|list|enumerate|give me|show me)\b[^.\n]{0,25}"
        r"\b(all|every|entire|full)\b[^.\n]{0,25}"
        r"\b(records?|rows?|tables?|database|documents?|employees?|salaries|invoices?|"
        r"contracts?|data)\b",
        45,
        "warning",
        "Bulk-extraction request.",
    ),
    PatternRule(
        "EXF-002",
        "Other-user data request",
        r"\b(salaries?|compensation|performance reviews?|disciplinary|medical|"
        r"personal (file|record))\b[^.\n]{0,30}\b(of|for|about)\b[^.\n]{0,30}"
        r"\b(all|other|another|colleague|employee|team)\b",
        35,
        "warning",
        "Request for other employees' personal data.",
    ),
    PatternRule(
        "EXF-003",
        "Authority claim",
        r"\b(i am|i'm|this is)\b[^.\n]{0,20}\b(the\s+)?(ceo|cfo|cto|ciso|admin|"
        r"administrator|auditor|board member|owner)\b|\bas an? (admin|administrator|"
        r"auditor|executive)\b",
        35,
        "warning",
        "Unverified authority claim (social engineering).",
    ),
    PatternRule(
        "EXF-004",
        "Permission escalation request",
        r"\b(grant|give|elevate|upgrade|temporarily assign)\b[^.\n]{0,25}"
        r"\b(me|my (account|role|user))\b[^.\n]{0,25}"
        r"\b(access|permission|role|clearance|privilege)s?\b",
        65,
        "critical",
        "Attempt to obtain privileges through the chat channel.",
    ),
    PatternRule(
        "EXF-006",
        "Directory / roster fishing",
        r"\b(employee|staff|headcount|payroll|company)\b[^.\n]{0,20}"
        r"\b(directory|roster|list|register)\b"
        r"|\b(direct dial|mobile phone|home address|personal email|next of kin)\b",
        45,
        "warning",
        "Request for a personnel roster or contact details.",
    ),
    PatternRule(
        "EXF-005",
        "Cross-department probe",
        r"\b(hr|human resources|payroll|finance|legal|board|executive)\b[^.\n]{0,25}"
        r"\b(confidential|restricted|private|internal|secret|not (for|meant for) me)\b",
        30,
        "warning",
        "Probing for data outside the requester's remit.",
    ),
)


# --------------------------------------------------------------------------- #
# PII (redacted, never blocked - masking is the correct control for PII)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class PIIRule:
    """A PII pattern with a redaction tag and an optional checksum validator."""

    code: str
    label: str
    regex: str
    tag: str
    validator: str = ""
    weight: int = 10

    @property
    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.regex, re.IGNORECASE)


def luhn_ok(value: str) -> bool:
    """Luhn checksum - keeps the credit-card rule from firing on random digits."""
    digits = [int(c) for c in re.sub(r"\D", "", value)]
    if len(digits) < 13:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def cnic_ok(value: str) -> bool:
    """Pakistani CNIC format ``NNNNN-NNNNNNN-N``."""
    return bool(re.fullmatch(r"\d{5}-\d{7}-\d", re.sub(r"\s", "", value)))


_PII_VALIDATORS = {"luhn": luhn_ok, "cnic": cnic_ok}

PII_RULES: tuple[PIIRule, ...] = (
    PIIRule("PII-001", "Email address", r"[\w.+-]+@[\w-]+\.[\w.-]{2,}", "EMAIL"),
    PIIRule(
        "PII-002",
        "Phone number",
        r"(?<!\d)(?:\+\d{1,3}[\s-]?)?(?:\(\d{2,4}\)[\s-]?)?\d{3}[\s-]?\d{3,4}[\s-]?\d{2,4}(?!\d)",
        "PHONE",
    ),
    PIIRule("PII-003", "National ID (CNIC)", r"\b\d{5}-\d{7}-\d\b", "NATIONAL_ID", "cnic", 15),
    PIIRule(
        "PII-004",
        "Payment card",
        r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",
        "CARD",
        "luhn",
        25,
    ),
    PIIRule("PII-005", "IBAN", r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", "IBAN", "", 20),
    PIIRule(
        "PII-006",
        "Bank account / payroll reference",
        # Require a digit in the reference itself: "payroll export" is prose,
        # "PAYROLL REF PR-88213" and "account 12345678" are references.
        r"\b(?:account|payroll|iban|swift)\b(?:[\s#:]+[A-Z0-9-]+)*[\s#:]+(?=[A-Z0-9-]*\d)[A-Z0-9-]{6,}\b",
        "BANK_REF",
    ),
    PIIRule("PII-007", "Date of birth", r"\b(?:dob|date of birth)[\s:]*\d{4}-\d{2}-\d{2}\b", "DOB"),
)

REDACTION_TEMPLATE = "[REDACTED-{tag}]"


def redact_pii(text: str) -> tuple[str, list[Finding]]:
    """Mask PII in ``text``; returns the redacted text and what was masked."""
    redacted = text
    findings: list[Finding] = []
    for rule in PII_RULES:
        validator = _PII_VALIDATORS.get(rule.validator) if rule.validator else None
        found: set[str] = set()

        def _replace(match: re.Match[str], _validator=validator, _found=found, _rule=rule) -> str:
            value = match.group(0)
            if _validator and not _validator(value):
                return value
            _found.add(value)
            return REDACTION_TEMPLATE.format(tag=_rule.tag)

        new_text = rule.compiled.sub(_replace, redacted)
        if found:
            findings.append(
                Finding(
                    code=rule.code,
                    label=rule.label,
                    severity="warning",
                    weight=rule.weight,
                    detail=f"Masked {len(found)} occurrence(s).",
                    snippet=", ".join(sorted(found)[:2]),
                )
            )
            redacted = new_text
    return redacted, findings


def detect_pii_types(text: str) -> list[str]:
    """Return the PII rule codes present in ``text`` (used by the classifier)."""
    haystack = normalize(text)
    detected: list[str] = []
    for rule in PII_RULES:
        validator = _PII_VALIDATORS.get(rule.validator) if rule.validator else None
        for match in rule.compiled.finditer(haystack):
            if not validator or validator(match.group(0)):
                detected.append(rule.code)
                break
    return detected


# --------------------------------------------------------------------------- #
# Secrets / credentials (always blocking: no legitimate answer contains them)
# --------------------------------------------------------------------------- #
SECRET_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "SEC-001",
        "AWS access key",
        r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
        80,
        "critical",
        "Cloud credential material.",
    ),
    PatternRule(
        "SEC-002",
        "Private key block",
        r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----",
        85,
        "critical",
        "Private key material.",
    ),
    PatternRule(
        "SEC-003",
        "JWT / bearer token",
        r"(\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
        r"\bbearer\s+[A-Za-z0-9\-._~+/]{20,}=*)",
        80,
        "critical",
        "Session/API token material.",
    ),
    PatternRule(
        "SEC-004",
        "Provider API key",
        r"\b(sk-[A-Za-z0-9]{20,}|gsk_[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|"
        r"xox[baprs]-[A-Za-z0-9-]{10,})\b",
        85,
        "critical",
        "Third-party API credential.",
    ),
    PatternRule(
        "SEC-005",
        "Inline secret assignment",
        r"\b(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|password)\b"
        r"\s*[:=]\s*[\"']?[A-Za-z0-9!@#$%^&*\-_]{12,}",
        70,
        "critical",
        "Hard-coded credential in text.",
    ),
    PatternRule(
        "SEC-006",
        "Credentialed connection string",
        r"\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s\"']{6,}"
        r":[^\s\"'@]{6,}@",
        75,
        "critical",
        "Database URI with embedded credentials.",
    ),
)


# --------------------------------------------------------------------------- #
# Privileged business topics
#
# This is a *signal layer*, not the enforcement layer: retrieval ACLs decide
# access. Topic detection lets the assistant recognise "this person is asking
# about a domain they have no grant for", so it can answer with a deliberate
# refusal instead of a vague "I found nothing" - and log the intent at the
# right severity.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class PrivilegedTopic:
    """A business domain with the grants needed to discuss it."""

    code: str
    label: str
    keywords: tuple[str, ...]
    roles: frozenset[str]
    departments: frozenset[str]
    weight: int = 40

    @property
    def patterns(self) -> tuple[re.Pattern[str], ...]:
        # Built outside the f-string: a backslash inside an f-string expression
        # is a syntax error before Python 3.12.
        compiled = []
        for keyword in self.keywords:
            body = re.escape(keyword).replace("\\ ", "\\s+")
            compiled.append(re.compile(r"\b" + body + r"\b", re.IGNORECASE))
        return tuple(compiled)

    def matches(self, text: str) -> tuple[str, ...]:
        """Return the topic keywords found in ``text``."""
        hits: list[str] = []
        for keyword, pattern in zip(self.keywords, self.patterns, strict=True):
            if pattern.search(text):
                hits.append(keyword)
        return tuple(hits)


PRIVILEGED_TOPICS: tuple[PrivilegedTopic, ...] = (
    PrivilegedTopic(
        code="TOPIC-COMP",
        label="Compensation & payroll",
        keywords=(
            "salary",
            "salaries",
            "compensation",
            "payroll",
            "bonus",
            "bonuses",
            "pay band",
            "pay grade",
            "remuneration",
            "raise",
            "stock option",
            "equity grant",
            "total comp",
            "payslip",
        ),
        roles=frozenset({"hr_business_partner", "executive"}),
        departments=frozenset({"hr", "executive"}),
    ),
    PrivilegedTopic(
        code="TOPIC-FIN",
        label="Budgets, spend & revenue",
        keywords=(
            "budget",
            "forecast",
            "revenue",
            "burn rate",
            "expense report",
            "vendor contract",
            "invoice",
            "purchase order",
            "cost center",
            "profit margin",
            "cash flow",
            "ebitda",
        ),
        roles=frozenset({"finance_analyst", "executive"}),
        departments=frozenset({"finance", "executive"}),
    ),
    PrivilegedTopic(
        code="TOPIC-LEGAL",
        label="Litigation & regulatory",
        keywords=(
            "litigation",
            "lawsuit",
            "settlement",
            "subpoena",
            "legal hold",
            "contract dispute",
            "patent claim",
            "regulatory investigation",
        ),
        roles=frozenset({"legal_counsel", "executive"}),
        departments=frozenset({"legal", "executive"}),
    ),
    PrivilegedTopic(
        code="TOPIC-PEOPLE",
        label="Employee performance & relations",
        keywords=(
            "performance review",
            "performance rating",
            "disciplinary",
            "termination",
            "grievance",
            "attrition",
            "headcount plan",
            "hiring plan",
            "promotion",
        ),
        roles=frozenset({"hr_business_partner", "manager", "executive"}),
        departments=frozenset({"hr", "executive"}),
    ),
    PrivilegedTopic(
        code="TOPIC-INCIDENT",
        label="Incidents & vulnerabilities",
        keywords=(
            "postmortem",
            "post-mortem",
            "outage",
            "breach",
            "security incident",
            "vulnerability",
            "root cause",
            "data leak",
        ),
        roles=frozenset({"manager", "executive"}),
        departments=frozenset({"engineering", "security", "executive"}),
    ),
)


# --------------------------------------------------------------------------- #
# Canned refusals. Deliberately neutral: a refusal must not confirm that the
# withheld data exists, or the refusal itself becomes a disclosure channel.
# --------------------------------------------------------------------------- #
REFUSAL_UNAUTHORIZED = (
    "I can't help with that. The information needed to answer isn't part of the knowledge "
    "I'm permitted to use for your account. If you need it for your role, raise a data-access "
    "request; access decisions are logged and reviewed."
)
REFUSAL_BLOCKED = (
    "I can't process that request. It looks like an attempt to change my operating rules or to "
    "extract material I'm not allowed to share. This attempt has been logged for security review."
)
REFUSAL_INSUFFICIENT_EVIDENCE = (
    "I don't have enough authorised, verifiable source material to answer that. Try rephrasing the "
    "question, or name the document or topic you mean."
)
REFUSAL_RATE_LIMIT = (
    "You've reached the request limit for your account. Please wait a moment and try again."
)
REFUSAL_EMPTY = "Please enter a question."

__all__ = [
    "detect_pii_types",
    "EXFIL_RULES",
    "Finding",
    "INJECTION_RULES",
    "normalize",
    "PatternRule",
    "PII_RULES",
    "PIIRule",
    "PRIVILEGED_TOPICS",
    "PrivilegedTopic",
    "redact_pii",
    "REDACTION_TEMPLATE",
    "REFUSAL_BLOCKED",
    "REFUSAL_EMPTY",
    "REFUSAL_INSUFFICIENT_EVIDENCE",
    "REFUSAL_RATE_LIMIT",
    "REFUSAL_UNAUTHORIZED",
    "scan",
    "SECRET_RULES",
    "SEVERITY_ORDER",
]
