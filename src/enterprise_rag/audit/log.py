"""Tamper-evident audit logging.

Every security-relevant action (login, retrieval decision, refusal, guardrail
trip, ingestion, evaluation) is appended to a JSONL file where each record
stores the hash of its predecessor. Deleting or editing any line breaks the
chain, which ``verify()`` detects - the property an auditor actually cares
about, and the reason the log cannot simply be "a text file".
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64
SEVERITIES = ("info", "warning", "critical")


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One immutable audit record."""

    event_id: str
    ts: str
    actor: str
    action: str
    outcome: str
    severity: str
    details: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS_HASH
    record_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "ts": self.ts,
            "actor": self.actor,
            "action": self.action,
            "outcome": self.outcome,
            "severity": self.severity,
            "details": self.details,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> AuditEvent:
        return cls(
            event_id=str(raw.get("event_id", "")),
            ts=str(raw.get("ts", "")),
            actor=str(raw.get("actor", "")),
            action=str(raw.get("action", "")),
            outcome=str(raw.get("outcome", "")),
            severity=str(raw.get("severity", "info")),
            details=dict(raw.get("details", {})),
            prev_hash=str(raw.get("prev_hash", GENESIS_HASH)),
            record_hash=str(raw.get("record_hash", "")),
        )


def compute_hash(prev_hash: str, event: AuditEvent) -> str:
    """Deterministic hash over the canonical form of an event."""
    payload = {
        "event_id": event.event_id,
        "ts": event.ts,
        "actor": event.actor,
        "action": event.action,
        "outcome": event.outcome,
        "severity": event.severity,
        "details": event.details,
        "prev_hash": prev_hash,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{prev_hash}|{canonical}".encode()).hexdigest()


class AuditLog:
    """Append-only, hash-chained audit log backed by a JSONL file."""

    def __init__(self, path: Path, *, fsync: bool = False) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._fsync = fsync

    # -------------------------------------------------------------- writing
    def record(
        self,
        *,
        actor: str,
        action: str,
        outcome: str = "success",
        severity: str = "info",
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Append one event, chaining it to the previous record's hash."""
        severity = severity if severity in SEVERITIES else "info"
        with self._lock:
            prev_hash = self._tail_hash()
            draft = AuditEvent(
                event_id=uuid.uuid4().hex[:16],
                ts=datetime.now(UTC).isoformat(timespec="milliseconds"),
                actor=actor,
                action=action,
                outcome=outcome,
                severity=severity,
                details=details or {},
                prev_hash=prev_hash,
            )
            event = AuditEvent(
                event_id=draft.event_id,
                ts=draft.ts,
                actor=draft.actor,
                action=draft.action,
                outcome=draft.outcome,
                severity=draft.severity,
                details=draft.details,
                prev_hash=prev_hash,
                record_hash=compute_hash(prev_hash, draft),
            )
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
                handle.flush()
                if self._fsync:
                    os.fsync(handle.fileno())
            return event

    # -------------------------------------------------------------- reading
    def read(
        self,
        *,
        limit: int = 100,
        actor: str | None = None,
        severity: str | None = None,
        action_prefix: str | None = None,
    ) -> list[AuditEvent]:
        """Most recent events first, optionally filtered."""
        events = [
            event
            for event in self.iter_events()
            if (actor is None or event.actor == actor)
            and (severity is None or event.severity == severity)
            and (action_prefix is None or event.action.startswith(action_prefix))
        ]
        return list(reversed(events[-max(1, limit) :]))

    def iter_events(self) -> Iterable[AuditEvent]:
        if not self.path.exists():
            return []
        events: list[AuditEvent] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(AuditEvent.from_dict(json.loads(line)))
                except json.JSONDecodeError:  # pragma: no cover - corrupted line
                    continue
        return events

    def count(self) -> int:
        return len(list(self.iter_events()))

    # ---------------------------------------------------------- integrity
    def verify(self) -> tuple[bool, str, int]:
        """Re-walk the chain. Returns ``(ok, message, records_checked)``."""
        prev = GENESIS_HASH
        checked = 0
        for index, event in enumerate(self.iter_events(), start=1):
            if event.prev_hash != prev:
                return False, f"Chain break at record {index}: prev_hash mismatch.", checked
            expected = compute_hash(event.prev_hash, event)
            if expected != event.record_hash:
                return False, f"Record {index} was modified after being written.", checked
            prev = event.record_hash
            checked += 1
        return True, "Audit chain intact.", checked

    def _tail_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last = GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    last = str(json.loads(line).get("record_hash", GENESIS_HASH))
                except json.JSONDecodeError:  # pragma: no cover
                    continue
        return last


__all__ = ["AuditEvent", "AuditLog", "GENESIS_HASH", "compute_hash"]
