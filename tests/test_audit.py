"""Audit log integrity: hash chaining, tamper detection, filtering, concurrency."""

from __future__ import annotations

import json
import threading

from enterprise_rag.audit.log import GENESIS_HASH, AuditLog


def _write(log: AuditLog, count: int = 3) -> None:
    for index in range(count):
        log.record(actor="tester", action=f"action.{index}", details={"index": index})


def test_empty_log_is_valid(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    ok, message, records = log.verify()
    assert ok and records == 0


def test_records_form_a_valid_chain(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    _write(log, 5)
    ok, message, records = log.verify()
    assert ok, message
    assert records == 5
    oldest = list(log.iter_events())[0]
    assert oldest.prev_hash == GENESIS_HASH


def test_read_returns_newest_first(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    _write(log, 3)
    events = log.read(limit=10)
    assert [e.action for e in events] == ["action.2", "action.1", "action.0"]


def test_filters(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record(actor="alice", action="chat.answered", severity="info")
    log.record(actor="bob", action="chat.blocked", severity="critical")
    assert len(log.read(actor="bob")) == 1
    assert len(log.read(severity="critical")) == 1
    assert len(log.read(action_prefix="chat.")) == 2


def test_tampering_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _write(log, 3)

    lines = path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[1])
    payload["details"]["index"] = 999  # attacker edits a record in place
    lines[1] = json.dumps(payload)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, message, _ = AuditLog(path).verify()
    assert not ok
    assert "modified" in message


def test_deleting_a_record_breaks_the_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _write(log, 4)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:2] + lines[3:]) + "\n", encoding="utf-8")

    ok, message, _ = AuditLog(path).verify()
    assert not ok


def test_concurrent_writes_keep_the_chain_valid(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")

    def worker(worker_id: int) -> None:
        for index in range(20):
            log.record(actor=f"worker-{worker_id}", action="chat.answered", details={"i": index})

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    ok, message, records = log.verify()
    assert ok, message
    assert records == 80


def test_critical_severity_is_recorded(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    event = log.record(
        actor="mallory", action="chat.blocked", outcome="blocked", severity="critical"
    )
    assert event.severity == "critical"
    assert log.read(severity="critical")[0].actor == "mallory"


def test_query_content_is_not_stored_in_the_log(context):
    """The graph logs a fingerprint, never the question itself."""
    user = context.user_store.get("amina.yusuf")
    secret_question = "My personal CNIC is 35202-1234567-1, what is the leave policy?"
    context.graph.run(user, secret_question)
    raw = context.audit.path.read_text(encoding="utf-8")
    assert "35202-1234567-1" not in raw
    assert "personal CNIC" not in raw
