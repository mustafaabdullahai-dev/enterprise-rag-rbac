# Incident Postmortem: Checkout latency spike, 2026-03-14

## Summary
Between 09:12 and 10:04 UTC the checkout service responded in the 95th percentile with 8.4
seconds, exceeding the 800 ms objective. Approximately 12,400 requests were affected.

## Root cause
A database connection pool limit was reduced from 120 to 40 during routine hardening. The
checkout service, which is chatty under load, exhausted the pool and queued on acquisition.

## Detection
The latency alert fired after four minutes. The team was already investigating a support ticket.

## Resolution
The pool limit was restored to 100 with a separate read-only pool for reporting queries, and the
checkout service now uses a circuit breaker with a 250 ms acquisition timeout.

## Action items
- Add a load test to the release pipeline for pool sizing changes (owner: platform team).
- Document pool sizing guidance in the runbook (owner: service owners).
- Review all other services for the same hardening change (owner: SRE).
