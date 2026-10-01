"""API safety limits: per-principal sliding-window and daily quota limiting.

Two independent limits are enforced because they defend against different abuse
patterns:

* ``requests_per_minute`` - burst/DoS protection and prompt-stuffing loops.
* ``queries_per_day``     - cost control: token spend cannot run away even if a
  credential leaks and the attacker stays under the burst limit.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Result of a rate-limit check."""

    allowed: bool
    scope: str
    limit: int
    remaining: int
    retry_after: int = 0
    used_today: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "scope": self.scope,
            "limit": self.limit,
            "remaining": self.remaining,
            "retry_after": self.retry_after,
            "used_today": self.used_today,
        }


class RateLimiter:
    """Thread-safe in-memory limiter keyed by principal (username + role scope)."""

    def __init__(
        self,
        requests_per_minute: int = 20,
        queries_per_day: int = 300,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.per_minute = max(1, requests_per_minute)
        self.per_day = max(1, queries_per_day)
        self._clock = clock
        self._wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self._windows: dict[str, deque[float]] = {}
        self._daily: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------- checking
    def check(self, key: str) -> RateLimitDecision:
        """Check both scopes without consuming quota."""
        with self._lock:
            now = self._clock()
            window = self._windows.setdefault(key, deque())
            self._trim(window, now)
            if len(window) >= self.per_minute:
                retry = max(1, int(60 - (now - window[0])) + 1)
                return RateLimitDecision(False, "per_minute", self.per_minute, 0, retry)

            today = self._wall_clock().strftime("%Y-%m-%d")
            used = self._daily.get((key, today), 0)
            if used >= self.per_day:
                return RateLimitDecision(False, "per_day", self.per_day, 0, 3600, used_today=used)
            return RateLimitDecision(
                True,
                "ok",
                self.per_minute,
                self.per_minute - len(window) - 1,
                used_today=used,
            )

    def consume(self, key: str) -> RateLimitDecision:
        """Atomically check and record usage of one unit."""
        with self._lock:
            now = self._clock()
            window = self._windows.setdefault(key, deque())
            self._trim(window, now)

            today = self._wall_clock().strftime("%Y-%m-%d")
            used = self._daily.get((key, today), 0)

            if len(window) >= self.per_minute:
                retry = max(1, int(60 - (now - window[0])) + 1)
                return RateLimitDecision(
                    False, "per_minute", self.per_minute, 0, retry, used_today=used
                )
            if used >= self.per_day:
                return RateLimitDecision(False, "per_day", self.per_day, 0, 3600, used_today=used)

            window.append(now)
            self._daily[(key, today)] = used + 1
            return RateLimitDecision(
                True,
                "ok",
                self.per_minute,
                self.per_minute - len(window),
                used_today=used + 1,
            )

    # ------------------------------------------------------------ maint
    def reset(self, key: str | None = None) -> None:
        """Clear limits for one principal, or everybody when ``key`` is None."""
        with self._lock:
            if key is None:
                self._windows.clear()
                self._daily.clear()
                return
            self._windows.pop(key, None)
            for daily_key in [k for k in self._daily if k[0] == key]:
                self._daily.pop(daily_key, None)

    def snapshot(self) -> dict[str, dict[str, int]]:
        with self._lock:
            today = self._wall_clock().strftime("%Y-%m-%d")
            return {
                key: {
                    "in_window": len(self._trim(self._windows.get(key, deque()), self._clock())),
                    "today": self._daily.get((key, today), 0),
                }
                for key in self._windows
            }

    # ---------------------------------------------------------- internals
    def _trim(self, window: deque[float], now: float) -> deque[float]:
        while window and now - window[0] >= 60:
            window.popleft()
        return window


__all__ = ["RateLimitDecision", "RateLimiter"]
