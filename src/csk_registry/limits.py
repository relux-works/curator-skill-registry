from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    retry_after: int


class FixedWindowLimiter:
    """A bounded in-process limiter for one writable registry process."""

    def __init__(self, *, requests: int, window_seconds: int = 60, max_keys: int = 10_000) -> None:
        if requests < 1 or window_seconds < 1 or max_keys < 1:
            raise ValueError("rate limiter bounds must be positive")
        self.requests = requests
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._entries: dict[str, tuple[float, int, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, *, now: float | None = None) -> RateDecision:
        instant = time.monotonic() if now is None else now
        with self._lock:
            start, count, _ = self._entries.get(key, (instant, 0, instant))
            if instant - start >= self.window_seconds:
                start, count = instant, 0
            if count >= self.requests:
                remaining = max(1, math.ceil(self.window_seconds - (instant - start)))
                self._entries[key] = (start, count, instant)
                return RateDecision(False, remaining)
            self._entries[key] = (start, count + 1, instant)
            self._bound_entries(instant)
            return RateDecision(True, 0)

    def _bound_entries(self, now: float) -> None:
        if len(self._entries) <= self.max_keys:
            return
        expired = [
            key
            for key, (start, _, _) in self._entries.items()
            if now - start >= self.window_seconds
        ]
        for key in expired:
            self._entries.pop(key, None)
        while len(self._entries) > self.max_keys:
            oldest = min(self._entries, key=lambda key: self._entries[key][2])
            self._entries.pop(oldest, None)
