"""Minimum spacing between requests to the same address.

``IpPacer`` spaces individual requests (HTTP fetches). ``Gap`` and ``split_rounds`` space whole tool batches:
a batch never holds two targets with the same address, and the next batch starts only after the minimum
interval has passed since the previous one ended, so every address sees at least that long a pause.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable, Iterable, TypeVar

T = TypeVar("T")
_SLICE = 0.5


def _sleep_until(deadline: float, killed: Callable[[], bool], now: Callable[[], float], sleep: Callable[[float], None]) -> bool:
    """Sleep until ``deadline``; returns False if a stop condition fired first."""
    while True:
        remaining = deadline - now()
        if remaining <= 0:
            return True
        if killed():
            return False
        sleep(min(_SLICE, remaining))


class IpPacer:
    """Thread-safe: each address gets its next request slot at least ``min_interval`` after the previous one."""

    def __init__(self, min_interval: float, killed: Callable[[], bool] = lambda: False,
                 now: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> None:
        self.min_interval = float(min_interval)
        self._killed, self._now, self._sleep = killed, now, sleep
        self._next: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, ip: str) -> bool:
        """Block until a request to ``ip`` may start. False means a stop condition fired: do not send."""
        if self.min_interval <= 0:
            return True
        with self._lock:
            slot = max(self._now(), self._next.get(ip, 0.0))
            self._next[ip] = slot + self.min_interval
        return _sleep_until(slot, self._killed, self._now, self._sleep)


class Gap:
    """Enforces ``seconds`` between the end of one contacting step and the start of the next."""

    def __init__(self, seconds: float, killed: Callable[[], bool] = lambda: False,
                 now: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> None:
        self.seconds = float(seconds)
        self._killed, self._now, self._sleep = killed, now, sleep
        self._last: float | None = None

    def mark(self) -> None:
        self._last = self._now()

    def wait(self) -> bool:
        if self.seconds <= 0 or self._last is None:
            return True
        return _sleep_until(self._last + self.seconds, self._killed, self._now, self._sleep)


def split_rounds(items: Iterable[T], ip_of: Callable[[T], str]) -> list[list[T]]:
    """Round i holds the i-th item of every address, so no round contains an address twice."""
    rounds: list[list[T]] = []
    seen: dict[str, int] = {}
    for item in items:
        ip = ip_of(item)
        index = seen.get(ip, 0)
        seen[ip] = index + 1
        if index == len(rounds):
            rounds.append([])
        rounds[index].append(item)
    return rounds


def paced_rounds(items: list[T], ip_of: Callable[[T], str], gap: Gap, run_round: Callable[[list[T]], Any]) -> list[Any]:
    """Run ``run_round`` once per round, waiting out the gap before each. Stops early if a stop condition fires."""
    results: list[Any] = []
    for batch in split_rounds(items, ip_of):
        if not gap.wait():
            break
        results.append(run_round(batch))
        gap.mark()
    return results
