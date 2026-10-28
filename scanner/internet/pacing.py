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


class ContactLedger:
    """Thread-safe: when each address was last contacted, so a step can start as soon as its own addresses are due.

    ``mark_all`` covers every address at once (the end of a sweep that touched the whole sample). Addresses
    that are in flight count as contacted until their batch ends.
    """

    def __init__(self, seconds: float, killed: Callable[[], bool] = lambda: False,
                 now: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> None:
        self.seconds = float(seconds)
        self._killed, self._now, self._sleep = killed, now, sleep
        self._all: float | None = None
        self._last: dict[str, float] = {}
        self._busy: set[str] = set()
        self._lock = threading.Lock()

    def mark_all(self, at: float | None = None) -> None:
        with self._lock:
            self._all = self._now() if at is None else at

    def _due(self, ip: str) -> float:
        last = max(self._last.get(ip, float("-inf")), self._all if self._all is not None else float("-inf"))
        return last + self.seconds

    def ready_at(self, ips: Iterable[str]) -> float:
        with self._lock:
            return max((self._due(ip) for ip in ips), default=float("-inf"))

    def wait(self, ips: Iterable[str]) -> bool:
        """Block until every address is due (no marking). False means a stop condition fired."""
        if self.seconds <= 0:
            return True
        deadline = self.ready_at(list(ips))
        return deadline == float("-inf") or _sleep_until(deadline, self._killed, self._now, self._sleep)

    def claim(self, ips: list[str], extra: Callable[[float], bool] | None = None) -> bool:
        """Block until every address is due and none is in flight, then mark them in flight. False on a stop."""
        while True:
            if self._killed():
                return False
            with self._lock:
                now = self._now()
                free = not any(ip in self._busy for ip in ips)
                due = self.seconds <= 0 or max((self._due(ip) for ip in ips), default=float("-inf")) <= now
                if free and due and (extra is None or extra(now)):
                    self._busy.update(ips)
                    return True
                wait = max((self._due(ip) for ip in ips), default=now) - now if free and not due else _SLICE
            self._sleep(min(_SLICE, max(wait, 0.01)))

    def release(self, ips: list[str]) -> None:
        with self._lock:
            end = self._now()
            for ip in ips:
                self._last[ip] = end
                self._busy.discard(ip)


def paced_batches(items: list[T], ip_of: Callable[[T], str], ledger: ContactLedger,
                  run_batch: Callable[[list[T]], Any], *, batch_size: int, workers: int = 1,
                  extra: Callable[[list[T]], Callable[[float], bool] | None] | None = None) -> list[Any]:
    """Like ``paced_rounds`` but each batch waits only for its own addresses, and up to ``workers`` run at once.

    Batches are the rounds of ``split_rounds`` cut into ``batch_size`` pieces, so their composition never depends
    on timing. Results come back in batch order. ``extra`` may add a per-batch admission check (see overlap.py).
    Stops starting new batches once a stop condition fires.
    """
    from concurrent.futures import ThreadPoolExecutor

    size = max(1, batch_size)
    batches = [r[i:i + size] for r in split_rounds(items, ip_of) for i in range(0, len(r), size)]
    if not batches:
        return []
    results: list[Any] = [None] * len(batches)
    started: list[bool] = [False] * len(batches)
    take = threading.Lock()
    next_index = [0]
    failed = threading.Event()        # one batch raised: start nothing new, let the error reach the stage

    def worker() -> None:
        while not failed.is_set():
            with take:
                i = next_index[0]
                if i >= len(batches):
                    return
                next_index[0] += 1
            batch = batches[i]
            ips = [ip_of(t) for t in batch]
            if not ledger.claim(ips, extra(batch) if extra else None):
                return
            started[i] = True
            try:
                results[i] = run_batch(batch)
            except BaseException:
                failed.set()
                raise
            finally:
                ledger.release(ips)

    workers = max(1, min(workers, len(batches)))
    if workers == 1:
        worker()
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for f in [pool.submit(worker) for _ in range(workers)]:
                f.result()
    return [r for i, r in enumerate(results) if started[i]]
