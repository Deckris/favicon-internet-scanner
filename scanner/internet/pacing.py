"""Minimum spacing between requests to the same address, and a cap on simultaneous connections per network.

``IpPacer`` spaces individual requests (HTTP fetches). ``Gap`` and ``split_rounds`` space whole tool batches:
a batch never holds two targets with the same address, and the next batch starts only after the minimum
interval has passed since the previous one ended, so every address sees at least that long a pause.

``SubnetLimiter`` bounds how many connections are open at once to one /24 (IPv4) or /48 (IPv6). It is shared by
every stage and thread of a process. ``BackoffState`` lowers that bound for a network that times out repeatedly
or answers 429/503 and lets it recover after a quiet period.

Lock order: a ``ContactLedger`` or ``IpPacer`` lock may be held while taking the limiter lock, never the other
way round. The limiter lock is a leaf: nothing is called while it is held, and a waiter never sleeps holding a
lock. The limiter is only ever asked without blocking (``try_acquire``) from inside the ledger or pacer lock,
so a caller that waits for a slot holds no address and no slot while it waits.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import threading
import time
from typing import Any, Callable, Iterable, Mapping, TypeVar

T = TypeVar("T")
_SLICE = 0.5
_CHECK = 1.0               # longest sleep of a pacer waiter between looks at the kill switch
_LIMIT_POLL = 0.25          # how often a caller blocked only by the network cap looks again
_PRUNE_EVERY = 4096         # releases between sweeps for idle back-off records
log = logging.getLogger(__name__)


class PacingViolation(AssertionError):
    """A spacing or in-flight invariant did not hold (raised only in strict mode)."""


_strict = os.environ.get("SCANNER_PACING_STRICT", "") not in ("", "0")
_violations: list[str] = []
_violation_count = 0
_violation_lock = threading.Lock()


def set_strict(flag: bool) -> bool:
    """Make an invariant violation raise ``PacingViolation``; returns the previous setting (for tests)."""
    global _strict
    previous, _strict = _strict, bool(flag)
    return previous


def violations() -> tuple[int, list[str]]:
    """(total count, the first messages) of the violations seen so far."""
    with _violation_lock:
        return _violation_count, list(_violations)


def reset_violations() -> None:
    global _violation_count
    with _violation_lock:
        _violation_count = 0
        _violations.clear()


def _violation(message: str) -> None:
    global _violation_count
    with _violation_lock:
        _violation_count += 1
        if len(_violations) < 100:
            _violations.append(message)
            log.warning("pacing invariant violated: %s", message)
    if _strict:
        raise PacingViolation(message)


def _nap(seconds: float, sleep: Callable[[float], None], stop_event: Any) -> None:
    """Sleep, but wake at once if ``stop_event`` is set."""
    if stop_event is None:
        sleep(seconds)
    else:
        stop_event.wait(seconds)


def _sleep_until(deadline: float, killed: Callable[[], bool], now: Callable[[], float], sleep: Callable[[float], None],
                 stop_event: Any = None, slice_seconds: float = _SLICE) -> bool:
    """Sleep until ``deadline``; returns False if a stop condition fired first (checked every ``slice_seconds``)."""
    while True:
        if killed() or (stop_event is not None and stop_event.is_set()):
            return False
        remaining = deadline - now()
        if remaining <= 0:
            return True
        _nap(min(slice_seconds, remaining), sleep, stop_event)


class IpPacer:
    """Thread-safe: a request to an address is released at least ``min_interval`` after the previous release.

    A caller reserves its place in the address's queue when it arrives (slot = the later of now and the previous
    reservation, which then moves ``min_interval`` on) and sleeps until that deadline in one wait, so thousands of
    waiting threads do not wake in turn to look again. Wake-ups happen at the deadline, at a stop, and every
    ``poll`` seconds to look at ``killed``.

    The gap itself is measured from the actual previous release, which is checked again when the caller wakes. A
    waiter that wakes late (a busy CPU) therefore pushes the next release back instead of shortening the gap
    after it. A reservation that is never used because of a stop is simply skipped.

    With a ``limiter`` a release also needs a free connection slot for the address's network. The slot is held
    until ``done`` is called, which also reports how the request went so the limiter can back off. A caller held
    only by a full network looks again every ``_LIMIT_POLL`` seconds, keeping its place in the queue.
    """

    def __init__(self, min_interval: float, killed: Callable[[], bool] = lambda: False,
                 now: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 stop_event: Any = None, poll: float = _CHECK, limiter: "SubnetLimiter | None" = None) -> None:
        self.min_interval = float(min_interval)
        self._killed, self._now, self._sleep, self._stop = killed, now, sleep, stop_event
        self._poll = min(max(float(poll), 0.01), _CHECK)    # longest sleep between looks at the kill switch
        self._next: dict[str, float] = {}       # first unreserved slot per address
        self._last: dict[str, float] = {}       # when each address was actually released last
        self._lock = threading.Lock()
        self.limiter = limiter
        self._grants = 0

    def _prune(self, now: float) -> None:
        """Forget addresses whose pause has passed: an absent address is due at once."""
        self._next = {ip: due for ip, due in self._next.items() if due > now}
        self._last = {ip: at for ip, at in self._last.items() if at + self.min_interval > now}

    def wait(self, ip: str) -> bool:
        """Block until a request to ``ip`` may start. False means a stop condition fired: do not send."""
        if self.min_interval <= 0 and self.limiter is None:
            return not (self._killed() or (self._stop is not None and self._stop.is_set()))
        counts = {self.limiter.key_of(ip): 1} if self.limiter is not None else None
        slot: float | None = None
        while True:
            if self._killed() or (self._stop is not None and self._stop.is_set()):
                return False
            with self._lock:
                now = self._now()
                if slot is None:
                    slot = max(now, self._next.get(ip, float("-inf")))
                    if self.min_interval > 0:
                        self._next[ip] = slot + self.min_interval
                last = self._last.get(ip, float("-inf"))
                earliest = max(slot, last + self.min_interval) if self.min_interval > 0 else slot
                if now < earliest - 1e-9:
                    delay = earliest - now
                elif counts is not None and not self.limiter.try_acquire(counts):
                    delay = _LIMIT_POLL
                else:
                    if last != float("-inf") and now - last < self.min_interval - 1e-6:
                        _violation(f"{ip} contacted again {now - last:.3f} s after its last contact")
                    if self.min_interval > 0:
                        self._last[ip] = now
                        self._next[ip] = max(self._next.get(ip, now), now + self.min_interval)
                        self._grants += 1
                        if self._grants % (1 << 16) == 0:
                            self._prune(now)
                    return True
            _nap(min(self._poll, delay), self._sleep, self._stop)

    def done(self, ip: str, result: Any = None) -> None:
        """End of a request that ``wait`` released: give the network slot back and note how it went."""
        if self.limiter is None:
            return
        self.limiter.release({self.limiter.key_of(ip): 1})
        if result is not None:
            self.limiter.observe_outcome(ip, getattr(result, "outcome", None), getattr(result, "http_status", None),
                                         getattr(result, "retry_after_seconds", None))


class Gap:
    """Enforces ``seconds`` between the end of one contacting step and the start of the next."""

    def __init__(self, seconds: float, killed: Callable[[], bool] = lambda: False,
                 now: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 stop_event: Any = None) -> None:
        self.seconds = float(seconds)
        self._killed, self._now, self._sleep, self._stop = killed, now, sleep, stop_event
        self._last: float | None = None

    def mark(self) -> None:
        self._last = self._now()

    def wait(self) -> bool:
        if self.seconds <= 0 or self._last is None:
            return not (self._killed() or (self._stop is not None and self._stop.is_set()))
        return _sleep_until(self._last + self.seconds, self._killed, self._now, self._sleep, self._stop)


def network_key(ip: str) -> str:
    """The /24 of an IPv4 address or the /48 of an IPv6 address, as a short string key."""
    if ":" not in ip:
        head, sep, _ = ip.rpartition(".")
        return head if sep else ip
    try:
        return "6:" + ipaddress.IPv6Address(ip).packed[:6].hex()
    except ValueError:
        return ip


class BackoffState:
    """Allowed simultaneous connections to one network. Pure: the caller passes the time.

    ``timeout_threshold`` consecutive timeouts, or one 429/503, halve the limit (never below 1). Further bad
    news within ``settle`` seconds of a halving does not halve again: connections that were already in flight
    when the limit dropped must not push it down twice. After ``recover_after`` quiet seconds the limit grows
    by ``step``, up to ``ceiling``. Only time raises it; a successful reply merely clears the timeout streak.
    A Retry-After holds the network (no new connections) for that long, up to ``max_hold`` seconds.
    """

    def __init__(self, ceiling: int, *, timeout_threshold: int = 3, recover_after: float = 120.0, step: int = 1,
                 settle: float = 10.0, max_hold: float = 900.0) -> None:
        self.ceiling = max(1, int(ceiling))
        self.timeout_threshold = max(1, int(timeout_threshold))
        self.recover_after = float(recover_after)
        self.step = max(1, int(step))
        self.settle = float(settle)
        self.max_hold = float(max_hold)
        self._limit = self.ceiling
        self._streak = 0
        self._changed: float | None = None      # last halving, then the last step up
        self._halved_at: float | None = None
        self._hold_until = float("-inf")

    def limit(self, now: float) -> int:
        """Connections allowed now (recovery is applied here, from the time that has passed)."""
        if self._limit < self.ceiling and self._changed is not None and self.recover_after > 0:
            periods = int((now - self._changed) // self.recover_after)
            if periods > 0:
                self._limit = min(self.ceiling, self._limit + periods * self.step)
                self._changed = None if self._limit >= self.ceiling else self._changed + periods * self.recover_after
        return self._limit

    def held(self, now: float) -> bool:
        return now < self._hold_until

    def idle(self, now: float) -> bool:
        """Back at full strength with nothing pending: the record can be dropped."""
        return self.limit(now) >= self.ceiling and not self.held(now) and self._streak == 0

    def _halve(self, now: float) -> None:
        self.limit(now)
        self._streak = 0
        if self._halved_at is not None and now - self._halved_at < self.settle:
            return
        self._limit = max(1, self._limit // 2)
        self._halved_at = self._changed = now

    def timed_out(self, now: float) -> None:
        self._streak += 1
        if self._streak >= self.timeout_threshold:
            self._halve(now)

    def throttled(self, now: float, retry_after: float | None = None) -> None:
        """A 429 or 503 from the network."""
        self._halve(now)
        if retry_after is not None and retry_after > 0:
            self._hold_until = max(self._hold_until, now + min(float(retry_after), self.max_hold))

    def answered(self, now: float) -> None:
        self._streak = 0


class SubnetLimiter:
    """At most ``cap`` simultaneous connections per /24 (IPv4) or /48 (IPv6), lowered per network by back-off.

    ``try_acquire`` takes slots for several networks at once or for none. A request for more slots than the
    current limit is admitted when the network has nothing in flight, so a limit that fell after the work was
    cut into batches slows it down without stalling it. Memory follows the networks in use: counters are
    dropped when they reach zero and back-off records once the network has recovered.
    """

    def __init__(self, cap: int, *, now: Callable[[], float] = time.monotonic,
                 key_of: Callable[[str], str] = network_key, **backoff: Any) -> None:
        self.cap = max(1, int(cap))
        self._now, self.key_of, self._backoff = now, key_of, backoff
        self._active: dict[str, int] = {}
        self._states: dict[str, BackoffState] = {}
        self._lock = threading.Lock()
        self._releases = 0

    def counts(self, ips: Iterable[str]) -> dict[str, int]:
        out: dict[str, int] = {}
        for ip in ips:
            k = self.key_of(ip)
            out[k] = out.get(k, 0) + 1
        return out

    def limit_for(self, ip: str) -> int:
        with self._lock:
            return self._limit_locked(self.key_of(ip), self._now())

    def _limit_locked(self, key: str, now: float) -> int:
        state = self._states.get(key)
        return self.cap if state is None else state.limit(now)

    def in_flight(self, ip: str) -> int:
        with self._lock:
            return self._active.get(self.key_of(ip), 0)

    def tracked(self) -> tuple[int, int]:
        """(networks with connections open, networks with a back-off record): what the limiter keeps in memory."""
        with self._lock:
            return len(self._active), len(self._states)

    def try_acquire(self, counts: Mapping[str, int]) -> bool:
        """Take the slots without waiting; False (nothing taken) if any network is full or held."""
        with self._lock:
            now = self._now()
            for key, n in counts.items():
                state = self._states.get(key)
                if state is not None and state.held(now):
                    return False
                active = self._active.get(key, 0)
                if active > 0 and active + n > self._limit_locked(key, now):
                    return False
            for key, n in counts.items():
                total = self._active.get(key, 0) + n
                self._active[key] = total
                if total > max(self.cap, n):
                    _violation(f"network {key} has {total} connections in flight, above the cap of {self.cap}")
            return True

    def acquire(self, counts: Mapping[str, int], killed: Callable[[], bool] = lambda: False, stop_event: Any = None,
                sleep: Callable[[float], None] = time.sleep, poll: float = _LIMIT_POLL) -> bool:
        """Wait for the slots. False means a stop condition fired first."""
        while True:
            if killed() or (stop_event is not None and stop_event.is_set()):
                return False
            if self.try_acquire(counts):
                return True
            _nap(poll, sleep, stop_event)

    def release(self, counts: Mapping[str, int]) -> None:
        with self._lock:
            for key, n in counts.items():
                left = self._active.get(key, 0) - n
                if left < 0:
                    _violation(f"network {key} released more connections than were taken")
                if left > 0:
                    self._active[key] = left
                else:
                    self._active.pop(key, None)
            self._releases += 1
            if self._releases % _PRUNE_EVERY == 0:
                self._sweep_locked(self._now())

    def _sweep_locked(self, now: float) -> None:
        for key in [k for k, st in self._states.items() if k not in self._active and st.idle(now)]:
            del self._states[key]

    def sweep(self) -> None:
        """Drop the back-off records of networks that have recovered."""
        with self._lock:
            self._sweep_locked(self._now())

    def observe(self, ip: str, *, timeout: bool = False, http_status: int | None = None,
                retry_after: float | None = None) -> None:
        """Report how a connection to ``ip`` ended. Bad news can only lower the limit, never raise it."""
        throttled = http_status in (429, 503)
        key = self.key_of(ip)
        with self._lock:
            now = self._now()
            if timeout or throttled:
                state = self._states.get(key)
                if state is None:
                    state = self._states[key] = BackoffState(self.cap, **self._backoff)
                if throttled:
                    state.throttled(now, retry_after)
                else:
                    state.timed_out(now)
            elif key in self._states:
                self._states[key].answered(now)

    def observe_outcome(self, ip: str, outcome: str | None, http_status: int | None, retry_after: float | None) -> None:
        self.observe(ip, timeout=outcome == "timeout", http_status=http_status, retry_after=retry_after)

    def observe_results(self, results: Iterable[Any]) -> None:
        """ZGrab results (TLS or HTTP): timeouts by their zgrab status, 429/503 by their HTTP status."""
        for r in results:
            ip = getattr(r, "ip", None) or getattr(r, "target_ip", None)
            if not ip:
                continue
            status = getattr(r, "zgrab_status", None) or getattr(r, "status", None)
            self.observe(ip, timeout=status in ("connection-timeout", "io-timeout"), http_status=getattr(r, "http_status", None))


def split_by_network(items: list[T], ip_of: Callable[[T], str], key_of: Callable[[str], str], cap: int) -> list[list[T]]:
    """Group i holds items i*cap to i*cap+cap-1 of every network, so no group has more than ``cap`` of one network."""
    groups: list[list[T]] = []
    seen: dict[str, int] = {}
    for item in items:
        key = key_of(ip_of(item))
        n = seen.get(key, 0)
        seen[key] = n + 1
        while n // cap >= len(groups):
            groups.append([])
        groups[n // cap].append(item)
    return groups


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
                 now: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 stop_event: Any = None, limiter: SubnetLimiter | None = None) -> None:
        self.seconds = float(seconds)
        self._killed, self._now, self._sleep, self._stop = killed, now, sleep, stop_event
        self.limiter = limiter          # a claim also needs room in each network (lock order: ledger, then limiter)
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
            return not (self._killed() or (self._stop is not None and self._stop.is_set()))
        deadline = self.ready_at(list(ips))
        return _sleep_until(deadline, self._killed, self._now, self._sleep, self._stop)

    def claim(self, ips: list[str], extra: Callable[[float], bool] | None = None) -> bool:
        """Block until every address is due and none is in flight, then mark them in flight. False on a stop."""
        while True:
            if self._killed() or (self._stop is not None and self._stop.is_set()):
                return False
            with self._lock:
                now = self._now()
                free = not any(ip in self._busy for ip in ips)
                due = self.seconds <= 0 or max((self._due(ip) for ip in ips), default=float("-inf")) <= now
                if (free and due and (extra is None or extra(now))
                        and (self.limiter is None or self.limiter.try_acquire(self.limiter.counts(ips)))):
                    for ip in ips:
                        last = self._last.get(ip)
                        if self.seconds > 0 and last is not None and now - last < self.seconds - 1e-6:
                            _violation(f"{ip} contacted {now - last:.3f} s after its last contact, below the pause of {self.seconds:g} s")
                        if ip in self._busy:
                            _violation(f"{ip} claimed while already in flight")
                    self._busy.update(ips)
                    return True
                wait = max((self._due(ip) for ip in ips), default=now) - now if free and not due else _SLICE
            _nap(min(_SLICE, max(wait, 0.01)), self._sleep, self._stop)

    def release(self, ips: list[str]) -> None:
        with self._lock:
            end = self._now()
            for ip in ips:
                self._last[ip] = end
                self._busy.discard(ip)
        if self.limiter is not None:
            self.limiter.release(self.limiter.counts(ips))

    def observe(self, results: Iterable[Any]) -> None:
        """Pass finished ZGrab results to the limiter so a struggling network gets fewer connections."""
        if self.limiter is not None:
            self.limiter.observe_results(results)


def paced_batches(items: list[T], ip_of: Callable[[T], str], ledger: ContactLedger,
                  run_batch: Callable[[list[T]], Any], *, batch_size: int, workers: int = 1,
                  extra: Callable[[list[T]], Callable[[float], bool] | None] | None = None,
                  group_of: Callable[[T], Any] | None = None,
                  reuse: Callable[[list[T]], Any] | None = None) -> list[Any]:
    """Like ``paced_rounds`` but each batch waits only for its own addresses, and up to ``workers`` run at once.

    Batches are the rounds of ``split_rounds`` cut into ``batch_size`` pieces, so their composition never depends
    on timing. Results come back in batch order. ``extra`` may add a per-batch admission check (see overlap.py).
    Stops starting new batches once a stop condition fires.

    ``group_of`` keeps every batch within one group (the port, for ZGrab2): the groups are batched one after the other
    in ascending order. ``reuse(batch)`` returns the stored result of a batch that was already run by an earlier
    attempt, or None; such a batch contacts nothing, so it neither claims its addresses nor starts the pause clock.
    """
    from concurrent.futures import ThreadPoolExecutor

    size = max(1, batch_size)
    if group_of is None:
        rounds = split_rounds(items, ip_of)
    else:
        by_group: dict[Any, list[T]] = {}
        for item in items:
            by_group.setdefault(group_of(item), []).append(item)
        rounds = [r for key in sorted(by_group) for r in split_rounds(by_group[key], ip_of)]
    if ledger.limiter is not None:       # a batch holds at most `cap` addresses of one network, whatever the timing
        rounds = [g for r in rounds for g in split_by_network(r, ip_of, ledger.limiter.key_of, ledger.limiter.cap)]
    batches = [r[i:i + size] for r in rounds for i in range(0, len(r), size)]
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
            kept = reuse(batch) if reuse is not None else None
            if kept is not None:
                started[i] = True
                results[i] = kept
                continue
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
