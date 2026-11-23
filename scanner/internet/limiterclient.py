"""Client of the connection limiter daemon (``limiterd``), with the interface of ``SubnetLimiter``.

``ContactLedger``, ``IpPacer`` and the favicon stage use it in place of an in-process limiter. It fails closed: while
the daemon cannot be reached every claim is refused, so callers keep waiting; nothing is ever sent unlimited. A failed
call closes the connection and the next attempt is made after a delay that starts at ``retry_after`` seconds, doubles
up to a cap and is spread by a random factor, so many clients do not come back at the same instant; calls in between
are refused at once without touching the socket.

Two failures are not waited out. A daemon that refuses this client's limits (``LimiterRefused``) is a configuration
error and raised at once, and ``require`` raises if the daemon cannot be reached within its ``wait`` when the client is
made. A daemon that stays unreachable for more than ``outage_limit`` seconds makes the next claim raise
``LimiterOutage``, so the stage ends with an error instead of recording every request as skipped. Callers that wait
for a claim read ``unreachable`` and ``retry_in`` to tell an absent daemon from a busy network: only the second
counts against their ``max_wait``.

One connection serves all threads of the process and carries its leases under the client's id. After a break the
client says in its next ``hello`` what it holds and which addresses it contacted within the last pause, so a daemon
that restarted (or kept the old leases for its grace period) counts them once. ``close`` says goodbye, which frees
them at once.

Large lists are sent in slices (``release``) and the reports of how requests went (``observe``) are queued and sent
by a helper thread in small frames, so no single frame holds the daemon up and no request thread waits for a report.
The timeouts of a frame grow with its size.

Everything this client adds to ``SubnetLimiter`` can only make a caller wait longer, never claim more: a refusal
may be remembered for a moment and a claim that cannot fit under the cap is refused without asking.
"""
from __future__ import annotations

import collections
import logging
import os
import random
import socket
import sys
import threading
import time
from typing import Any, Callable, Iterable, Mapping

from scanner.internet import limiterd as proto
from scanner.internet.pacing import _LIMIT_POLL, _nap, network_key

log = logging.getLogger(__name__)
CONNECT_TIMEOUT = 3.0
IO_TIMEOUT = 4.0            # one frame, plus IO_PER_MB for every megabyte of it, for the send and again for the reply
IO_PER_MB = 1.0
HELLO_TIMEOUT = 10.0        # the hello restates what the client holds, so it is the largest frame; plus 1 s per MB above 3
HELLO_FREE_MB = 3.0
RETRY_AFTER = 0.5           # first delay after a failure; doubles up to RETRY_CAP, each time times a factor of 0.5 to 1.5
RETRY_CAP = 4.0
OUTAGE_LIMIT = 600.0
START_WAIT = 0.0            # how long ``require`` keeps trying when no wait is given
CLOSE_BOUND = 1.0           # reports still queued and the goodbye must be done within this
RELEASE_CHUNK = 2000        # addresses in one release frame
OBSERVE_CHUNK = 1000        # events in one observe frame
OBSERVE_QUEUE = 200_000     # events waiting to be sent; the oldest are dropped (and counted) beyond this
OBSERVE_DELAY = 0.2         # how long a report may wait for company
REFUSAL_TTL = 0.25          # how long a "full" answer for one network is believed
EPISODES = 100
REPORT_EVERY = 60.0
_BAD_STATUS = (429, 503)

ENV_START_WAIT = "SCANNER_LIMITER_START_WAIT"
ENV_OUTAGE_LIMIT = "SCANNER_LIMITER_OUTAGE_LIMIT"


class LimiterUnavailable(OSError):
    """The daemon cannot be reached."""


class LimiterRefused(RuntimeError):
    """The daemon refuses this client for good (limits looser than its own, or another protocol)."""


class LimiterOutage(RuntimeError):
    """The daemon has been unreachable for longer than the outage limit."""


class LimiterClosed(LimiterOutage):
    """A claim or query was made on a client that has been closed. Not recorded as a limiter failure."""


# What went wrong in this process, for the code that decides how a stage ended. A stage that did not finish only
# because the limiter was out of reach is not the stage's fault, and is told apart by this record.
_failures: collections.Counter[str] = collections.Counter()
_failures_lock = threading.Lock()


def note_failure(kind: str) -> None:
    """Record one failure of ``kind`` (``"limiter"`` for ``LimiterOutage`` and ``LimiterUnavailable``)."""
    with _failures_lock:
        _failures[str(kind)] += 1


def failure_kinds() -> dict[str, int]:
    """The failures recorded in this process so far: kind -> how many."""
    with _failures_lock:
        return dict(_failures)


def reset_failures() -> None:
    with _failures_lock:
        _failures.clear()


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError:
        log.warning("%s=%r is not a number, using %g", name, raw, default)
        return default
    if value != value or value < 0:
        log.warning("%s=%r is not a usable number of seconds, using %g", name, raw, default)
        return default
    return value


def start_wait_from_env() -> float:
    """How long a starting process keeps trying to reach the daemon (``SCANNER_LIMITER_START_WAIT``, default none)."""
    return _env_float(ENV_START_WAIT, START_WAIT)


class LimiterClient:
    """Drop-in for ``SubnetLimiter`` backed by the daemon at ``path``.

    ``cap`` and ``gap`` are the limits this process is configured with: the daemon refuses a client whose limits are
    stricter than its own. ``cap`` is also what ``split_by_network`` uses to size groups of one network.
    ``outage_limit`` defaults to ``SCANNER_LIMITER_OUTAGE_LIMIT`` or ``OUTAGE_LIMIT``. ``rng`` returns a float in
    [0, 1) and spreads the reconnect delays.
    """

    def __init__(self, path: str, cap: int, gap: float, *, key_of: Callable[[str], str] = network_key,
                 connect_timeout: float = CONNECT_TIMEOUT, io_timeout: float = IO_TIMEOUT, retry_after: float = RETRY_AFTER,
                 outage_limit: float | None = None, now: Callable[[], float] = time.monotonic,
                 hello_timeout: float | None = None, rng: Callable[[], float] = random.random) -> None:
        self.path, self.cap, self.gap = str(path), max(1, int(cap)), float(gap)
        self.key_of = key_of
        self._connect_timeout, self._io_timeout, self._retry_after, self._now = connect_timeout, io_timeout, retry_after, now
        self._hello_timeout = float(hello_timeout) if hello_timeout is not None else HELLO_TIMEOUT * io_timeout / IO_TIMEOUT
        self._rng = rng
        self._retry_cap = max(retry_after, min(RETRY_CAP, retry_after * 8))     # 4 s for the default first delay
        self._delay: float | None = None            # the last reconnect delay, before its random factor
        self.outage_limit = float(outage_limit) if outage_limit is not None else _env_float(ENV_OUTAGE_LIMIT, OUTAGE_LIMIT)
        self._id = f"{os.getpid()}-{os.urandom(8).hex()}"
        self._down_since: float | None = None       # when the daemon was last seen failing, until a call succeeds
        self._refused: LimiterRefused | None = None
        self._held_counts: dict[str, int] = {}      # slots held per network, as the daemon should have them
        self._held_ips: set[str] = set()            # addresses claimed as exclusive and not yet released
        self._recent_limit = 4096
        self._recent: dict[str, float] = {}         # address -> when it was last contacted (monotonic), for the last pause
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()           # one request at a time on the socket
        self._down_until = float("-inf")
        self._tickets = 0
        self._queued: set[int] = set()          # tickets the daemon has seen and may still hold a place for
        self._state = threading.Lock()
        self._full: dict[str, float] = {}       # network -> until when its "full" answer is believed
        self._ttl = 0.0
        self._closed = threading.Event()
        self._keepalive: threading.Thread | None = None
        self._last_error = ""
        # what happened while the daemon was out of reach
        self._failed_attempts = 0
        self._notes: list[tuple[int, str, tuple]] = []      # log lines gathered under the socket lock, written after it
        self._episodes: collections.deque[float] = collections.deque(maxlen=EPISODES)
        # one line of numbers per minute on the standard error
        self._tally: dict[str, float] = collections.defaultdict(float)
        self._failure_classes: collections.Counter[str] = collections.Counter()
        self._reported = time.monotonic()
        # reports of how requests went
        self._obs: collections.deque[dict[str, Any]] = collections.deque()
        self._obs_bad = 0                       # events in the queue that call for a prompt report
        self._obs_since = 0.0
        self._obs_cv = threading.Condition()
        self._obs_send = threading.Lock()       # whoever takes events off the queue also sends them: order is kept
        self._obs_thread: threading.Thread | None = None
        self._obs_closing = False
        self.observe_dropped = 0                # events dropped because the queue was full
        self.observe_lost = 0                   # events taken off the queue that the daemon never received

    # transport

    def _connect(self, limit: float | None = None) -> socket.socket:
        if not hasattr(socket, "AF_UNIX"):
            raise LimiterUnavailable("Unix domain sockets are not available on this platform")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            began = time.monotonic()
            s.settimeout(self._connect_timeout if limit is None else max(0.01, min(self._connect_timeout, limit)))
            s.connect(self.path)
            self._tally["connect_s"] += time.monotonic() - began
            reply = self._exchange(s, self._hello(), hello=True, limit=limit)
        except BaseException:
            s.close()
            raise
        if not reply.get("ok"):
            s.close()
            if reply.get("fatal"):
                raise LimiterRefused(f"limiter at {self.path} refuses this client: {reply.get('error', 'refused')}")
            raise LimiterUnavailable(str(reply.get("error", "refused")))
        self._ttl = float(reply.get("lease_ttl", 0.0))
        with self._state:
            self._full.clear()
        return s

    def _hello(self) -> dict[str, Any]:
        now = self._now()
        with self._state:
            for ip in [ip for ip, at in self._recent.items() if now - at >= self.gap]:
                del self._recent[ip]
            return {"op": "hello", "protocol": proto.PROTOCOL, "cap": self.cap, "gap": self.gap, "client": self._id,
                    "held": dict(self._held_counts), "busy": sorted(self._held_ips),
                    "recent": {ip: now - at for ip, at in self._recent.items()}}

    def _exchange(self, s: socket.socket, message: dict[str, Any], *, hello: bool = False,
                  limit: float | None = None) -> dict[str, Any]:
        """Send one frame and read the reply. The time allowed grows with the size of the frame in each direction;
        ``limit`` bounds every step (the goodbye of ``close``)."""
        base = self._hello_timeout if hello else self._io_timeout

        def allowed(size: int) -> float:
            mb = size / 1e6
            seconds = base + (max(0.0, mb - HELLO_FREE_MB) if hello else mb * IO_PER_MB)
            return seconds if limit is None else max(0.01, min(seconds, limit))

        data = proto.pack_frame(message)
        began = time.monotonic()
        s.settimeout(allowed(len(data)))
        s.sendall(data)
        sent = time.monotonic()
        s.settimeout(allowed(0))
        size = proto.unpack_length(_read(s, 4))
        s.settimeout(allowed(size))
        reply = proto.decode_frame(_read(s, size))
        done = time.monotonic()
        t = self._tally
        t["send_s"] += sent - began
        t["recv_s"] += done - sent
        t["bytes_out"] += len(data)
        t["bytes_in"] += size + 4
        return reply

    def _after_close(self, strict: bool) -> None:
        """A closed client sends nothing and never reconnects. A claim or query on it is an error, not a refusal:
        a caller that counted it against ``max_wait`` would end by skipping work without saying why."""
        if strict:
            raise LimiterClosed(f"the limiter client for {self.path} is closed")
        return None

    def _call(self, message: dict[str, Any], strict: bool = False,
              on_ok: Callable[[dict[str, Any]], None] | None = None, limit: float | None = None,
              lenient: bool = False) -> dict[str, Any] | None:
        """One request and its reply; None if the daemon is unreachable (the caller must then refuse).

        ``on_ok`` runs under the socket lock once the reply is in, so a reconnect never describes a state that
        lacks a grant the daemon has made. ``strict`` calls (claims and queries) raise ``LimiterOutage`` once the
        daemon has been down for ``outage_limit`` seconds; a daemon that refuses the client for good always raises.
        ``limit`` bounds the whole call, including the wait for the socket lock. ``lenient``: a reply that says the
        request was bad (not ok) is not a sign that the daemon is out of reach."""
        if self._refused is not None:
            raise self._refused
        if self._closed.is_set():
            return self._after_close(strict)
        waited = time.monotonic()
        if limit is None:
            self._lock.acquire()
        elif not self._lock.acquire(timeout=max(0.0, limit)):
            return None
        line = None
        try:
            if self._closed.is_set():
                return self._after_close(strict)
            self._tally["lock_wait_s"] += time.monotonic() - waited
            self._tally["calls"] += 1
            return self._call_locked(message, strict, on_ok, None if limit is None else max(0.01, limit - (time.monotonic() - waited)),
                                     lenient)
        finally:
            line = self._report()
            notes, self._notes = self._notes, []
            self._lock.release()
            self._emit(line, notes)

    def _call_locked(self, message: dict[str, Any], strict: bool, on_ok: Callable[[dict[str, Any]], None] | None,
                     limit: float | None, lenient: bool) -> dict[str, Any] | None:
        now = self._now()
        if now < self._down_until:
            self._check_outage(now, strict)
            return None
        try:
            if self._sock is None:
                self._sock = self._connect(limit)
            reply = self._exchange(self._sock, message, limit=limit)
        except LimiterRefused as exc:
            self._refused = exc
            raise
        except (OSError, ValueError) as exc:
            self._drop(exc)
            self._check_outage(self._now(), strict)
            return None
        if not reply.get("ok"):
            if lenient:
                return None
            self._drop(LimiterUnavailable(str(reply.get("error", "refused"))))
            self._check_outage(self._now(), strict)
            return None
        if self._down_since is not None:
            self._recovered()
        self._delay = None
        if on_ok is not None:
            on_ok(reply)
        return reply

    @staticmethod
    def _emit(line: str | None, notes: list[tuple[int, str, tuple]]) -> None:
        """Log and print what was gathered under the socket lock, now that it is released."""
        for level, fmt, args in notes:
            log.log(level, fmt, *args)
        if line:
            try:
                print(line, file=sys.stderr, flush=True)
            except (OSError, ValueError):
                pass

    def _check_outage(self, now: float, strict: bool) -> None:
        if strict and self._down_since is not None and now - self._down_since > self.outage_limit:
            note_failure("limiter")
            raise LimiterOutage(f"limiter at {self.path} unreachable for {now - self._down_since:.0f} s "
                                f"(limit {self.outage_limit:g} s): {self._last_error}")

    def _recovered(self) -> None:
        """The daemon answers again: say how long it was out of reach (under the socket lock)."""
        length = max(0.0, self._now() - (self._down_since or 0.0))
        self._episodes.append(length)
        self._notes.append((logging.INFO, "limiter at %s reachable again after %.1f s and %d failed attempts, last error: %s",
                            (self.path, length, self._failed_attempts, self._last_error or "none")))
        self._down_since = None
        self._failed_attempts = 0

    def episodes(self) -> list[float]:
        """The lengths in seconds of the last outages, oldest first (at most ``EPISODES``)."""
        return list(self._episodes)

    def _report(self) -> str | None:
        """Once per ``REPORT_EVERY`` seconds, one line of per-call numbers for the standard error. Built under the
        socket lock; the caller writes it after releasing the lock, so a blocked stream cannot hold up requests."""
        now = time.monotonic()
        if now - self._reported < REPORT_EVERY:
            return None
        t, self._tally = self._tally, collections.defaultdict(float)
        failed, self._failure_classes = self._failure_classes, collections.Counter()
        span, self._reported = now - self._reported, now
        if not t.get("calls"):
            return None
        return (f"limiter client {self._id}: {span:.0f} s calls={t['calls']:.0f} lock_wait={t['lock_wait_s']:.2f}s "
                f"connect={t['connect_s']:.2f}s send={t['send_s']:.2f}s recv={t['recv_s']:.2f}s "
                f"bytes_out={t['bytes_out']:.0f} bytes_in={t['bytes_in']:.0f} "
                f"failures={dict(failed) if failed else 0} observe_dropped={self.observe_dropped} observe_lost={self.observe_lost}")

    def unreachable(self) -> bool:
        """True from the first failed call until a call succeeds."""
        return self._down_since is not None

    def retry_in(self) -> float:
        """Seconds until the next attempt to reach the daemon is made (0 when one is due)."""
        return max(0.0, self._down_until - self._now())

    def require(self, wait: float = START_WAIT) -> None:
        """Raise if the daemon cannot be reached, or refuses this client. With ``wait`` > 0, keep trying at the
        reconnect delay for up to that many seconds first; a daemon that refuses the client is never retried."""
        deadline = time.monotonic() + max(0.0, float(wait))
        while True:
            if self._call({"op": "ping"}) is not None:
                return
            left = deadline - time.monotonic()
            if left <= 0 or self._closed.is_set():
                note_failure("limiter")
                raise LimiterUnavailable(f"no limiter daemon answers at {self.path}: {self._last_error or 'unreachable'}")
            self._closed.wait(min(max(self.retry_in(), 0.05), left))

    def _drop(self, exc: BaseException) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        now = self._now()
        self._delay = self._retry_after if self._delay is None else min(self._delay * 2.0, self._retry_cap)
        self._down_until = now + self._delay * (0.5 + self._rng())
        if self._down_since is None:
            self._down_since = now
        self._failed_attempts += 1
        self._failure_classes[type(exc).__name__] += 1
        text = f"{type(exc).__name__}: {exc}"
        if text != self._last_error:        # say it once per kind of failure, not on every retry
            self._last_error = text
            self._notes.append((logging.WARNING, "limiter at %s unavailable, requests wait: %s", (self.path, text)))

    def close(self) -> None:
        """Send what is still queued, say goodbye (the daemon frees every lease at once) and disconnect, all within
        ``CLOSE_BOUND`` seconds."""
        deadline = time.monotonic() + CLOSE_BOUND
        self.flush(CLOSE_BOUND, closing=True)
        self._closed.set()
        with self._obs_cv:
            self._obs_cv.notify_all()
        left = max(0.01, deadline - time.monotonic())
        if not self._lock.acquire(timeout=left):
            sock = self._sock
            if sock is not None:            # a call is stuck on the socket: cut it, the daemon keeps the leases for its grace
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            return
        try:
            if self._sock is not None:
                try:
                    self._exchange(self._sock, {"op": "goodbye"}, limit=max(0.01, deadline - time.monotonic()))
                except (OSError, ValueError):
                    pass
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
        finally:
            self._lock.release()

    def ping(self) -> bool:
        return self._call({"op": "ping"}) is not None

    def _forget_refusals(self) -> None:
        with self._state:
            self._full.clear()

    def stats(self) -> dict[str, Any] | None:
        self.flush(2.0)
        self._forget_refusals()
        reply = self._call({"op": "stats"})
        return None if reply is None else {k: v for k, v in reply.items() if k != "ok"}

    def _ping_while_holding(self) -> None:
        while not self._closed.wait(max(self._ttl / 3.0, 1.0)):
            if self._held_counts:
                try:
                    self._call({"op": "ping"})
                except (LimiterRefused, LimiterOutage):
                    return

    def _granted(self, counts: Mapping[str, int], ips: Iterable[str], exclusive: bool) -> None:
        """Remember a grant (under the socket lock, from ``_call``)."""
        now = self._now()
        with self._state:
            self._full.clear()
            for key, n in counts.items():
                self._held_counts[key] = self._held_counts.get(key, 0) + n
            for ip in ips:
                self._recent[ip] = now
                if exclusive:
                    self._held_ips.add(ip)
            if len(self._recent) > self._recent_limit:      # amortised: only when the table has doubled
                self._recent = {ip: at for ip, at in self._recent.items() if now - at < self.gap}
                self._recent_limit = max(4096, 2 * len(self._recent))
            if self._keepalive is None and self._ttl > 0:
                self._keepalive = threading.Thread(target=self._ping_while_holding, name="limiter-keepalive", daemon=True)
                self._keepalive.start()

    # the SubnetLimiter interface

    def ticket(self) -> int:
        with self._state:
            self._tickets += 1
            return self._tickets

    def withdraw(self, ticket: int | None) -> None:
        if ticket is None:
            return
        with self._state:
            queued = ticket in self._queued
            self._queued.discard(ticket)
        if queued:
            self._call({"op": "withdraw", "ticket": ticket})

    def counts(self, ips: Iterable[str]) -> dict[str, int]:
        out: dict[str, int] = {}
        for ip in ips:
            k = self.key_of(ip)
            out[k] = out.get(k, 0) + 1
        return out

    def _refuse_locally(self, counts: Mapping[str, int]) -> float | None:
        """Seconds to wait if a claim without a ticket would surely be refused, else None.

        Two cases, both sound because the daemon's limit for a network is never above this client's cap and counts
        everything this client holds: the claim does not fit under the cap next to what is already held, or the
        daemon said "full" for the network a moment ago. This only ever refuses; a grant is the daemon's alone."""
        if self._down_since is not None:        # let the call find out, and end in an outage if it has lasted
            return None
        now = self._now()
        with self._state:
            for key, n in counts.items():
                if self._held_counts.get(key, 0) + n > self.cap:
                    return REFUSAL_TTL
            for key in counts:
                until = self._full.get(key)
                if until is not None:
                    if until > now:
                        return until - now
                    del self._full[key]
        return None

    def _claim_reply(self, message: dict[str, Any], ticket: int | None, counts: Mapping[str, int],
                     ips: Iterable[str] = (), exclusive: bool = False, partial: bool = False) -> dict[str, Any] | None:
        """The daemon's reply to a claim (granted or not), None if it cannot be reached."""
        def granted(reply: dict[str, Any]) -> None:
            if reply.get("granted"):
                got = [ip for ip in reply.get("ips") or [] if isinstance(ip, str)] if partial else list(ips)
                self._granted(self.counts(got) if partial or ips else counts, got, exclusive)

        if self._closed.is_set():
            self._after_close(True)
        if ticket is None and not partial:
            need = counts if counts else self.counts(ips)
            wait = self._refuse_locally(need)
            if wait is not None:
                return {"ok": True, "granted": False, "reason": "full", "wait": wait, "local": True}
        reply = self._call({"op": "claim", "ticket": ticket, "exclusive": exclusive, **message}, strict=True, on_ok=granted)
        if reply is not None and not reply.get("granted") and ticket is None and not partial and reply.get("reason") == "full":
            need = counts if counts else self.counts(ips)
            if len(need) == 1 and sum(need.values()) == 1:      # one slot refused: any claim on this network is
                with self._state:
                    self._full[next(iter(need))] = self._now() + REFUSAL_TTL
        if ticket is not None:
            with self._state:
                if reply is not None and reply.get("granted"):
                    self._queued.discard(ticket)
                elif reply is not None:
                    self._queued.add(ticket)
        return reply

    def _claim(self, message: dict[str, Any], ticket: int | None, counts: Mapping[str, int],
               ips: Iterable[str] = (), exclusive: bool = False, partial: bool = False) -> dict[str, Any] | None:
        reply = self._claim_reply(message, ticket, counts, ips, exclusive, partial)
        return reply if reply is not None and reply.get("granted") else None

    def _hint(self, reply: dict[str, Any] | None) -> tuple[str | None, float]:
        """Why a claim was refused and how long the daemon says to wait: (reason, seconds)."""
        if reply is None:
            return "down", self.retry_in()
        reason = reply.get("reason")
        try:
            wait = max(0.0, float(reply.get("wait") or 0.0))
        except (TypeError, ValueError):
            wait = 0.0
        return (reason if isinstance(reason, str) else None), wait

    def try_acquire(self, counts: Mapping[str, int], ticket: int | None = None, ips: list[str] | None = None,
                    exclusive: bool = False) -> bool:
        """Take the slots (and, with ``ips``, their pause) in one step or not at all; False if refused or unreachable."""
        return self.try_acquire_hint(counts, ticket, ips, exclusive)[0]

    def try_acquire_hint(self, counts: Mapping[str, int], ticket: int | None = None, ips: list[str] | None = None,
                         exclusive: bool = False) -> tuple[bool, str | None, float]:
        """Like ``try_acquire`` but also says why a refused claim was refused (``full``, ``gap``, ``startup``, or
        ``down`` when the daemon cannot be reached) and for how long the daemon says to wait; (reason None, 0.0)
        when the daemon gave none. The hint is only for choosing when to ask again."""
        message: dict[str, Any] = {}
        if ips is not None:
            message["ips"] = list(ips)
        else:
            message["counts"] = dict(counts)
        reply = self._claim_reply(message, ticket, {k: n for k, n in counts.items() if n > 0}, ips or (), exclusive)
        if reply is not None and reply.get("granted"):
            return True, None, 0.0
        reason, wait = self._hint(reply)
        return False, reason, wait

    def try_acquire_some(self, ips: list[str], ticket: int | None = None, exclusive: bool = False) -> list[str]:
        """The addresses whose network has room and whose pause is over, taken now; the rest are left to the caller."""
        return self.try_acquire_some_hint(ips, ticket, exclusive)[0]

    def try_acquire_some_hint(self, ips: list[str], ticket: int | None = None,
                              exclusive: bool = False) -> tuple[list[str], str | None, float]:
        """Like ``try_acquire_some`` with the reason and wait of ``try_acquire_hint`` when nothing was taken."""
        reply = self._claim_reply({"ips": list(ips), "partial": True}, ticket, {}, (), exclusive, partial=True)
        if reply is not None and reply.get("granted"):
            return [ip for ip in reply.get("ips") or [] if isinstance(ip, str)], None, 0.0
        reason, wait = self._hint(reply)
        return [], reason, wait

    def acquire(self, counts: Mapping[str, int], killed: Callable[[], bool] = lambda: False, stop_event: Any = None,
                sleep: Callable[[float], None] = time.sleep, poll: float = _LIMIT_POLL) -> bool:
        """Wait for the slots. False means a stop condition fired first."""
        ticket = self.ticket()
        try:
            while True:
                if killed() or (stop_event is not None and stop_event.is_set()):
                    return False
                if self.try_acquire(counts, ticket):
                    return True
                _nap(poll, sleep, stop_event)
        finally:
            self.withdraw(ticket)

    def release(self, counts: Mapping[str, int], ips: Iterable[str] | None = None) -> None:
        """Give the slots back. If the daemon is gone it has freed them with the connection.

        The local record is changed first. The addresses go in slices of ``RELEASE_CHUNK``; if a slice fails the
        rest is not sent, and the daemon frees what is left when this client says hello again or after its grace."""
        ips = list(ips) if ips is not None else []
        frames = [(dict(counts), ips[:RELEASE_CHUNK])]
        frames += [({}, ips[start:start + RELEASE_CHUNK]) for start in range(RELEASE_CHUNK, len(ips), RELEASE_CHUNK)]
        lowered = [False] * len(frames)

        def lower(i: int) -> None:
            if not lowered[i]:
                lowered[i] = True
                self._lower(*frames[i])

        try:
            for i, (held, part) in enumerate(frames):
                # The record is lowered only after the call that carries it, and under the socket lock once the
                # reply is in: a hello built while that call reconnects still describes what the frame is about to
                # release, so the daemon subtracts it once, and none built later describes it again.
                try:
                    sent = self._call({"op": "release", "counts": held, "ips": part},
                                      on_ok=lambda _reply, i=i: lower(i)) is not None
                finally:
                    lower(i)
                if not sent:
                    return
        finally:
            for i in range(len(frames)):        # not sent: the daemon frees them at the next hello or after its grace
                lower(i)

    def _lower(self, counts: Mapping[str, int], ips: Iterable[str]) -> None:
        now = self._now()
        with self._state:
            self._full.clear()
            for key, n in counts.items():
                left = self._held_counts.get(key, 0) - n
                if left > 0:
                    self._held_counts[key] = left
                else:
                    self._held_counts.pop(key, None)
            for ip in ips:
                self._held_ips.discard(ip)
                self._recent[ip] = now          # the pause of a claimed address runs from the end of the request

    # reports of how requests went

    def observe(self, ip: str, *, timeout: bool = False, http_status: int | None = None, retry_after: float | None = None) -> None:
        self._observe([{"ip": ip, "timeout": timeout, "http_status": http_status, "retry_after": retry_after}])

    @staticmethod
    def _is_bad_news(event: Mapping[str, Any]) -> bool:
        return bool(event.get("timeout")) or event.get("http_status") in _BAD_STATUS

    def _observe(self, events: list[dict[str, Any]]) -> None:
        """Queue the events; a helper thread sends them. A report that is lost only delays a back-off."""
        if not events or self._closed.is_set():
            return
        with self._obs_cv:
            if self._obs_closing:
                return
            if not self._obs:
                self._obs_since = time.monotonic()
            for ev in events:
                if len(self._obs) >= OBSERVE_QUEUE:
                    if self._is_bad_news(self._obs.popleft()):
                        self._obs_bad -= 1
                    self.observe_dropped += 1
                self._obs.append(ev)
                if self._is_bad_news(ev):
                    self._obs_bad += 1
            if self._obs_thread is None:
                self._obs_thread = threading.Thread(target=self._flusher, name="limiter-observe", daemon=True)
                self._obs_thread.start()
            self._obs_cv.notify()

    def _flusher(self) -> None:
        try:
            while True:
                with self._obs_cv:
                    while True:
                        if self._closed.is_set():
                            return
                        if not self._obs:
                            self._obs_cv.wait(1.0)
                            continue
                        if self._obs_bad or len(self._obs) >= OBSERVE_CHUNK:
                            break
                        left = self._obs_since + OBSERVE_DELAY - time.monotonic()
                        if left <= 0:
                            break
                        self._obs_cv.wait(left)
                try:
                    self._send_observed(None)
                except LimiterRefused:
                    return
                except Exception:       # the chunk is already counted as lost; the thread keeps serving the queue
                    log.exception("limiter observe: a chunk could not be sent")
        except Exception:
            log.exception("limiter observe thread stopped")

    def _send_observed(self, deadline: float | None) -> bool:
        """Take up to ``OBSERVE_CHUNK`` events off the queue and send them; False if there were none (or no time)."""
        if deadline is None:
            self._obs_send.acquire()
        elif not self._obs_send.acquire(timeout=max(0.0, deadline - time.monotonic())):
            return False
        try:
            with self._obs_cv:
                if not self._obs:
                    return False
                chunk = [self._obs.popleft() for _ in range(min(OBSERVE_CHUNK, len(self._obs)))]
                self._obs_bad -= sum(1 for ev in chunk if self._is_bad_news(ev))
                self._obs_since = time.monotonic()
            limit = None if deadline is None else max(0.01, deadline - time.monotonic())
            try:
                sent = self._call({"op": "observe", "events": chunk}, limit=limit, lenient=True) is not None
            except LimiterRefused:
                self.observe_lost += len(chunk)
                raise
            except Exception:           # an event that cannot be encoded: drop this chunk, keep the connection
                self.observe_lost += len(chunk)
                log.exception("limiter observe: dropped %d events that could not be sent", len(chunk))
                return True
            if not sent:
                self.observe_lost += len(chunk)
            return True
        finally:
            self._obs_send.release()

    def flush(self, timeout: float = CLOSE_BOUND, closing: bool = False) -> None:
        """Send the queued reports now, for at most ``timeout`` seconds."""
        deadline = time.monotonic() + timeout
        if closing:
            with self._obs_cv:
                self._obs_closing = True
        while time.monotonic() < deadline and self._obs:
            try:
                if not self._send_observed(deadline):
                    break
            except LimiterRefused:
                return
        if self._obs_send.acquire(timeout=max(0.0, deadline - time.monotonic())):      # one the helper has in hand
            self._obs_send.release()

    def observe_outcome(self, ip: str, outcome: str | None, http_status: int | None, retry_after: float | None) -> None:
        self.observe(ip, timeout=outcome == "timeout", http_status=http_status, retry_after=retry_after)

    def observe_results(self, results: Iterable[Any]) -> None:
        events = []
        for r in results:
            ip = getattr(r, "ip", None) or getattr(r, "target_ip", None)
            if not ip:
                continue
            status = getattr(r, "zgrab_status", None) or getattr(r, "status", None)
            events.append({"ip": ip, "timeout": status in ("connection-timeout", "io-timeout"),
                           "http_status": getattr(r, "http_status", None), "retry_after": None})
        self._observe(events)

    def limit_for(self, ip: str) -> int:
        self.flush(2.0)
        self._forget_refusals()
        reply = self._call({"op": "query", "ip": ip}, strict=True)
        return int(reply["limit"]) if reply else 0          # unreachable: no connection allowed

    def in_flight(self, ip: str) -> int:
        self.flush(2.0)
        self._forget_refusals()
        reply = self._call({"op": "query", "ip": ip}, strict=True)
        return int(reply["in_flight"]) if reply else 0

    def tracked(self) -> tuple[int, int]:
        snap = self.stats()
        return (int(snap["networks_active"]), int(snap["networks_backoff"])) if snap else (0, 0)

    def sweep(self) -> None:
        """The daemon sweeps its own records."""


def _read(s: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("the limiter closed the connection")
        buf += chunk
    return bytes(buf)
