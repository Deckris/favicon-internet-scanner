"""A connection limiter shared by every process of a host: ``python -m scanner.internet.limiterd --socket PATH``
(``python -m scanner.internet limiterd`` takes the same flags).

The per-network cap of ``SubnetLimiter`` and the pause between two requests to one address hold inside one process.
When the stages run as separate processes (TLS, HTTP, DNS, SNI, favicon) each would apply them on its own and the
limits would multiply. This daemon keeps them in one place. Processes talk to it through ``limiterclient``.

The daemon owns one ``SubnetLimiter`` (the same network keys, back-off and FIFO tickets as in a single process) and
a ledger of recent contacts. The ledger is a ring of time buckets, ``bucket`` seconds wide, that covers only the
pause: a bucket is dropped once the pause after it has passed, so memory follows the contact rate times the pause, not
the number of addresses ever seen. A contact counts as made at the end of its bucket, which can only make a pause
up to one bucket longer, never shorter.

Leases belong to the client that took them. A client that says ``goodbye`` gets everything freed at once: slots,
addresses in flight and places in line. A connection that breaks without it keeps its leases for ``grace`` seconds,
so a client that reconnects (``hello`` with the same ``client`` id) takes over from them instead of being counted
twice; after that, or on silence of ``lease_ttl`` seconds, they are freed. Clients send a ping at a third of the
interval while they hold any.

A daemon that has just started knows nothing of what its clients hold. It refuses every claim for ``startup_hold``
seconds (the pause plus the longest request) while the clients that survive it reconnect and say in ``hello`` what
they hold (``held``, ``busy``) and which addresses they contacted within the last pause (``recent``).

Protocol: frames of a 4-byte big-endian length and a JSON object. The client opens with ``hello`` (its cap and pause,
which the daemon refuses if they are looser than its own), then sends ``claim``, ``release``, ``withdraw``,
``observe``, ``query``, ``ping``, ``stats`` or ``goodbye``; every request gets one reply with ``ok``. A refusal that
no retry can change carries ``fatal``.

The daemon reports on itself: one ``heartbeat`` line every ``HEARTBEAT_EVERY`` seconds, written by the event loop's own
task, so a missing line means the loop did not run. A probe task measures how late the loop wakes up and, past
``LAG_WARN``, says what the process was doing meanwhile; a watchdog thread writes every thread's stack to ``<socket>.stall``
when the loop does not come back within ``STALL_DUMP_AFTER`` seconds. ``python -m scanner.internet.limiterd probe``
measures the round trip of a ``ping`` from outside.
"""
from __future__ import annotations

import argparse
import asyncio
import faulthandler
import json
import logging
import logging.handlers
import os
import queue
import socket
import stat
import struct
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable

from scanner.internet import pacing
from scanner.internet.pacing import SubnetLimiter, network_key, quick_key

log = logging.getLogger("scanner.internet.limiterd")
PROTOCOL = 1
MAX_FRAME = 16 * 1024 * 1024
DEFAULT_LEASE_TTL = 300.0
DEFAULT_BUCKET = 1.0
DEFAULT_GRACE = 30.0
DEFAULT_REQUEST_TIME = 30.0     # the longest a request runs, for the startup hold
SWEEP_EVERY = 1.0
RETRY_POLL = 0.25               # wait hint for a claim refused only because a network is full or an address in flight
BACKLOG = 1024                  # connections the kernel may queue before the loop accepts them (it clamps to somaxconn)
HEARTBEAT_EVERY = 10.0
LAG_TICK = 0.25                 # the loop-lag probe sleeps this long and measures how late it wakes
LAG_WARN = 0.75                 # a wake-up later than this is logged with what the process was doing
STALL_DUMP_AFTER = 3.0          # a loop that does not return within this long gets its thread stacks written to a file
STALL_FILE_MAX = 1 << 20        # a stall file larger than this is set aside at the start
SLOW_REQUEST = 0.1              # seconds; a request that takes longer is logged
SLOW_FRAME = 256 * 1024         # bytes; a larger request frame is logged
SLOW_LOG_PER_SECOND = 5
BIG_FRAME = 4 * 1024 * 1024     # a request frame over this size, other than a hello, is counted
LOG_QUEUE = 10000               # log records waiting for the writer; more are dropped and counted
DROP_EXAMPLE_EVERY = 10.0       # seconds between two logged examples of a dropped connection
_OPS = ("hello", "claim", "release", "withdraw", "observe", "query", "ping", "stats", "goodbye")


def pack_frame(message: dict[str, Any]) -> bytes:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    return struct.pack(">I", len(body)) + body


def unpack_length(header: bytes) -> int:
    (n,) = struct.unpack(">I", header)
    if n > MAX_FRAME:
        raise ValueError(f"frame of {n} bytes is over the limit")
    return n


def decode_frame(body: bytes) -> dict[str, Any]:
    message = json.loads(body.decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("frame is not a JSON object")
    return message


class ContactBuckets:
    """When addresses were contacted, in buckets of ``width`` seconds, kept only for ``gap`` seconds.

    Each address is kept once, with the newest bucket it was added to; the buckets list their addresses so that an
    expired bucket can take its addresses out."""

    def __init__(self, gap: float, width: float = DEFAULT_BUCKET) -> None:
        self.gap = float(gap)
        self.width = max(float(width), 1e-3)
        self._buckets: deque[tuple[int, list[str]]] = deque()       # (bucket index, addresses added to it), oldest first
        self._last: dict[str, int] = {}                             # address -> index of the newest bucket it was added to

    def _expiry(self, index: int) -> float:
        return (index + 1) * self.width + self.gap

    def add(self, ip: str, now: float) -> None:
        if self.gap <= 0:
            return
        index = int(now // self.width)
        if not self._buckets or self._buckets[-1][0] < index:
            self._buckets.append((index, []))
        newest, members = self._buckets[-1]       # a clock that went back lands in the newest bucket: later, never earlier
        if self._last.get(ip) != newest:
            self._last[ip] = newest
            members.append(ip)

    def add_many(self, ips: list[str], now: float) -> None:
        """``add`` for each of ``ips``, in order."""
        if self.gap <= 0 or not ips:
            return
        index = int(now // self.width)
        if not self._buckets or self._buckets[-1][0] < index:
            self._buckets.append((index, []))
        newest, members = self._buckets[-1]
        last = self._last
        for ip in ips:
            if last.get(ip) != newest:
                last[ip] = newest
                members.append(ip)

    def due_in(self, ip: str, now: float) -> float:
        """Seconds until ``ip`` may be contacted again (0 if it may be now)."""
        index = self._last.get(ip)
        if index is None:
            return 0.0
        expiry = self._expiry(index)
        return expiry - now if expiry > now else 0.0

    def waits(self, ips: list[str], now: float, busy: Any, busy_wait: float) -> list[float]:
        """``busy_wait`` for each address in ``busy``, else ``due_in``, for each of ``ips``."""
        last, ends = self._last, {}
        out = []
        for ip in ips:
            if ip in busy:
                out.append(busy_wait)
                continue
            index = last.get(ip)
            if index is None:
                out.append(0.0)
                continue
            expiry = ends.get(index)
            if expiry is None:
                expiry = ends[index] = self._expiry(index)
            out.append(expiry - now if expiry > now else 0.0)
        return out

    def prune(self, now: float) -> None:
        last = self._last
        while self._buckets and self._expiry(self._buckets[0][0]) <= now:
            index, members = self._buckets.popleft()
            for ip in members:
                if last.get(ip) == index:       # contacted again since: the newer bucket keeps it
                    del last[ip]

    def __len__(self) -> int:
        return len(self._last)

    @property
    def buckets(self) -> int:
        return len(self._buckets)


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="ascii", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


_TICKS = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") and "SC_CLK_TCK" in os.sysconf_names else 100
_PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") and "SC_PAGE_SIZE" in os.sysconf_names else 4096


def proc_sample() -> dict[str, float]:
    """What the calling thread has used so far, from /proc: ``cpu`` and ``runq`` (seconds on a CPU and waiting for one),
    ``minflt`` and ``majflt``. Empty where /proc is not available."""
    out: dict[str, float] = {}
    for base in ("/proc/thread-self", "/proc/self"):
        stat_text = _read(base + "/stat")
        if stat_text is None:
            continue
        try:
            fields = stat_text.rsplit(")", 1)[1].split()
            out["minflt"], out["majflt"] = float(fields[7]), float(fields[9])
            out["cpu"] = (float(fields[11]) + float(fields[12])) / _TICKS
        except (IndexError, ValueError):
            return out
        sched = _read(base + "/schedstat")
        if sched:
            try:
                cpu_ns, wait_ns = sched.split()[:2]
                out["cpu"], out["runq"] = int(cpu_ns) / 1e9, int(wait_ns) / 1e9
            except ValueError:
                pass
        break
    return out


def rss_kb() -> int:
    text = _read("/proc/self/statm")
    try:
        return int(text.split()[1]) * _PAGE // 1024 if text else 0
    except (IndexError, ValueError):
        return 0


def _swap_kb() -> int:
    for line in (_read("/proc/self/status") or "").splitlines():
        if line.startswith("VmSwap:"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                break
    return 0


def _pressure(name: str) -> float | None:
    """The 10-second average share of time some task waited for ``name`` (cpu or io), if the kernel reports it."""
    for line in (_read("/proc/pressure/" + name) or "").splitlines():
        if line.startswith("some"):
            for part in line.split():
                if part.startswith("avg10="):
                    try:
                        return float(part[6:])
                    except ValueError:
                        return None
    return None


class QueuedLogging:
    """Log records go through a bounded queue to a writer thread, so a log stream that blocks stops that thread and not
    the event loop. A full queue drops the record and counts it."""

    class _Handler(logging.handlers.QueueHandler):
        dropped = 0

        def enqueue(self, record: logging.LogRecord) -> None:
            try:
                self.queue.put_nowait(record)
            except queue.Full:
                self.dropped += 1

    def __init__(self, root: logging.Logger | None = None, size: int = LOG_QUEUE) -> None:
        self.root = root or logging.getLogger()
        self._old = list(self.root.handlers)
        self.handler = self._Handler(queue.Queue(size))
        self.listener = logging.handlers.QueueListener(self.handler.queue, *self._old, respect_handler_level=True)
        self.root.handlers = [self.handler]
        self.listener.start()

    @property
    def dropped(self) -> int:
        return self.handler.dropped

    def stop(self, timeout: float = 2.0) -> None:
        """Hand the handlers back; give up on a writer that is stuck after ``timeout`` seconds."""
        self.root.handlers = self._old
        if self.handler.queue.full():          # the stop marker needs a free place, so the oldest record makes room
            try:
                self.handler.queue.get_nowait()
                self.handler.dropped += 1
            except queue.Empty:
                pass
        stopper = threading.Thread(target=self.listener.stop, daemon=True)
        stopper.start()
        stopper.join(timeout)


_queued: QueuedLogging | None = None


def log_records_dropped() -> int:
    return _queued.dropped if _queued is not None else 0


class Metrics:
    """Counters of what the daemon has done: totals since the start, and the same over the current heartbeat interval."""

    def __init__(self) -> None:
        self.ops: dict[str, int] = {}
        self.reconnects = 0
        self.dropped_connections = 0
        self.truncated_connections = 0
        self.big_frames = 0
        self.largest_frame = 0
        self.lag_max = 0.0
        self.bytes_in = 0
        self.last_drop_example = -DROP_EXAMPLE_EVERY
        self.dropped_since_example = 0
        self.reset_interval()

    def reset_interval(self) -> None:
        self.i_started = time.monotonic()
        self.i_ops: dict[str, int] = {}
        self.i_op_time: dict[str, float] = {}
        self.i_durations: list[float] = []
        self.i_requests = 0
        self.i_bytes = 0
        self.i_largest = 0
        self.i_lag_max = 0.0

    def request(self, op: Any, size: int, seconds: float) -> None:
        name = op if op in _OPS else "other"
        self.bytes_in += size
        self.largest_frame = max(self.largest_frame, size)
        self.i_requests += 1
        self.i_bytes += size
        self.i_largest = max(self.i_largest, size)
        self.i_ops[name] = self.i_ops.get(name, 0) + 1
        self.i_op_time[name] = self.i_op_time.get(name, 0.0) + seconds
        if len(self.i_durations) < 50000:
            self.i_durations.append(seconds)

    def lag(self, seconds: float) -> None:
        seconds = max(seconds, 0.0)
        self.lag_max = max(self.lag_max, seconds)
        self.i_lag_max = max(self.i_lag_max, seconds)

    def p99(self) -> float:
        if not self.i_durations:
            return 0.0
        ordered = sorted(self.i_durations)
        return ordered[int(0.99 * (len(ordered) - 1))]


def _items(req: Any) -> int:
    """How many addresses, events or counts a request carries (for the slow-request log)."""
    total = 0
    if isinstance(req, dict):
        for key in ("ips", "events", "counts", "busy", "held", "recent"):
            value = req.get(key)
            if isinstance(value, (list, dict)):
                total += len(value)
    return total


class _Conn:
    def __init__(self, ident: int, now: float) -> None:
        self.id = ident
        self.counts: dict[str, int] = {}        # slots held per network
        self.ips: set[str] = set()              # addresses in flight (claimed as exclusive)
        self.tickets: dict[int, int] = {}       # the client's ticket -> the daemon's, for places in line
        self.last_seen = now
        self.hello = False
        self.expired = False
        self.client: str | None = None
        self.closed = False                     # the socket is gone but the leases are kept until ``linger_until``
        self.linger_until = 0.0

    def holds(self) -> bool:
        return bool(self.counts or self.ips or self.tickets)


class LimiterCore:
    """The state and rules of the daemon, without I/O: ``handle(conn, request)`` returns the reply."""

    def __init__(self, cap: int, gap: float, *, now: Callable[[], float] = time.monotonic, lease_ttl: float = DEFAULT_LEASE_TTL,
                 bucket: float = DEFAULT_BUCKET, grace: float = DEFAULT_GRACE, startup_hold: float = 0.0,
                 **backoff: Any) -> None:
        self.cap, self.gap, self.lease_ttl = max(1, int(cap)), float(gap), float(lease_ttl)
        self.grace, self.startup_hold = float(grace), float(startup_hold)
        self._now = now
        self._started = now()
        self.limiter = SubnetLimiter(self.cap, now=now, **backoff)
        self.contacts = ContactBuckets(self.gap, bucket)
        self._busy: dict[str, int] = {}         # address in flight -> connection
        self._conns: dict[int, _Conn] = {}
        self._next_conn = 0
        self.metrics = Metrics()
        self._clients_seen: set[str] = set()
        self.stats: dict[str, int] = {"grants": 0, "refused_full": 0, "refused_gap": 0, "expired": 0, "stale_releases": 0,
                                    "refused_startup": 0, "adopted": 0}

    def open(self) -> _Conn:
        self._next_conn += 1
        conn = self._conns[self._next_conn] = _Conn(self._next_conn, self._now())
        return conn

    def close(self, conn: _Conn) -> None:
        """The socket is gone. Leases are kept for the grace period unless the client said goodbye or has none."""
        if (conn.counts or conn.ips) and self.grace > 0 and not conn.expired:    # places in line are not kept
            conn.closed, conn.linger_until = True, self._now() + self.grace
            return
        self._free(conn)
        self._conns.pop(conn.id, None)

    def _free(self, conn: _Conn) -> None:
        """Give back everything a connection holds."""
        now = self._now()
        if conn.counts:
            self.limiter.release(conn.counts)
            conn.counts = {}
        for ip in conn.ips:         # a request may have been sent: the pause starts now
            self._busy.pop(ip, None)
            self.contacts.add(ip, now)
        conn.ips = set()
        for mine in conn.tickets.values():
            self.limiter.withdraw(mine)
        conn.tickets = {}

    def sweep(self) -> None:
        now = self._now()
        for conn in list(self._conns.values()):
            if conn.closed:
                if now >= conn.linger_until:
                    self._free(conn)
                    del self._conns[conn.id]
                continue
            if conn.holds() and now - conn.last_seen > self.lease_ttl:
                log.warning("connection %d silent for %.0f s: its leases are freed", conn.id, now - conn.last_seen)
                self._free(conn)
                conn.expired = True
                self.stats["expired"] += 1
        self.contacts.prune(now)
        self.limiter.sweep()

    # requests

    def handle(self, conn: _Conn, req: dict[str, Any]) -> dict[str, Any]:
        conn.last_seen = self._now()
        op = req.get("op")
        ops = self.metrics.ops
        name = op if op in _OPS else "other"        # op may be any JSON value
        ops[name] = ops.get(name, 0) + 1
        if conn.expired:
            return {"ok": False, "error": "leases expired", "close": True}
        try:
            if op == "hello":
                return self._hello(conn, req)
            if not conn.hello:
                return {"ok": False, "error": "hello required", "close": True}
            if op == "claim":
                return self._claim(conn, req)
            if op == "release":
                return self._release(conn, req)
            if op == "goodbye":
                self._free(conn)
                return {"ok": True, "close": True}
            if op == "withdraw":
                self._withdraw(conn, req.get("ticket"))
                return {"ok": True}
            if op == "observe":
                return self._observe(req)
            if op == "query":
                ip = str(req.get("ip", ""))
                return {"ok": True, "limit": self.limiter.limit_for(ip), "in_flight": self.limiter.in_flight(ip)}
            if op == "ping":
                return {"ok": True}
            if op == "stats":
                return {"ok": True, **self.snapshot()}
        except (KeyError, OverflowError, TypeError, ValueError, AttributeError) as exc:
            return {"ok": False, "error": f"bad request: {exc!r}"}
        return {"ok": False, "error": f"unknown op {op!r}"}

    def snapshot(self) -> dict[str, Any]:
        networks, backoff = self.limiter.tracked()
        lingering = sum(1 for c in self._conns.values() if c.closed)
        return {"connections": len(self._conns) - lingering, "lingering": lingering, "networks_active": networks, "networks_backoff": backoff,
                "in_flight_addresses": len(self._busy), "ledger_addresses": len(self.contacts),
                "ledger_buckets": self.contacts.buckets, "waiting": len(self.limiter._waiting), **self.stats,
                "uptime": round(self._now() - self._started, 3), "loop_lag_max_ms": round(self.metrics.lag_max * 1000.0, 1),
                "largest_frame": self.metrics.largest_frame, "rss_kb": rss_kb(), "ops": dict(self.metrics.ops),
                "reconnects": self.metrics.reconnects, "dropped_connections": self.metrics.dropped_connections,
                "truncated_connections": self.metrics.truncated_connections, "log_dropped": log_records_dropped()}

    def _hello(self, conn: _Conn, req: dict[str, Any]) -> dict[str, Any]:
        if conn.hello:
            return {"ok": False, "error": "hello sent twice"}
        if req.get("protocol") != PROTOCOL:
            return {"ok": False, "close": True, "fatal": True, "error": f"protocol {req.get('protocol')!r} not supported"}
        cap, gap = int(req["cap"]), float(req["gap"])
        if self.cap > cap or self.gap < gap:
            return {"ok": False, "close": True, "fatal": True,
                    "error": f"daemon allows {self.cap} per network and {self.gap:g} s per address; "
                             f"the client asks for at most {cap} and at least {gap:g} s"}
        client = req.get("client")
        held = {str(k): int(n) for k, n in (req.get("held") or {}).items() if int(n) > 0}
        busy = req.get("busy") or []
        recent = {str(ip): float(age) for ip, age in (req.get("recent") or {}).items()}
        if client is not None and not isinstance(client, str):
            raise ValueError("client must be a string")
        if not isinstance(busy, list) or not all(isinstance(ip, str) for ip in busy):
            raise ValueError("busy must be a list of strings")
        now = self._now()
        if client is not None:
            for other in list(self._conns.values()):        # the client's earlier connection: its leases are re-declared here
                if other is not conn and other.client == client:
                    self._free(other)
                    other.expired = True
                    if other.closed:
                        del self._conns[other.id]
        if client is not None:
            if client in self._clients_seen:
                self.metrics.reconnects += 1
            elif len(self._clients_seen) < 100000:
                self._clients_seen.add(client)
        conn.client, conn.hello = client, True
        if held:
            self.limiter.adopt(held)
            for key, n in held.items():
                conn.counts[key] = conn.counts.get(key, 0) + n
            self.stats["adopted"] += sum(held.values())
        for ip in busy:
            self._busy[ip] = conn.id
            conn.ips.add(ip)
        for ip, age in recent.items():
            self.contacts.add(ip, now - min(max(age, 0.0), self.gap))
        return {"ok": True, "cap": self.cap, "gap": self.gap, "lease_ttl": self.lease_ttl}

    def _ticket(self, conn: _Conn, theirs: Any) -> int | None:
        if theirs is None:
            return None
        if theirs not in conn.tickets:
            conn.tickets[theirs] = self.limiter.ticket()      # numbered when first seen, so the line is in arrival order
        return conn.tickets[theirs]

    def _withdraw(self, conn: _Conn, theirs: Any) -> None:
        mine = conn.tickets.pop(theirs, None)
        if mine is not None:
            self.limiter.withdraw(mine)

    def _wait_for(self, ip: str, now: float) -> float:
        if ip in self._busy:
            return RETRY_POLL
        return self.contacts.due_in(ip, now)

    def _counts(self, ips: list[str]) -> dict[str, int]:
        """Slots per network for ``ips``, as ``SubnetLimiter.counts`` gives them."""
        key_of = self.limiter.key_of
        if key_of is not network_key:
            return self.limiter.counts(ips)
        out: dict[str, int] = {}
        for ip in ips:
            key = quick_key(ip)
            out[key] = out.get(key, 0) + 1
        return out

    def _claim(self, conn: _Conn, req: dict[str, Any]) -> dict[str, Any]:
        now = self._now()
        remaining = self._started + self.startup_hold - now
        if remaining > 0:       # clients that outlived a restart have not said what they hold yet
            self.stats["refused_startup"] += 1
            return {"ok": True, "granted": False, "reason": "startup", "wait": min(max(remaining, 0.01), 1.0)}
        ips = req.get("ips")
        partial, exclusive, theirs = bool(req.get("partial")), bool(req.get("exclusive")), req.get("ticket")
        if ips is not None:
            if not isinstance(ips, list) or not all(isinstance(ip, str) for ip in ips):
                raise ValueError("ips must be a list of strings")
            if not ips:
                return {"ok": True, "granted": True, "ips": []}       # nothing to take, as in the process itself
            waits = self.contacts.waits(ips, now, self._busy, RETRY_POLL)
            ok_ips = [ip for ip, w in zip(ips, waits) if w <= 0]
            late = [w for w in waits if w > 0]
            if not ok_ips or (late and not partial):
                self.stats["refused_gap"] += 1          # a place in line is kept: the pause is not the network's fault
                return {"ok": True, "granted": False, "reason": "gap", "wait": max(min(late) if partial else max(late), 0.01)}
            mine = self._ticket(conn, theirs)
            if partial:
                key_of = self.limiter.key_of
                if key_of is network_key:
                    keys = [quick_key(ip) for ip in ok_ips]
                else:
                    keys = [key_of(ip) for ip in ok_ips]
                got, counts = self.limiter.try_acquire_some_keyed(ok_ips, keys, mine)
                granted = bool(got)
            else:
                got = list(ips)
                counts = self._counts(got)
                granted = self.limiter.try_acquire(counts, mine)
        else:
            counts_in = req.get("counts")
            if not isinstance(counts_in, dict):
                raise ValueError("a claim needs ips or counts")
            counts = {str(k): int(n) for k, n in counts_in.items() if int(n) > 0}
            mine = self._ticket(conn, theirs) if counts else None
            got = []
            granted = self.limiter.try_acquire(counts, mine)
        if not granted:
            self.stats["refused_full"] += 1
            return {"ok": True, "granted": False, "reason": "full", "wait": RETRY_POLL}
        conn.tickets.pop(theirs, None)      # served: the limiter dropped the place in line itself
        for key, n in counts.items():
            conn.counts[key] = conn.counts.get(key, 0) + n
        if ips is not None:
            self.contacts.add_many(got, now)
            if exclusive:
                self._busy.update(dict.fromkeys(got, conn.id))
                conn.ips.update(got)
        self.stats["grants"] += 1
        return {"ok": True, "granted": True, "ips": got if ips is not None else None}

    def _release(self, conn: _Conn, req: dict[str, Any]) -> dict[str, Any]:
        now = self._now()
        counts_in, ips_in = req.get("counts") or {}, req.get("ips") or []
        if not isinstance(counts_in, dict) or not isinstance(ips_in, list) or not all(isinstance(ip, str) for ip in ips_in):
            raise ValueError("release needs counts as an object and ips as a list of strings")
        counts = {str(k): int(n) for k, n in counts_in.items()}
        for key, n in counts.items():
            if n <= 0:
                continue
            held = conn.counts.get(key, 0)
            take = min(n, held)
            if take < n:
                self.stats["stale_releases"] += n - take      # already freed (leases expired) or never taken
            if take:
                self.limiter.release({key: take})
                if held - take > 0:
                    conn.counts[key] = held - take
                else:
                    conn.counts.pop(key, None)
        for ip in ips_in:
            if ip in conn.ips:
                conn.ips.discard(ip)
                self._busy.pop(ip, None)
                self.contacts.add(ip, now)       # the pause of a claimed address runs from the end of the request
        return {"ok": True}

    def _observe(self, req: dict[str, Any]) -> dict[str, Any]:
        events = req.get("events") or []
        if not isinstance(events, list):
            raise ValueError("events must be a list")
        parsed = []
        for ev in events:
            retry_after = ev.get("retry_after")
            parsed.append((str(ev["ip"]), bool(ev.get("timeout")), ev.get("http_status"),
                           float(retry_after) if retry_after is not None else None))
        states = self.limiter._states
        for ip, timeout, status, retry_after in parsed:          # all checked first: a bad event applies none
            if not states and not timeout and status not in (429, 503):
                continue            # a success changes nothing while no network has a back-off record
            self.limiter.observe(ip, timeout=timeout, http_status=status, retry_after=retry_after)
        return {"ok": True}


class LimiterServer:
    def __init__(self, core: LimiterCore, path: str | os.PathLike[str], *, heartbeat_every: float = HEARTBEAT_EVERY,
                 lag_tick: float = LAG_TICK, lag_warn: float = LAG_WARN, stall_dump_after: float = STALL_DUMP_AFTER,
                 stall_file: str | os.PathLike[str] | None = None, slow_request: float = SLOW_REQUEST) -> None:
        """``stall_dump_after`` of 0 turns the stack dump off; ``stall_file`` defaults to ``<path>.stall``."""
        self.core, self.path = core, str(path)
        self.heartbeat_every, self.lag_tick, self.lag_warn = heartbeat_every, lag_tick, lag_warn
        self.stall_dump_after, self.slow_request = stall_dump_after, slow_request
        self.stall_file = str(stall_file) if stall_file is not None else self.path + ".stall"
        self._server: asyncio.AbstractServer | None = None
        self._lock_fd: int | None = None
        self._ino: int | None = None
        self._stall_fh: Any = None
        self._stall_thread: threading.Thread | None = None
        self._stall_stop = threading.Event()
        self._armed_at = time.monotonic()       # when the loop last went to sleep for a tick
        self._slow_second = 0
        self._slow_lines = 0
        self._slow_skipped = 0
        self._beat_cpu = (time.process_time(), proc_sample())
        self._stalls = 0

    # reading and answering

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = self.core.open()
        metrics = self.core.metrics
        try:
            while True:
                try:
                    header = await reader.readexactly(4)
                except asyncio.IncompleteReadError as exc:
                    if exc.partial:
                        metrics.truncated_connections += 1
                    break
                size = unpack_length(header)
                try:
                    body = await reader.readexactly(size)
                except asyncio.IncompleteReadError:
                    metrics.truncated_connections += 1
                    raise
                started = time.perf_counter()
                req: dict[str, Any] | None = None
                try:
                    req = decode_frame(body)
                    reply = self.core.handle(conn, req)
                except ValueError as exc:       # not JSON, or not an object: the framing is intact, so say so and go on
                    reply = {"ok": False, "error": f"bad frame: {exc}"}
                frame = pack_frame(reply)
                self._timed(conn, req, size + 4, time.perf_counter() - started)
                writer.write(frame)
                await writer.drain()
                if reply.get("close"):
                    break
        except (ConnectionError, asyncio.IncompleteReadError, ValueError) as exc:
            self._dropped(conn, exc)
        finally:
            self.core.close(conn)
            writer.close()

    def _dropped(self, conn: _Conn, exc: BaseException) -> None:
        """Count a connection that ended badly; log one example per ``DROP_EXAMPLE_EVERY`` seconds."""
        m = self.core.metrics
        m.dropped_connections += 1
        m.dropped_since_example += 1
        now = time.monotonic()
        if now - m.last_drop_example >= DROP_EXAMPLE_EVERY:
            log.info("connection %d dropped: %s (%d dropped since the last example)", conn.id, exc, m.dropped_since_example)
            m.last_drop_example, m.dropped_since_example = now, 0

    def _timed(self, conn: _Conn, req: dict[str, Any] | None, nbytes: int, seconds: float) -> None:
        op = req.get("op") if req is not None else None
        self.core.metrics.request(op, nbytes, seconds)
        if nbytes > BIG_FRAME and op != "hello":
            self.core.metrics.big_frames += 1
        if seconds <= self.slow_request and nbytes <= SLOW_FRAME:
            return
        second = int(time.monotonic())
        if second != self._slow_second:
            if self._slow_skipped:
                log.warning("slow requests not logged in the last second: %d", self._slow_skipped)
            self._slow_second, self._slow_lines, self._slow_skipped = second, 0, 0
        if self._slow_lines >= SLOW_LOG_PER_SECOND:
            self._slow_skipped += 1
            return
        self._slow_lines += 1
        log.warning("slow request: connection %d op=%s bytes=%d items=%d took %.0f ms", conn.id,
                    op if op in _OPS else "other", nbytes, _items(req), seconds * 1000.0)

    # the daemon's own report

    def _arm_dump(self) -> None:
        self._armed_at = time.monotonic()

    def _watch_stalls(self) -> None:
        """Write every thread's stack while the loop has been away for ``stall_dump_after`` seconds, and again at that interval
        for as long as it stays away. It runs as an ordinary thread, so it holds the interpreter lock while it walks the
        stacks: a loop that comes back at that moment waits for the lock instead of changing a frame under the walk."""
        last = 0.0
        period = max(min(self.stall_dump_after / 4.0, 0.5), 0.02)
        while not self._stall_stop.wait(period):
            now = time.monotonic()
            if now - self._armed_at >= self.stall_dump_after and now - last >= self.stall_dump_after:
                last = now
                try:
                    self._stall_fh.write(f"--- loop away for {now - self._armed_at:.1f} s, "
                                         f"{time.strftime('%Y-%m-%d %H:%M:%S')} ---\n".encode("ascii"))
                    faulthandler.dump_traceback(file=self._stall_fh, all_threads=True)
                except (OSError, ValueError):
                    pass

    def _open_stall_file(self) -> None:
        if self.stall_dump_after <= 0:
            return
        try:
            if os.path.getsize(self.stall_file) > STALL_FILE_MAX:
                os.replace(self.stall_file, self.stall_file + ".1")
        except OSError:
            pass
        try:
            self._stall_fh = open(self.stall_file, "ab", buffering=0)
            self._stall_fh.write(f"--- limiter {os.getpid()} started {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n".encode("ascii"))
        except OSError as exc:
            self._stall_fh = None
            log.warning("no stall file at %s (%s): stacks are not recorded", self.stall_file, exc)
            return
        self._armed_at = time.monotonic()
        self._stall_thread = threading.Thread(target=self._watch_stalls, name="stall-watch", daemon=True)
        self._stall_thread.start()

    def _close_stall_file(self) -> None:
        if self._stall_fh is not None:
            self._stall_stop.set()
            if self._stall_thread is not None:
                self._stall_thread.join(2.0)
                if self._stall_thread.is_alive():       # stuck in a write: the file stays open with it
                    return
            try:
                self._stall_fh.close()
            except OSError:
                pass
            self._stall_fh = None

    async def watch_loop(self) -> None:
        """Sleep one tick at a time and measure how late the loop wakes. A late wake-up is logged with the CPU time, run-queue
        wait and page faults of the interval, which say whether the loop was computing, starved of a CPU or waiting on memory."""
        while True:
            try:
                self._arm_dump()
                before, started = proc_sample(), time.monotonic()
                await asyncio.sleep(self.lag_tick)
                lag = time.monotonic() - started - self.lag_tick
                self.core.metrics.lag(lag)
                if lag > self.lag_warn:
                    self._stalls += 1
                    self._warn_stall(lag, before, proc_sample())
                    self.heartbeat("after a stall")
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("loop-lag probe failed")
                await asyncio.sleep(self.lag_tick)

    def _warn_stall(self, lag: float, before: dict[str, float], after: dict[str, float]) -> None:
        def delta(key: str) -> float:
            return after.get(key, 0.0) - before.get(key, 0.0)

        cpu, runq, minor, major = delta("cpu"), delta("runq"), delta("minflt"), delta("majflt")
        if not after:
            reading = "no /proc to tell"
        elif cpu >= 0.7 * lag:
            reading = "the loop was computing"
        elif runq >= 0.5 * lag:
            reading = "the loop waited for a CPU"
        elif major > 0 or minor > 1000:
            reading = "the loop waited on memory or disk"
        else:
            reading = "the loop was neither computing nor runnable"
        dump = f"; stacks in {self.stall_file}" if self._stall_fh is not None and lag >= self.stall_dump_after else ""
        log.warning("event loop late by %.2f s: cpu %.2f s, run-queue wait %.2f s, page faults %d minor %d major: %s%s",
                    lag, cpu, runq, minor, major, reading, dump)

    async def beat(self) -> None:
        """One heartbeat line per interval, written from this task only."""
        due = time.monotonic() + self.heartbeat_every
        while True:
            try:
                await asyncio.sleep(max(due - time.monotonic(), 0.0))
                self.heartbeat()
                due += self.heartbeat_every
                if due <= time.monotonic():         # late after a stall: one line, not a burst
                    due = time.monotonic() + self.heartbeat_every
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("heartbeat failed")
                due = time.monotonic() + self.heartbeat_every
                await asyncio.sleep(self.heartbeat_every)

    def heartbeat(self, why: str = "") -> None:
        core, m = self.core, self.core.metrics
        now = time.monotonic()
        span = max(now - m.i_started, 1e-6)
        cpu0, sample0 = self._beat_cpu
        cpu, sample = time.process_time(), proc_sample()
        self._beat_cpu = (cpu, sample)
        networks, backoff = core.limiter.tracked()
        lingering = sum(1 for c in core._conns.values() if c.closed)
        ops = " ".join(f"{op}={n}/{m.i_op_time.get(op, 0.0) * 1000.0:.0f}ms" for op, n in sorted(m.i_ops.items())) or "-"
        parts = [f"heartbeat{' (' + why + ')' if why else ''}: up {core._now() - core._started:.0f} s",
                 f"connections {len(core._conns) - lingering} lingering {lingering}",
                 f"in_flight {len(core._busy)} waiting {len(core.limiter._waiting)} networks {networks} backoff {backoff}",
                 f"requests {m.i_requests / span:.1f}/s ops {ops}",
                 f"bytes_in {m.i_bytes} largest_frame {m.i_largest} big_frames {m.big_frames}",
                 f"p99 {m.p99() * 1000.0:.1f} ms lag_max {m.i_lag_max * 1000.0:.0f} ms stalls {self._stalls}",
                 f"reconnects {m.reconnects} dropped {m.dropped_connections} truncated {m.truncated_connections}",
                 f"rss {rss_kb()} kB swap {_swap_kb()} kB",
                 f"cpu {(cpu - cpu0) / span * 100.0:.0f}%"]
        if sample and sample0:
            parts.append(f"runq {(sample.get('runq', 0.0) - sample0.get('runq', 0.0)) / span * 100.0:.0f}%")
            parts.append(f"faults {sample.get('minflt', 0.0) - sample0.get('minflt', 0.0):.0f} minor "
                         f"{sample.get('majflt', 0.0) - sample0.get('majflt', 0.0):.0f} major")
        for name in ("cpu", "io"):
            level = _pressure(name)
            if level is not None:
                parts.append(f"psi_{name} {level:.2f}")
        parts.append(f"log_dropped {log_records_dropped()}")
        log.info(", ".join(parts))
        m.reset_interval()

    # the socket

    def _claim_path(self) -> None:
        """Make the path ours: hold the lock beside it for the daemon's life, and remove only a dead daemon's socket."""
        import fcntl

        fd = os.open(self.path + ".lock", os.O_RDWR | os.O_CREAT, 0o660)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise RuntimeError(f"a limiter daemon is already listening on {self.path} (its lock is held)") from None
        self._lock_fd = fd
        try:
            mode = os.lstat(self.path).st_mode
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(mode):
            raise RuntimeError(f"{self.path} exists and is not a socket; it is left alone")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(1.0)
        try:
            probe.connect(self.path)
        except ConnectionRefusedError:
            os.unlink(self.path)            # nobody listens: a daemon that died without cleaning up
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise RuntimeError(f"cannot tell whether a daemon listens on {self.path} ({exc}); it is left alone") from exc
        else:
            raise RuntimeError(f"a limiter daemon is already listening on {self.path}")
        finally:
            probe.close()

    def _unlock(self) -> None:
        if self._lock_fd is not None:
            os.close(self._lock_fd)          # closing drops the flock
            self._lock_fd = None

    async def start(self) -> None:
        try:
            self._claim_path()
            old = os.umask(0o117)           # the socket is created 0660, never wider, even for an instant
            try:
                self._server = await asyncio.start_unix_server(self._serve, path=self.path, backlog=BACKLOG)
            finally:
                os.umask(old)
            self._ino = os.lstat(self.path).st_ino
        except BaseException:
            self._unlock()
            raise
        somaxconn = (_read("/proc/sys/net/core/somaxconn") or "").strip()
        log.info("accept backlog %d (kernel limit %s)", BACKLOG, somaxconn or "unknown")

    async def sweeper(self) -> None:
        while True:
            await asyncio.sleep(SWEEP_EVERY)
            self.core.sweep()

    def _remove_socket(self) -> None:
        """Unlink the path only while it is still the socket this daemon made."""
        try:
            st = os.lstat(self.path)
        except OSError:
            return
        if stat.S_ISSOCK(st.st_mode) and st.st_ino == self._ino:
            try:
                os.unlink(self.path)
            except OSError:
                pass

    async def run(self, stop: asyncio.Event) -> None:
        await self.start()
        self._open_stall_file()
        tasks = [asyncio.create_task(self.sweeper()), asyncio.create_task(self.watch_loop())]
        if self.heartbeat_every > 0:
            tasks.append(asyncio.create_task(self.beat()))
        try:
            await stop.wait()
        finally:
            for task in tasks:
                task.cancel()
            assert self._server is not None
            self._server.close()
            self._close_stall_file()
            self._remove_socket()
            self._unlock()


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


def run_daemon(path: str | os.PathLike[str], cap: int, gap: float, *, lease_ttl: float = DEFAULT_LEASE_TTL,
               bucket: float = DEFAULT_BUCKET, retry_after_max_hold: float = pacing.DEFAULT_RETRY_AFTER_MAX_HOLD,
               grace: float = DEFAULT_GRACE, startup_hold: float | None = None) -> None:
    """Serve until SIGTERM or SIGINT. ``startup_hold`` defaults to the pause plus ``DEFAULT_REQUEST_TIME``.

    The heartbeat interval, the lateness that is logged and the time after which stacks are written can be set with
    ``SCANNER_LIMITER_HEARTBEAT_EVERY``, ``SCANNER_LIMITER_LAG_WARN`` and ``SCANNER_LIMITER_STALL_DUMP_AFTER`` (seconds;
    0 turns the stack dump off)."""
    import signal

    global _queued
    hold = gap + DEFAULT_REQUEST_TIME if startup_hold is None else startup_hold
    core = LimiterCore(cap, gap, lease_ttl=lease_ttl, bucket=bucket, grace=grace, startup_hold=hold, max_hold=retry_after_max_hold)
    _queued = QueuedLogging()

    async def main() -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        server = LimiterServer(core, Path(path), heartbeat_every=_env_float("SCANNER_LIMITER_HEARTBEAT_EVERY", HEARTBEAT_EVERY),
                               lag_warn=_env_float("SCANNER_LIMITER_LAG_WARN", LAG_WARN),
                               stall_dump_after=_env_float("SCANNER_LIMITER_STALL_DUMP_AFTER", STALL_DUMP_AFTER))
        log.info("limiter listening on %s: %d per network, %g s per address", path, core.cap, core.gap)
        await server.run(stop)

    try:
        asyncio.run(main())
    finally:
        _queued.stop()
        _queued = None


# the command line: ``python -m scanner.internet.limiterd`` imports nothing beyond this module and ``pacing``

def _daemon_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m scanner.internet.limiterd",
                                 description="Serve the shared connection limiter. 'probe --socket PATH' measures the round trip of a ping instead.")
    ap.add_argument("--config", type=Path, help="read the cap, pause and socket from this configuration (needs PyYAML)")
    ap.add_argument("--socket", type=Path, help="Unix socket to listen on (default: measurement.limiter_socket of --config)")
    ap.add_argument("--max-connections-per-subnet", type=int,
                    help="connections open at once to one /24 (1-64; default: the config's, else 4)")
    ap.add_argument("--retry-after-max-hold-seconds", type=float,
                    help="longest a network is left alone after a 429/503 with Retry-After (0-900)")
    ap.add_argument("--min-seconds-between-probes", type=float, metavar="S",
                    help="pause between two requests to one address (default: the config's, else 5)")
    ap.add_argument("--lease-ttl-seconds", type=float, default=300.0,
                    help="a client silent for this long loses the slots it holds (default 300)")
    ap.add_argument("--grace-seconds", type=float, default=30.0,
                    help="a client whose connection broke keeps its slots this long so that it can reconnect (default 30)")
    ap.add_argument("--startup-hold-seconds", type=float,
                    help="refuse every claim for this long after the start, while clients report what they hold "
                         "(default: the pause plus fetch.total_timeout of --config, else plus 30)")
    ap.add_argument("--bucket-seconds", type=float, default=1.0,
                    help="width of the time buckets of the per-address ledger (default 1; the pause can run this much longer)")
    return ap


def _probe(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m scanner.internet.limiterd probe",
                                 description="Log the round-trip time of a ping to a running limiter daemon.")
    ap.add_argument("--socket", type=Path, required=True)
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between two pings (default 2)")
    ap.add_argument("--timeout", type=float, default=5.0, help="seconds to wait for a connection or a reply (default 5)")
    ap.add_argument("--count", type=int, default=0, help="stop after this many pings (default 0: until interrupted)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    sock: socket.socket | None = None
    sent = 0
    try:
        while args.count <= 0 or sent < args.count:
            sent += 1
            began = time.perf_counter()
            try:
                if sock is None:
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.settimeout(args.timeout)
                    sock.connect(str(args.socket))
                    _probe_ask(sock, {"op": "hello", "protocol": PROTOCOL, "cap": 64, "gap": 0.0})
                    log.info("probe connected in %.1f ms", (time.perf_counter() - began) * 1000.0)
                    began = time.perf_counter()
                _probe_ask(sock, {"op": "ping"})
                log.info("probe ping %.1f ms", (time.perf_counter() - began) * 1000.0)
            except (OSError, ValueError) as exc:
                log.warning("probe failed after %.1f ms: %s", (time.perf_counter() - began) * 1000.0, exc)
                if sock is not None:
                    sock.close()
                sock = None
            if args.count <= 0 or sent < args.count:
                time.sleep(max(args.interval, 0.0))
    except KeyboardInterrupt:
        pass
    finally:
        if sock is not None:
            sock.close()
    return 0


def _probe_ask(sock: socket.socket, request: dict[str, Any]) -> dict[str, Any]:
    sock.sendall(pack_frame(request))
    header = _probe_read(sock, 4)
    reply = decode_frame(_probe_read(sock, unpack_length(header)))
    if not reply.get("ok"):
        raise ValueError(f"refused: {reply.get('error')}")
    return reply


def _probe_read(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("the daemon closed the connection")
        data += chunk
    return data


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "probe":
        return _probe(argv[1:])
    ap = _daemon_parser()
    args = ap.parse_args(argv)
    request_time = None
    cap, gap, hold, path = args.max_connections_per_subnet, args.min_seconds_between_probes, args.retry_after_max_hold_seconds, args.socket
    if args.config is not None:
        from scanner.internet.config import ConfigError, load_config

        try:
            loaded = load_config(args.config, require_approval=False)
        except ConfigError as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2
        m = loaded.measurement
        cap = m.max_connections_per_subnet if cap is None else cap
        gap = m.min_seconds_between_probes_per_ip if gap is None else gap
        hold = m.retry_after_max_hold_seconds if hold is None else hold
        path = Path(m.limiter_socket) if path is None and m.limiter_socket else path
        request_time = loaded.fetch.total_timeout
    if path is None:
        ap.error("limiterd needs --socket (or measurement.limiter_socket in --config)")
    if not hasattr(socket, "AF_UNIX"):
        print("REFUSED: limiterd needs Unix domain sockets", file=sys.stderr)
        return 2
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    kwargs = {} if hold is None else {"retry_after_max_hold": hold}
    gap = 5.0 if gap is None else gap
    start_hold = args.startup_hold_seconds
    if start_hold is None:
        start_hold = gap + (30.0 if request_time is None else request_time)
    try:
        run_daemon(path, 4 if cap is None else cap, gap, lease_ttl=args.lease_ttl_seconds, bucket=args.bucket_seconds,
                   grace=args.grace_seconds, startup_hold=start_hold, **kwargs)
    except RuntimeError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    return 0


__all__ = ["LimiterCore", "LimiterServer", "ContactBuckets", "QueuedLogging", "run_daemon", "main"]

if __name__ == "__main__":
    sys.exit(main())
