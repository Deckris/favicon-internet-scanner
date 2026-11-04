"""A connection limiter shared by every process of a host: ``python -m scanner.internet limiterd --socket PATH``.

The per-network cap of ``SubnetLimiter`` and the pause between two requests to one address hold inside one process.
When the stages run as separate processes (TLS, HTTP, DNS, SNI, favicon) each would apply them on its own and the
limits would multiply. This daemon keeps them in one place. Processes talk to it through ``limiterclient``.

The daemon owns one ``SubnetLimiter`` (the same network keys, back-off and FIFO tickets as in a single process) and
a ledger of recent contacts. The ledger is a ring of time buckets, ``bucket`` seconds wide, that covers only the
pause: a bucket is dropped once the pause after it has passed, so memory follows the contact rate times the pause, not
the number of addresses ever seen. A contact counts as made at the end of its bucket, which can only make a pause
up to one bucket longer, never shorter.

Leases belong to the connection that took them. When a connection closes, everything it holds is freed: slots,
addresses in flight and places in line. A connection that sends nothing for ``lease_ttl`` seconds is treated as
hung and loses its leases too; clients send a ping at a third of that interval while they hold any.

Protocol: frames of a 4-byte big-endian length and a JSON object. The client opens with ``hello`` (its cap and pause,
which the daemon refuses if they are looser than its own), then sends ``claim``, ``release``, ``withdraw``,
``observe``, ``query``, ``ping`` or ``stats``; every request gets one reply with ``ok``.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import struct
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable

from scanner.internet import pacing
from scanner.internet.pacing import SubnetLimiter

log = logging.getLogger(__name__)
PROTOCOL = 1
MAX_FRAME = 16 * 1024 * 1024
DEFAULT_LEASE_TTL = 300.0
DEFAULT_BUCKET = 1.0
SWEEP_EVERY = 1.0
RETRY_POLL = 0.25               # wait hint for a claim refused only because a network is full or an address in flight


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
    """When addresses were contacted, in buckets of ``width`` seconds, kept only for ``gap`` seconds."""

    def __init__(self, gap: float, width: float = DEFAULT_BUCKET) -> None:
        self.gap = float(gap)
        self.width = max(float(width), 1e-3)
        self._buckets: deque[tuple[int, set[str]]] = deque()       # (bucket index, addresses), oldest first
        self._size = 0

    def _expiry(self, index: int) -> float:
        return (index + 1) * self.width + self.gap

    def add(self, ip: str, now: float) -> None:
        if self.gap <= 0:
            return
        index = int(now // self.width)
        if not self._buckets or self._buckets[-1][0] < index:
            self._buckets.append((index, set()))
        members = self._buckets[-1][1]       # a clock that went back lands in the newest bucket: later, never earlier
        if ip not in members:
            members.add(ip)
            self._size += 1

    def due_in(self, ip: str, now: float) -> float:
        """Seconds until ``ip`` may be contacted again (0 if it may be now)."""
        for index, members in reversed(self._buckets):
            if self._expiry(index) <= now:
                break
            if ip in members:
                return self._expiry(index) - now
        return 0.0

    def prune(self, now: float) -> None:
        while self._buckets and self._expiry(self._buckets[0][0]) <= now:
            self._size -= len(self._buckets.popleft()[1])

    def __len__(self) -> int:
        return self._size

    @property
    def buckets(self) -> int:
        return len(self._buckets)


class _Conn:
    def __init__(self, ident: int, now: float) -> None:
        self.id = ident
        self.counts: dict[str, int] = {}        # slots held per network
        self.ips: set[str] = set()              # addresses in flight (claimed as exclusive)
        self.tickets: dict[int, int] = {}       # the client's ticket -> the daemon's, for places in line
        self.last_seen = now
        self.hello = False
        self.expired = False

    def holds(self) -> bool:
        return bool(self.counts or self.ips or self.tickets)


class LimiterCore:
    """The state and rules of the daemon, without I/O: ``handle(conn, request)`` returns the reply."""

    def __init__(self, cap: int, gap: float, *, now: Callable[[], float] = time.monotonic, lease_ttl: float = DEFAULT_LEASE_TTL,
                 bucket: float = DEFAULT_BUCKET, **backoff: Any) -> None:
        self.cap, self.gap, self.lease_ttl = max(1, int(cap)), float(gap), float(lease_ttl)
        self._now = now
        self.limiter = SubnetLimiter(self.cap, now=now, **backoff)
        self.contacts = ContactBuckets(self.gap, bucket)
        self._busy: dict[str, int] = {}         # address in flight -> connection
        self._conns: dict[int, _Conn] = {}
        self._next_conn = 0
        self.stats: dict[str, int] = {"grants": 0, "refused_full": 0, "refused_gap": 0, "expired": 0, "stale_releases": 0}

    def open(self) -> _Conn:
        self._next_conn += 1
        conn = self._conns[self._next_conn] = _Conn(self._next_conn, self._now())
        return conn

    def close(self, conn: _Conn) -> None:
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
        except (TypeError, ValueError, AttributeError) as exc:
            return {"ok": False, "error": f"bad request: {exc}"}
        return {"ok": False, "error": f"unknown op {op!r}"}

    def snapshot(self) -> dict[str, Any]:
        networks, backoff = self.limiter.tracked()
        return {"connections": len(self._conns), "networks_active": networks, "networks_backoff": backoff,
                "in_flight_addresses": len(self._busy), "ledger_addresses": len(self.contacts),
                "ledger_buckets": self.contacts.buckets, "waiting": len(self.limiter._waiting), **self.stats}

    def _hello(self, conn: _Conn, req: dict[str, Any]) -> dict[str, Any]:
        if req.get("protocol") != PROTOCOL:
            return {"ok": False, "error": f"protocol {req.get('protocol')!r} not supported", "close": True}
        cap, gap = int(req["cap"]), float(req["gap"])
        if self.cap > cap or self.gap < gap:
            return {"ok": False, "close": True, "error": f"daemon allows {self.cap} per network and {self.gap:g} s per address; "
                    f"the client asks for at most {cap} and at least {gap:g} s"}
        conn.hello = True
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

    def _claim(self, conn: _Conn, req: dict[str, Any]) -> dict[str, Any]:
        now = self._now()
        ips = req.get("ips")
        partial, exclusive, theirs = bool(req.get("partial")), bool(req.get("exclusive")), req.get("ticket")
        if ips is not None:
            if not isinstance(ips, list) or not all(isinstance(ip, str) for ip in ips):
                raise ValueError("ips must be a list of strings")
            waits = {ip: self._wait_for(ip, now) for ip in ips}
            ok_ips = [ip for ip in ips if waits[ip] <= 0]
            late = [w for w in waits.values() if w > 0]
            if not ok_ips or (late and not partial):
                self._withdraw(conn, theirs)
                self.stats["refused_gap"] += 1
                return {"ok": True, "granted": False, "reason": "gap", "wait": max(min(late) if partial else max(late), 0.01)}
            mine = self._ticket(conn, theirs)
            if partial:
                got = self.limiter.try_acquire_some(ok_ips, mine)
                counts = self.limiter.counts(got)
            else:
                got = list(ips)
                counts = self.limiter.counts(got)
                if not self.limiter.try_acquire(counts, mine):
                    got = []
        else:
            counts_in = req.get("counts")
            if not isinstance(counts_in, dict):
                raise ValueError("a claim needs ips or counts")
            counts = {str(k): int(n) for k, n in counts_in.items() if int(n) > 0}
            mine = self._ticket(conn, theirs)
            got = [] if not self.limiter.try_acquire(counts, mine) else [None]
        if not got:
            self.stats["refused_full"] += 1
            return {"ok": True, "granted": False, "reason": "full", "wait": RETRY_POLL}
        conn.tickets.pop(theirs, None)      # served: the limiter dropped the place in line itself
        for key, n in counts.items():
            conn.counts[key] = conn.counts.get(key, 0) + n
        if ips is not None:
            for ip in got:
                self.contacts.add(ip, now)
                if exclusive:
                    self._busy[ip] = conn.id
                    conn.ips.add(ip)
        self.stats["grants"] += 1
        return {"ok": True, "granted": True, "ips": got if ips is not None else None}

    def _release(self, conn: _Conn, req: dict[str, Any]) -> dict[str, Any]:
        now = self._now()
        for key, n in (req.get("counts") or {}).items():
            held = conn.counts.get(key, 0)
            take = min(int(n), held)
            if take < int(n):
                self.stats["stale_releases"] += int(n) - take      # already freed (leases expired) or never taken
            if take:
                self.limiter.release({key: take})
                if held - take > 0:
                    conn.counts[key] = held - take
                else:
                    conn.counts.pop(key, None)
        for ip in req.get("ips") or []:
            if ip in conn.ips:
                conn.ips.discard(ip)
                self._busy.pop(ip, None)
                self.contacts.add(ip, now)       # the pause of a claimed address runs from the end of the request
        return {"ok": True}

    def _observe(self, req: dict[str, Any]) -> dict[str, Any]:
        for ev in req.get("events") or []:
            retry_after = ev.get("retry_after")
            self.limiter.observe(str(ev["ip"]), timeout=bool(ev.get("timeout")), http_status=ev.get("http_status"),
                                 retry_after=float(retry_after) if retry_after is not None else None)
        return {"ok": True}


class LimiterServer:
    def __init__(self, core: LimiterCore, path: str | os.PathLike[str]) -> None:
        self.core, self.path = core, str(path)
        self._server: asyncio.AbstractServer | None = None

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = self.core.open()
        try:
            while True:
                try:
                    header = await reader.readexactly(4)
                except asyncio.IncompleteReadError:
                    break
                req = decode_frame(await reader.readexactly(unpack_length(header)))
                reply = self.core.handle(conn, req)
                writer.write(pack_frame(reply))
                await writer.drain()
                if reply.get("close"):
                    break
        except (ConnectionError, asyncio.IncompleteReadError, ValueError, UnicodeDecodeError) as exc:
            log.info("connection %d dropped: %s", conn.id, exc)
        finally:
            self.core.close(conn)
            writer.close()

    def _claim_path(self) -> None:
        """Remove a socket file left by a daemon that is gone; refuse to start over a live one."""
        if not os.path.exists(self.path):
            return
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(1.0)
        try:
            probe.connect(self.path)
        except OSError:
            os.unlink(self.path)
        else:
            raise RuntimeError(f"a limiter daemon is already listening on {self.path}")
        finally:
            probe.close()

    async def start(self) -> None:
        self._claim_path()
        old = os.umask(0o117)           # the socket is created 0660, never wider, even for an instant
        try:
            self._server = await asyncio.start_unix_server(self._serve, path=self.path)
        finally:
            os.umask(old)
        os.chmod(self.path, 0o660)

    async def sweeper(self) -> None:
        while True:
            await asyncio.sleep(SWEEP_EVERY)
            self.core.sweep()

    async def run(self, stop: asyncio.Event) -> None:
        await self.start()
        task = asyncio.create_task(self.sweeper())
        try:
            await stop.wait()
        finally:
            task.cancel()
            assert self._server is not None
            self._server.close()
            try:
                os.unlink(self.path)
            except OSError:
                pass


def run_daemon(path: str | os.PathLike[str], cap: int, gap: float, *, lease_ttl: float = DEFAULT_LEASE_TTL,
               bucket: float = DEFAULT_BUCKET, retry_after_max_hold: float = pacing.DEFAULT_RETRY_AFTER_MAX_HOLD) -> None:
    """Serve until SIGTERM or SIGINT."""
    import signal

    core = LimiterCore(cap, gap, lease_ttl=lease_ttl, bucket=bucket, max_hold=retry_after_max_hold)

    async def main() -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        server = LimiterServer(core, Path(path))
        log.info("limiter listening on %s: %d per network, %g s per address", path, core.cap, core.gap)
        await server.run(stop)

    asyncio.run(main())


__all__ = ["LimiterCore", "LimiterServer", "ContactBuckets", "run_daemon"]
