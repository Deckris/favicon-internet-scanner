"""Client of the connection limiter daemon (``limiterd``), with the interface of ``SubnetLimiter``.

``ContactLedger``, ``IpPacer`` and the favicon stage use it in place of an in-process limiter. It fails closed: while
the daemon cannot be reached every claim is refused, so callers keep waiting and then skip the request at their own
``max_wait``; nothing is ever sent unlimited. A failed call closes the connection and the next attempt is made after
``RETRY_AFTER`` seconds; calls in between are refused at once without touching the socket.

One connection serves all threads of the process and carries its leases: if the process dies the daemon frees them.
The client does not know the daemon's replies to a request that was cut off, and a request in flight when the
connection breaks is no longer counted by the daemon.
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Any, Callable, Iterable, Mapping

from scanner.internet import limiterd as proto
from scanner.internet.pacing import _LIMIT_POLL, _nap, network_key

log = logging.getLogger(__name__)
CONNECT_TIMEOUT = 1.0
IO_TIMEOUT = 5.0
RETRY_AFTER = 0.5


class LimiterUnavailable(OSError):
    """The daemon cannot be reached or refused this client."""


class LimiterClient:
    """Drop-in for ``SubnetLimiter`` backed by the daemon at ``path``.

    ``cap`` and ``gap`` are the limits this process is configured with: the daemon refuses a client whose limits are
    stricter than its own. ``cap`` is also what ``split_by_network`` uses to size groups of one network.
    """

    def __init__(self, path: str, cap: int, gap: float, *, key_of: Callable[[str], str] = network_key,
                 connect_timeout: float = CONNECT_TIMEOUT, io_timeout: float = IO_TIMEOUT, retry_after: float = RETRY_AFTER,
                 now: Callable[[], float] = time.monotonic) -> None:
        self.path, self.cap, self.gap = str(path), max(1, int(cap)), float(gap)
        self.key_of = key_of
        self._connect_timeout, self._io_timeout, self._retry_after, self._now = connect_timeout, io_timeout, retry_after, now
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()           # one request at a time on the socket
        self._down_until = float("-inf")
        self._tickets = 0
        self._queued: set[int] = set()          # tickets the daemon has seen and may still hold a place for
        self._held = 0                          # slots taken here and not yet released
        self._state = threading.Lock()
        self._ttl = 0.0
        self._closed = threading.Event()
        self._keepalive: threading.Thread | None = None
        self._last_error = ""

    # transport

    def _connect(self) -> socket.socket:
        if not hasattr(socket, "AF_UNIX"):
            raise LimiterUnavailable("Unix domain sockets are not available on this platform")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(self._connect_timeout)
            s.connect(self.path)
            s.settimeout(self._io_timeout)
            reply = self._exchange(s, {"op": "hello", "protocol": proto.PROTOCOL, "cap": self.cap, "gap": self.gap})
        except BaseException:
            s.close()
            raise
        if not reply.get("ok"):
            s.close()
            raise LimiterUnavailable(str(reply.get("error", "refused")))
        self._ttl = float(reply.get("lease_ttl", 0.0))
        return s

    @staticmethod
    def _exchange(s: socket.socket, message: dict[str, Any]) -> dict[str, Any]:
        s.sendall(proto.pack_frame(message))
        return proto.decode_frame(_read(s, proto.unpack_length(_read(s, 4))))

    def _call(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """One request and its reply; None if the daemon is unreachable (the caller must then refuse)."""
        if self._closed.is_set():
            return None
        with self._lock:
            now = self._now()
            if now < self._down_until:
                return None
            try:
                if self._sock is None:
                    self._sock = self._connect()
                reply = self._exchange(self._sock, message)
            except (OSError, ValueError) as exc:
                self._drop(exc)
                return None
            if not reply.get("ok"):
                self._drop(LimiterUnavailable(str(reply.get("error", "refused"))))
                return None
            return reply

    def _drop(self, exc: BaseException) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._down_until = self._now() + self._retry_after
        text = f"{type(exc).__name__}: {exc}"
        if text != self._last_error:        # say it once per kind of failure, not on every retry
            self._last_error = text
            log.warning("limiter at %s unavailable, requests wait: %s", self.path, text)

    def close(self) -> None:
        self._closed.set()
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None

    def ping(self) -> bool:
        return self._call({"op": "ping"}) is not None

    def stats(self) -> dict[str, Any] | None:
        reply = self._call({"op": "stats"})
        return None if reply is None else {k: v for k, v in reply.items() if k != "ok"}

    def _ping_while_holding(self) -> None:
        while not self._closed.wait(max(self._ttl / 3.0, 1.0)):
            if self._held > 0:
                self._call({"op": "ping"})

    def _granted(self, n: int) -> None:
        with self._state:
            self._held += n
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

    def _claim(self, message: dict[str, Any], ticket: int | None) -> dict[str, Any] | None:
        reply = self._call({"op": "claim", "ticket": ticket, **message})
        if ticket is not None:
            with self._state:
                if reply is not None and reply.get("granted"):
                    self._queued.discard(ticket)
                elif reply is not None:
                    self._queued.add(ticket)
        return reply if reply is not None and reply.get("granted") else None

    def try_acquire(self, counts: Mapping[str, int], ticket: int | None = None, ips: list[str] | None = None,
                    exclusive: bool = False) -> bool:
        """Take the slots (and, with ``ips``, their pause) in one step or not at all; False if refused or unreachable."""
        message: dict[str, Any] = {"exclusive": exclusive}
        if ips is not None:
            message["ips"] = list(ips)
        else:
            message["counts"] = dict(counts)
        if self._claim(message, ticket) is None:
            return False
        self._granted(sum(counts.values()))
        return True

    def try_acquire_some(self, ips: list[str], ticket: int | None = None, exclusive: bool = False) -> list[str]:
        """The addresses whose network has room and whose pause is over, taken now; the rest are left to the caller."""
        reply = self._claim({"ips": list(ips), "partial": True, "exclusive": exclusive}, ticket)
        if reply is None:
            return []
        got = [ip for ip in reply.get("ips") or [] if isinstance(ip, str)]
        self._granted(len(got))
        return got

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
        """Give the slots back. If the daemon is gone it has freed them with the connection."""
        with self._state:
            self._held = max(0, self._held - sum(counts.values()))
        self._call({"op": "release", "counts": dict(counts), "ips": list(ips) if ips is not None else []})

    def observe(self, ip: str, *, timeout: bool = False, http_status: int | None = None, retry_after: float | None = None) -> None:
        self._observe([{"ip": ip, "timeout": timeout, "http_status": http_status, "retry_after": retry_after}])

    def _observe(self, events: list[dict[str, Any]]) -> None:
        if events:
            self._call({"op": "observe", "events": events})        # a lost report only delays a back-off

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
        reply = self._call({"op": "query", "ip": ip})
        return int(reply["limit"]) if reply else 0          # unreachable: no connection allowed

    def in_flight(self, ip: str) -> int:
        reply = self._call({"op": "query", "ip": ip})
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
