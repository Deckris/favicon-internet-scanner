"""Hostname-aware, IP-pinned HTTP(S) acquisition layer.

The client always opens its TCP connection to a caller-supplied IP while the
HTTP ``Host`` header and TLS SNI carry the measured hostname, so document and
favicon acquisition never depends on local DNS resolution. Every destination
and redirect hop clears the central :class:`~scanner.safety.TargetPolicy`
before a socket is opened. This replaces a hand-written parser
with a standards-capable client while keeping full control over bytes read,
decoding and timing so slow-drip and decompression-bomb fixtures stay bounded.
"""
from __future__ import annotations

import gzip
import hashlib
import contextlib
import ipaddress
import os
import socket
import ssl
import threading
import time
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Callable, Protocol, runtime_checkable
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx
from httpcore._backends.sync import SyncStream

from scanner.models import CertificateInfo, FetchResult, RedirectHop
from scanner.safety import TargetPolicy

try:
    import brotli
except ImportError:  # pragma: no cover - optional at import time, required at runtime
    brotli = None

DEFAULT_PORTS = {"http": 80, "https": 443}
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True)
class FetchLimits:
    connect_timeout: float
    read_timeout: float
    total_timeout: float
    max_bytes: int
    max_decoded_bytes: int
    max_redirects: int


@runtime_checkable
class Resolver(Protocol):
    def resolve_a(self, hostname: str) -> list[str]:
        """Current A-record answers for ``hostname``, or ``[]``/raise on failure."""


class _TooLarge(Exception):
    def __init__(self, outcome: str) -> None:
        super().__init__(outcome)
        self.outcome = outcome


class _StreamDecoder:
    """Incremental content-encoding decoder bounded by ``max_decoded``."""

    def __init__(self, encoding: str | None, max_decoded: int) -> None:
        self._max_decoded = max_decoded
        self._total = 0
        self._encoding = (encoding or "identity").strip().lower()
        self._zlib: zlib.decompressobj | None = None
        self._brotli = None
        if self._encoding in ("gzip", "x-gzip"):
            self._zlib = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif self._encoding == "deflate":
            self._zlib = zlib.decompressobj()
        elif self._encoding == "br":
            if brotli is None:
                raise _TooLarge("unsupported_encoding")
            self._brotli = brotli.Decompressor()
        elif self._encoding not in ("identity", ""):
            raise _TooLarge("unsupported_encoding")

    def feed(self, chunk: bytes) -> bytes:
        if self._zlib is not None:
            out = self._zlib.decompress(chunk, self._max_decoded - self._total + 1)
            while self._zlib.unconsumed_tail and self._total + len(out) <= self._max_decoded:
                out += self._zlib.decompress(self._zlib.unconsumed_tail, self._max_decoded - self._total - len(out) + 1)
        elif self._brotli is not None:
            room = self._max_decoded - self._total + 1
            out = self._brotli.process(chunk, output_buffer_limit=room)
            while not self._brotli.can_accept_more_data() and self._total + len(out) <= self._max_decoded:
                out += self._brotli.process(b"", output_buffer_limit=self._max_decoded - self._total - len(out) + 1)
        else:
            out = chunk
        self._total += len(out)
        if self._total > self._max_decoded:
            raise _TooLarge("decoded_too_large")
        return out


def _default_port(scheme: str) -> int:
    return DEFAULT_PORTS[scheme]


def _host_header(hostname: str, port: int, scheme: str) -> str:
    return hostname if port == _default_port(scheme) else f"{hostname}:{port}"


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _raw_shutdown(sock: socket.socket) -> None:
    # socket.socket.shutdown, not SSLSocket.shutdown: the latter also drops the SSL object another thread is reading from.
    socket.socket.shutdown(sock, socket.SHUT_RDWR)


def _raw_close(sock: socket.socket) -> None:
    sock.close()


class _SocketGuard:
    """Sockets of one request, shared between the worker and its watchdog.

    The watchdog may only ``shutdown`` a socket: that wakes a thread blocked in recv or SSL_read with EOF but leaves the
    descriptor allocated. Closing it from another thread would free the number while OpenSSL still reads from it, and the
    number can be handed to an unrelated socket. Only the worker closes, and both go through one lock so a shutdown never
    meets a descriptor that was just closed.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._socks: list[socket.socket] = []
        self._closed: set[int] = set()
        self.expired = False

    def attach(self, sock: socket.socket) -> None:
        with self._lock:
            if self.expired:
                raise OSError("request expired")
            self._socks.append(sock)

    def expire(self) -> None:
        with self._lock:
            self.expired = True
            for sock in self._socks:
                if id(sock) in self._closed:
                    continue
                try:
                    _raw_shutdown(sock)
                except OSError:
                    pass

    def close(self, sock: socket.socket | None = None) -> None:
        with self._lock:
            for item in ([sock] if sock is not None else list(self._socks)):
                if id(item) in self._closed:
                    continue
                self._closed.add(id(item))
                try:
                    _raw_close(item)
                except OSError:
                    pass


class _Watch:
    """One request's registration with the watchdog service."""

    def __init__(self, service: "_WatchdogService", deadline: float, killed: Callable[[], bool], expire: Callable[[], None]) -> None:
        self._service = service
        self.deadline = deadline
        self.killed = killed
        self._expire = expire
        self._lock = threading.Lock()
        self._done = False
        self.fired = threading.Event()

    def fire(self) -> None:
        with self._lock:
            if self._done:
                return
            self.fired.set()
            self._done = True
            try:
                self._expire()
            except Exception:
                pass

    def finish(self) -> None:
        """Called by the worker when the request is over; once this returns the watchdog never fires for it."""
        with self._lock:
            self._done = True
        self._service.forget(self)


class _WatchdogService:
    """One thread that enforces the wall-clock cap of every request in flight.

    A thread per request costs a thread start and stop on each fetch; here the requests register a deadline and an
    ``expire`` callback instead. The thread sleeps until the earliest deadline (a request with an earlier one wakes
    it), so a deadline is met on time. A second thread asks the kill switches once per ``TICK`` seconds, however
    many requests share one, so a switch that is slow to answer delays only the kill check, never a deadline; one
    that raises counts as not set. Both end after ``IDLE`` seconds without a request and are started again by the
    next one.
    """

    TICK = 0.25
    IDLE = 1.0

    def __init__(self) -> None:
        self._reset()

    def _reset(self) -> None:
        self._cond = threading.Condition()
        self._entries: set[_Watch] = set()
        self._thread: threading.Thread | None = None
        self._kill_thread: threading.Thread | None = None
        self._sleeping_idle = False
        self._wake_at = float("inf")            # when the deadline thread next looks, if it is asleep

    def watch(self, deadline: float, killed: Callable[[], bool], expire: Callable[[], None]) -> _Watch:
        """Registers a request; raises ``RuntimeError`` when the service thread cannot be started."""
        entry = _Watch(self, deadline, killed, expire)
        with self._cond:
            if self._thread is None or not self._thread.is_alive():
                thread = threading.Thread(target=self._run, daemon=True)
                thread.start()
                self._thread = thread
            if self._kill_thread is None or not self._kill_thread.is_alive():
                kill_thread = threading.Thread(target=self._run_kills, daemon=True)
                kill_thread.start()
                self._kill_thread = kill_thread
            self._entries.add(entry)
            if self._sleeping_idle or entry.deadline < self._wake_at:
                self._cond.notify()
        return entry

    def forget(self, entry: _Watch) -> None:
        with self._cond:
            self._entries.discard(entry)

    def _run(self) -> None:
        me = threading.current_thread()
        while True:
            with self._cond:
                if not self._entries:
                    self._sleeping_idle = True
                    try:
                        self._cond.wait(self.IDLE)
                    finally:
                        self._sleeping_idle = False
                    if not self._entries:
                        if self._thread is me:
                            self._thread = None
                        return
                entries = list(self._entries)
            now = time.monotonic()
            for entry in entries:
                if now >= entry.deadline:
                    entry.fire()
                    self.forget(entry)
            soonest = min((e.deadline for e in entries if not e.fired.is_set()), default=now + self.TICK)
            delay = max(0.0, min(self.TICK, soonest - time.monotonic()))
            with self._cond:
                self._wake_at = time.monotonic() + delay
                try:
                    self._cond.wait(delay)
                finally:
                    self._wake_at = float("inf")

    def _run_kills(self) -> None:
        me = threading.current_thread()
        while True:
            with self._cond:
                entries = list(self._entries)
                if not entries:
                    if self._kill_thread is me:
                        self._kill_thread = None
                    return
            stops: dict[int, bool] = {}
            for entry in entries:
                if entry.fired.is_set():
                    continue
                key = id(entry.killed)
                if key not in stops:
                    try:
                        stops[key] = bool(entry.killed())
                    except Exception:
                        stops[key] = False
                if stops[key]:
                    entry.fire()
                    self.forget(entry)
            time.sleep(self.TICK)


_WATCHDOG = _WatchdogService()


def _after_fork_in_child() -> None:
    """A forked favicon process keeps neither the watchdog threads, nor a lock another thread held at the fork, nor
    the forking thread's client."""
    global _SSL_LOCK
    _WATCHDOG._reset()
    _SSL_LOCK = threading.Lock()
    _LOCAL.__dict__.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


_SLICE = 0.25


def _sliced_io(sock, guard, call, timeout, timeout_exc, error_exc):
    end = None if timeout is None else time.monotonic() + timeout
    while True:
        if guard.expired:
            raise error_exc(OSError("request expired"))
        remaining = _SLICE if end is None else min(_SLICE, max(end - time.monotonic(), 0.001))
        try:
            sock.settimeout(remaining)
            return call()
        except socket.timeout as exc:
            if end is not None and time.monotonic() >= end:
                raise timeout_exc(exc) from exc
        except OSError as exc:
            raise error_exc(exc) from exc


class _GuardedStream(SyncStream):
    def __init__(self, sock: socket.socket, guard: _SocketGuard) -> None:
        super().__init__(sock)
        self._guard = guard

    def close(self) -> None:
        self._guard.close(self._sock)

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._sliced(lambda: self._sock.recv(max_bytes), timeout, httpcore.ReadTimeout, httpcore.ReadError)

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        while buffer:
            sent = self._sliced(lambda: self._sock.send(buffer), timeout, httpcore.WriteTimeout, httpcore.WriteError)
            buffer = buffer[sent:]

    def _sliced(self, call, timeout, timeout_exc, error_exc):
        # Waits in short slices so an expired request is noticed even where shutdown does not wake a blocked call.
        return _sliced_io(self._sock, self._guard, call, timeout, timeout_exc, error_exc)

    def start_tls(self, ssl_context: ssl.SSLContext, server_hostname: str | None = None, timeout: float | None = None):
        tls = None
        try:
            self._sock.settimeout(timeout)
            tls = ssl_context.wrap_socket(self._sock, server_hostname=server_hostname, do_handshake_on_connect=False)
            self._guard.attach(tls)
            _sliced_io(tls, self._guard, tls.do_handshake, timeout, httpcore.ConnectTimeout, httpcore.ConnectError)
        except socket.timeout as exc:
            self._abort(tls)
            raise httpcore.ConnectTimeout(exc) from exc
        except OSError as exc:
            self._abort(tls)
            raise httpcore.ConnectError(exc) from exc
        except BaseException:
            self._abort(tls)
            raise
        return _GuardedStream(tls, self._guard)

    def _abort(self, tls: socket.socket | None) -> None:
        if tls is not None:
            self._guard.close(tls)
        self._guard.close(self._sock)


class _GuardedBackend(httpcore.SyncBackend):
    """Opens sockets the watchdog can reach from the first moment of the connect."""

    def __init__(self, guard: _SocketGuard) -> None:
        super().__init__()
        self._guard = guard

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        source = None if local_address is None else (local_address, 0)
        try:
            error: OSError | None = None
            for family, kind, proto, _name, address in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
                sock = socket.socket(family, kind, proto)
                try:
                    self._guard.attach(sock)
                    sock.settimeout(timeout)
                    if source is not None:
                        sock.bind(source)
                    sock.connect(address)
                    if self._guard.expired:
                        raise OSError("request expired")
                    for option in socket_options or ():
                        sock.setsockopt(*option)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError as exc:
                    self._guard.close(sock)
                    if self._guard.expired:
                        raise
                    error = exc
                    continue
                except BaseException:
                    self._guard.close(sock)
                    raise
                return _GuardedStream(sock, self._guard)
            raise error or OSError("no address")
        except socket.timeout as exc:
            raise httpcore.ConnectTimeout(exc) from exc
        except OSError as exc:
            raise httpcore.ConnectError(exc) from exc


class _ThreadGuardBackend(_GuardedBackend):
    """The same backend for a client that outlives a request: the guard is the one of the request this thread is running."""

    def __init__(self) -> None:
        httpcore.SyncBackend.__init__(self)

    @property
    def _guard(self) -> _SocketGuard:           # type: ignore[override]
        guard = getattr(_LOCAL, "guard", None)
        if guard is None:
            raise httpcore.ConnectError(OSError("no request in progress"))
        return guard


_LOCAL = threading.local()
_SSL_LOCK = threading.Lock()
_SSL_CONTEXT: ssl.SSLContext | None = None


def _thread_client() -> httpx.Client:
    global _SSL_CONTEXT
    with _SSL_LOCK:         # the transport sets the ALPN list on the context it is given
        if _SSL_CONTEXT is None:
            _SSL_CONTEXT = httpx.create_ssl_context(verify=False)
        transport = httpx.HTTPTransport(verify=_SSL_CONTEXT, http2=False, trust_env=False,
                                        limits=httpx.Limits(max_connections=None, max_keepalive_connections=0))
    transport._pool._network_backend = _ThreadGuardBackend()
    return httpx.Client(transport=transport, trust_env=False, follow_redirects=False)


@contextlib.contextmanager
def _request_client(guard: _SocketGuard):
    """The calling thread's client, bound to ``guard`` for one request.

    Building a client builds a pool and a transport, which a fetch of a few kilobytes does not need to repeat.
    Nothing is kept alive between requests: the pool holds no idle connection, and whatever it still holds when
    the request ends is closed.
    """
    client = getattr(_LOCAL, "client", None)
    if client is None:
        client = _LOCAL.client = _thread_client()
    client.cookies.clear()          # the client outlives the request: no cookie may carry over to another host or port
    _LOCAL.guard = guard
    try:
        yield client
    finally:
        _LOCAL.guard = None
        client.cookies.clear()
        pool = client._transport._pool
        if pool.connections:
            pool.close()


_CLIP_MARGIN = 0.1


def _clipped_timeout(limits: FetchLimits, deadline: float) -> httpx.Timeout:
    """Per-phase timeouts, none longer than what is left of the request's wall-clock budget. They end a little after
    the deadline so that the watchdog, which acts at the deadline, stays the one that ends a request."""
    left = max(deadline - time.monotonic(), 0.0) + _CLIP_MARGIN
    connect, read = min(limits.connect_timeout, left), min(limits.read_timeout, left)
    return httpx.Timeout(connect=connect, read=read, write=read, pool=connect)


def _caused_by(exc: BaseException | None, kind: type) -> bool:
    """Whether ``kind`` appears anywhere in the chain of causes: httpx wraps the httpcore error, which wraps the socket one."""
    seen = 0
    while exc is not None and seen < 8:
        if isinstance(exc, kind):
            return True
        exc, seen = exc.__cause__ or exc.__context__, seen + 1
    return False


def _guarded_client(guard: _SocketGuard) -> httpx.Client:
    transport = httpx.HTTPTransport(verify=False, http2=False, trust_env=False)
    transport._pool._network_backend = _GuardedBackend(guard)
    return httpx.Client(transport=transport, trust_env=False, follow_redirects=False)


class WebFetcher:
    def __init__(
        self,
        policy: TargetPolicy,
        resolver: Resolver,
        *,
        user_agent: str,
        document_limits: FetchLimits,
        favicon_limits: FetchLimits,
        retry_statuses: tuple[int, ...] = (429, 503),
        max_retries: int = 1,
        retry_after_cap: float = 2.0,
        killed: Callable[[], bool] = lambda: False,
    ) -> None:
        self.policy = policy
        self.resolver = resolver
        self.user_agent = user_agent
        self.document_limits = document_limits
        self.favicon_limits = favicon_limits
        self.retry_statuses = retry_statuses
        self.max_retries = max_retries
        self.retry_after_cap = retry_after_cap
        self.killed = killed

    def fetch(self, url: str, *, connect_ip: str | None, kind: str, context: str = "") -> tuple[FetchResult, bytes | None]:
        limits = self.favicon_limits if kind == "favicon" else self.document_limits
        budget = limits.total_timeout       # request time left; waits for the pacer never count against it
        chain: list[RedirectHop] = []
        visited: set[tuple[str, str | None]] = set()
        current_url = url
        current_ip = connect_ip
        retries = 0
        started = time.monotonic()
        is_retry = False

        while True:
            try:
                parts = urlsplit(current_url)
            except ValueError:
                return self._failure(url, current_ip, None, None, "protocol_error", "unparsable_url", chain, started, kind=kind), None

            if parts.scheme not in ("http", "https"):
                return self._failure(current_url, current_ip, None, None, "policy_refused", "unsafe_scheme", chain, started, kind=kind), None
            hostname = parts.hostname
            if not hostname:
                return self._failure(current_url, current_ip, None, None, "policy_refused", "invalid_hostname", chain, started, kind=kind), None
            try:
                port = parts.port or _default_port(parts.scheme)
            except ValueError:
                return self._failure(current_url, current_ip, None, None, "protocol_error", "unparsable_url", chain, started, kind=kind), None

            if current_ip is None:
                refusal = self.policy.check_url(current_url, stage="document" if kind == "document" else "favicon", context=context)
                if refusal is not None:
                    return self._failure(current_url, None, None, None, "policy_refused", refusal.reason, chain, started, kind=kind), None
                if _is_ip_literal(hostname):
                    current_ip = hostname
                else:
                    current_ip = self._resolve_one(hostname, stage="favicon", context=context)
                    if current_ip is None:
                        return self._failure(current_url, None, hostname, None, "dns_failure", "no_current_answer", chain, started, kind=kind), None

            dedupe_key = (current_url, current_ip)
            if is_retry:
                is_retry = False
            else:
                if dedupe_key in visited:
                    return self._failure(current_url, current_ip, hostname, None, "redirect_loop", "repeat_url", chain, started, kind=kind), None
                visited.add(dedupe_key)

            refusal = self.policy.check_ip(current_ip, stage="document" if kind == "document" else "favicon", context=context)
            if refusal is not None:
                return self._failure(current_url, current_ip, hostname, None, "policy_refused", refusal.reason, chain, started, kind=kind), None

            remaining = budget
            if remaining <= 0:
                return self._failure(current_url, current_ip, hostname, None, "timeout", "total_deadline", chain, started, kind=kind), None

            outcome = self._one_request(
                parts, hostname, port, current_ip, limits, min(remaining, limits.total_timeout), None,
            )
            budget -= outcome.elapsed

            if outcome.kind == "transport":
                return self._finish(outcome, chain, started, kind=kind), outcome.body

            if outcome.http_status in REDIRECT_STATUSES and len(chain) < limits.max_redirects:
                location = outcome.location
                if not location:
                    return self._finish(outcome, chain, started, override_outcome="http_status", kind=kind), outcome.body
                next_url = urljoin(current_url, location)
                next_parts = urlsplit(next_url)
                if next_parts.scheme not in ("http", "https") or not next_parts.hostname:
                    chain.append(RedirectHop(from_url=current_url, status=outcome.http_status, location=location, to_url=None, connect_ip=None, decision="unsupported_scheme"))
                    return self._failure(current_url, current_ip, hostname, outcome.http_status, "policy_refused", "unsafe_scheme", chain, started, kind=kind), outcome.body

                try:
                    next_port = next_parts.port or _default_port(next_parts.scheme)
                except ValueError:
                    return self._failure(current_url, current_ip, hostname, outcome.http_status, "protocol_error", "unparsable_url", chain, started, kind=kind), outcome.body
                next_hostname = next_parts.hostname
                same_host_port = next_hostname == hostname and next_port == port

                if same_host_port:
                    next_ip = current_ip
                    decision_refusal = None
                elif _is_ip_literal(next_hostname):
                    next_ip = next_hostname
                    decision_refusal = self.policy.check_ip(next_ip, stage="document_redirect" if kind == "document" else "favicon_redirect", context=current_url)
                else:
                    next_ip, decision_refusal = self._resolve_redirect(next_hostname, kind, current_url)

                if decision_refusal is not None:
                    chain.append(RedirectHop(from_url=current_url, status=outcome.http_status, location=location, to_url=next_url, connect_ip=None, decision="policy_refused"))
                    return self._failure(current_url, current_ip, hostname, outcome.http_status, "policy_refused", decision_refusal, chain, started, kind=kind), outcome.body
                if next_ip is None:
                    chain.append(RedirectHop(from_url=current_url, status=outcome.http_status, location=location, to_url=next_url, connect_ip=None, decision="dns_failure"))
                    return self._failure(current_url, current_ip, hostname, outcome.http_status, "dns_failure", "no_current_answer", chain, started, kind=kind), outcome.body

                chain.append(RedirectHop(from_url=current_url, status=outcome.http_status, location=location, to_url=next_url, connect_ip=next_ip, decision="followed"))
                current_url, current_ip = next_url, next_ip
                continue

            if outcome.http_status in REDIRECT_STATUSES and len(chain) >= limits.max_redirects:
                return self._finish(outcome, chain, started, override_outcome="too_many_redirects", kind=kind), outcome.body

            if outcome.http_status in self.retry_statuses and retries < self.max_retries:
                retries += 1
                delay = min(outcome.retry_after_seconds or 1.0, self.retry_after_cap)
                remaining_after_sleep = budget - delay
                if remaining_after_sleep <= 0:
                    outcome.retries = retries
                    return self._finish(outcome, chain, started, kind=kind), outcome.body
                time.sleep(max(delay, 0.0))
                budget -= delay
                outcome.retries = retries
                is_retry = True
                continue

            outcome.retries = retries
            return self._finish(outcome, chain, started, kind=kind), outcome.body

    # ------------------------------------------------------------------ helpers

    def _resolve_one(self, hostname: str, *, stage: str, context: str) -> str | None:
        try:
            answers = list(self.resolver.resolve_a(hostname))
        except Exception:
            return None
        allowed = sorted(ip for ip in answers if self.policy.check_ip(ip, stage=stage, context=context) is None)
        return allowed[0] if allowed else None

    def _resolve_redirect(self, hostname: str, kind: str, context: str) -> tuple[str | None, str | None]:
        stage = "document_redirect" if kind == "document" else "favicon_redirect"
        name_refusal = self.policy.check_hostname(hostname, stage=stage, context=context)
        if name_refusal is not None:
            return None, name_refusal.reason
        try:
            answers = list(self.resolver.resolve_a(hostname))
        except Exception:
            return None, None
        if not answers:
            return None, None
        refusal_reason: str | None = None
        allowed: list[str] = []
        for ip in answers:
            refusal = self.policy.check_ip(ip, stage=stage, context=context)
            if refusal is None:
                allowed.append(ip)
            else:
                refusal_reason = refusal.reason
        if allowed:
            return sorted(allowed)[0], None
        return None, refusal_reason or "outside_population"

    def _one_request(self, parts, hostname: str, port: int, connect_ip: str, limits: FetchLimits, timeout: float, deadline: float | None = None) -> "_RequestOutcome":
        """One request under a hard wall-clock cap: httpx's read timeout restarts on every byte, so a server that drips
        its response headers would otherwise hold a worker for as long as it likes. The cap starts here, when the request
        does, so time spent waiting for the pacer is not taken out of it.

        At the cap the watchdog only shuts the sockets down (see :class:`_SocketGuard`); the worker unwinds on the
        resulting EOF or error and closes everything itself. The watchdog is the shared :class:`_WatchdogService`."""
        started = time.monotonic()
        request_deadline = started + timeout
        if deadline is not None:
            request_deadline = min(request_deadline, deadline)
        guard = _SocketGuard()

        def transport_outcome(outcome: str) -> "_RequestOutcome":
            return _RequestOutcome(kind="transport", outcome=outcome, http_status=None, content_type=None, content_encoding=None, location=None,
                                   body=None, body_bytes=0, certificate=None, retry_after_seconds=None, connect_ip=connect_ip,
                                   host_header=_host_header(hostname, port, parts.scheme), sni=None, final_url=f"{parts.scheme}://{connect_ip}:{port}",
                                   elapsed=time.monotonic() - started)

        try:
            watch = _WATCHDOG.watch(request_deadline, self.killed, guard.expire)
        except RuntimeError:
            return transport_outcome("fetch_error")
        try:
            result = self._one_request_inner(parts, hostname, port, connect_ip, limits, timeout, request_deadline, guard)
        except Exception:
            if not watch.fired.is_set():
                raise
            result = None
        finally:
            watch.finish()
            guard.close()
        # Once the watchdog has shut the sockets, an EOF can end a body without a length early,
        # so nothing read after that point is trusted.
        if result is None or watch.fired.is_set():
            return transport_outcome("timeout")
        result.elapsed = time.monotonic() - started
        return result

    def _one_request_inner(self, parts, hostname: str, port: int, connect_ip: str, limits: FetchLimits, timeout: float, deadline: float, guard: _SocketGuard) -> "_RequestOutcome":
        scheme = parts.scheme
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        request_url = f"{scheme}://{connect_ip}:{port}{path}"
        sni = None if _is_ip_literal(hostname) else hostname
        headers = {"Host": _host_header(hostname, port, scheme), "User-Agent": self.user_agent, "Accept-Encoding": "gzip, deflate, br"}
        extensions: dict = {}
        if sni is not None:
            extensions["sni_hostname"] = sni

        raw_chunks: list[bytes] = []
        raw_total = 0
        cert_info: CertificateInfo | None = None
        final_url = request_url

        try:
            with _request_client(guard) as client:
                request = client.build_request("GET", request_url, headers=headers, extensions=extensions)
                with client.stream("GET", request_url, headers=headers, extensions=extensions, timeout=_clipped_timeout(limits, deadline)) as response:
                    cert_info = self._extract_certificate(response, connect_ip, port, sni)
                    content_encoding = response.headers.get("content-encoding")
                    try:
                        decoder = _StreamDecoder(content_encoding, limits.max_decoded_bytes)
                    except _TooLarge as exc:
                        drained = 0
                        for chunk in response.iter_raw():
                            drained += len(chunk)
                            if drained > limits.max_bytes or time.monotonic() > deadline:
                                break
                        return _RequestOutcome(
                            kind="transport", outcome=exc.outcome, http_status=response.status_code,
                            content_type=response.headers.get("content-type"), content_encoding=content_encoding,
                            location=response.headers.get("location"), body=None, body_bytes=0,
                            certificate=cert_info, retry_after_seconds=None, connect_ip=connect_ip,
                            host_header=headers["Host"], sni=sni, final_url=final_url,
                        )
                    decoded_chunks: list[bytes] = []
                    for chunk in response.iter_raw():
                        if time.monotonic() > deadline:
                            return _RequestOutcome(
                                kind="transport", outcome="timeout", http_status=None, content_type=None,
                                content_encoding=content_encoding, location=None, body=None, body_bytes=raw_total,
                                certificate=cert_info, retry_after_seconds=None, connect_ip=connect_ip,
                                host_header=headers["Host"], sni=sni, final_url=final_url,
                            )
                        raw_total += len(chunk)
                        if raw_total > limits.max_bytes:
                            # How far past the cap the read got depends on chunk
                            # boundaries; record the cap so repeats stay identical.
                            return _RequestOutcome(
                                kind="transport", outcome="body_too_large", http_status=response.status_code, content_type=response.headers.get("content-type"),
                                content_encoding=content_encoding, location=response.headers.get("location"), body=None, body_bytes=limits.max_bytes,
                                certificate=cert_info, retry_after_seconds=None, connect_ip=connect_ip,
                                host_header=headers["Host"], sni=sni, final_url=final_url,
                            )
                        raw_chunks.append(chunk)
                        try:
                            decoded_chunks.append(decoder.feed(chunk))
                        except _TooLarge as exc:
                            return _RequestOutcome(
                                kind="transport", outcome=exc.outcome, http_status=response.status_code, content_type=response.headers.get("content-type"),
                                content_encoding=content_encoding, location=response.headers.get("location"), body=None, body_bytes=raw_total,
                                certificate=cert_info, retry_after_seconds=None, connect_ip=connect_ip,
                                host_header=headers["Host"], sni=sni, final_url=final_url,
                            )
                    body = b"".join(decoded_chunks)
                    status = response.status_code
                    return _RequestOutcome(
                        kind="status", outcome="ok" if 200 <= status < 300 else "http_status", http_status=status,
                        content_type=response.headers.get("content-type"), content_encoding=content_encoding,
                        location=response.headers.get("location"), body=body, body_bytes=len(body),
                        certificate=cert_info, retry_after_seconds=_parse_retry_after(response.headers.get("retry-after")),
                        connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url,
                        raw_retry_after=response.headers.get("retry-after"),
                    )
        except httpx.ConnectTimeout:
            return _RequestOutcome(kind="transport", outcome="timeout", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=0, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except httpx.ReadTimeout:
            return _RequestOutcome(kind="transport", outcome="timeout", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=raw_total, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except httpx.PoolTimeout:
            return _RequestOutcome(kind="transport", outcome="timeout", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=0, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except httpx.RemoteProtocolError:
            return _RequestOutcome(kind="transport", outcome="protocol_error", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=raw_total, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except httpx.ReadError as exc:
            cause = exc.__cause__
            outcome_name = "reset" if isinstance(cause, ConnectionResetError) or "reset" in str(exc).lower() else "connect_error"
            return _RequestOutcome(kind="transport", outcome=outcome_name, http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=raw_total, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except ConnectionResetError:
            return _RequestOutcome(kind="transport", outcome="reset", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=raw_total, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except (httpx.ConnectError,) as exc:
            if _caused_by(exc, ssl.SSLError):
                return _RequestOutcome(kind="transport", outcome="tls_error", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=0, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
            return _RequestOutcome(kind="transport", outcome="connect_error", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=0, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except httpx.TimeoutException:
            return _RequestOutcome(kind="transport", outcome="timeout", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=raw_total, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except httpx.HTTPError:
            return _RequestOutcome(kind="transport", outcome="protocol_error", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=raw_total, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)

    def _extract_certificate(self, response: httpx.Response, connect_ip: str, port: int, sni: str | None) -> CertificateInfo | None:
        network_stream = response.extensions.get("network_stream")
        if network_stream is None:
            return None
        try:
            ssl_object = network_stream.get_extra_info("ssl_object")
        except Exception:
            return None
        if ssl_object is None:
            return None
        try:
            # httpcore exposes the raw low-level `_ssl._SSLSocket` C object
            # here, not the `ssl.SSLSocket` wrapper -- its `getpeercert`
            # only accepts the binary-form flag positionally and raises
            # TypeError on `binary_form=True`, so the flag is passed positionally.
            der = ssl_object.getpeercert(True)
        except Exception:
            return None
        if not der:
            return None
        try:
            from scanner.certificates import parse_der
        except ImportError:
            return None
        try:
            return parse_der(
                der,
                handshake_mode="hostname_aware" if sni is not None else "direct_ip",
                sni_sent=sni,
                observed_at=datetime.now(UTC),
                target_ip=connect_ip,
                port=port,
            )
        except Exception:
            return None

    def _failure(self, url, connect_ip, hostname, http_status, outcome, reason, chain, started, kind="document") -> FetchResult:
        return FetchResult(
            kind=kind, requested_url=url, connect_ip=connect_ip, host_header=hostname, sni=None,
            outcome=outcome, failure_category=reason, http_status=http_status, content_type=None,
            content_encoding=None, retry_after=None, body_sha256=None, body_bytes=0,
            redirect_chain=tuple(chain), final_url=None, certificate=None, retries=0,
            timing_ms=round((time.monotonic() - started) * 1000, 3),
        )

    def _finish(self, outcome: "_RequestOutcome", chain: list[RedirectHop], started: float, *, override_outcome: str | None = None, kind: str = "document") -> FetchResult:
        body = outcome.body
        return FetchResult(
            kind=kind, requested_url=outcome.final_url, connect_ip=outcome.connect_ip, host_header=outcome.host_header,
            sni=outcome.sni, outcome=override_outcome or outcome.outcome, failure_category=None if (override_outcome or outcome.outcome) in ("ok", "http_status") else (override_outcome or outcome.outcome),
            http_status=outcome.http_status, content_type=outcome.content_type, content_encoding=outcome.content_encoding,
            retry_after=getattr(outcome, "raw_retry_after", None), body_sha256=_sha256(body) if body is not None else None,
            body_bytes=outcome.body_bytes, redirect_chain=tuple(chain), final_url=outcome.final_url if body is not None or outcome.outcome in ("ok", "http_status") else None,
            certificate=outcome.certificate, retries=getattr(outcome, "retries", 0),
            timing_ms=round((time.monotonic() - started) * 1000, 3),
        )


@dataclass
class _RequestOutcome:
    kind: str
    outcome: str
    http_status: int | None
    content_type: str | None
    content_encoding: str | None
    location: str | None
    body: bytes | None
    body_bytes: int
    certificate: CertificateInfo | None
    retry_after_seconds: float | None
    connect_ip: str | None
    host_header: str | None
    sni: str | None
    final_url: str | None
    raw_retry_after: str | None = None
    retries: int = 0
    elapsed: float = 0.0


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(int(value.strip()))
    except ValueError:
        return None
