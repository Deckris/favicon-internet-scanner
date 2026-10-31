"""The per-request wall-clock cap holds against servers that stall, drip or stop mid-TLS, and never frees a descriptor
another thread is still reading from."""
import datetime
import os
import socket
import ssl
import sys
import threading
import time

import pytest

from scanner import web_fetch
from scanner.internet.favicon import GuardedFetcher
from scanner.safety import TargetPolicy
from scanner.web_fetch import FetchLimits, WebFetcher

LOOPBACK = "127.0.0.1"


def _limits(total=1.5, read=30.0, max_bytes=10_000):
    return FetchLimits(connect_timeout=3.0, read_timeout=read, total_timeout=total, max_bytes=max_bytes, max_decoded_bytes=max_bytes, max_redirects=1)


def _fetcher(cls=WebFetcher, limits=None, **kw):
    lim = limits or _limits()
    return cls(TargetPolicy.for_tests(["127.0.0.1/32"]), None, user_agent="t", document_limits=lim, favicon_limits=lim, **kw)


@pytest.fixture(scope="module")
def tls_context(tmp_path_factory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    d = tmp_path_factory.mktemp("tls")
    (d / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "c.pem", d / "k.pem")
    return ctx


class Server:
    """One-connection-at-a-time loopback server; ``behave(conn)`` decides what the peer does."""

    def __init__(self, behave, tls_context=None):
        self.sock = socket.socket()
        self.sock.bind((LOOPBACK, 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.behave, self.ctx = behave, tls_context
        self.stop = threading.Event()
        self.conns = []
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        self.conns.append(conn)
        try:
            if self.ctx is not None:
                conn = self.ctx.wrap_socket(conn, server_side=True)
                self.conns.append(conn)
            self.behave(conn, self.stop)
        except OSError:
            pass

    def close(self):
        self.stop.set()
        for c in self.conns:
            try:
                c.close()
            except OSError:
                pass
        self.sock.close()


@pytest.fixture
def serve(tls_context):
    servers = []

    def make(behave, tls=False):
        s = Server(behave, tls_context if tls else None)
        servers.append(s)
        return s
    yield make
    for s in servers:
        s.close()


def silent(conn, stop):
    conn.recv(4096)
    stop.wait(30)


def header_drip(conn, stop):
    conn.recv(4096)
    conn.sendall(b"HTTP/1.1 200 OK\r\n")
    while not stop.is_set():
        conn.sendall(b"X")
        time.sleep(0.2)


def body_drip(conn, stop):
    conn.recv(4096)
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\n\r\n")
    while not stop.is_set():
        conn.sendall(b"x")
        time.sleep(0.2)


def _get(fetcher, scheme, port):
    t0 = time.monotonic()
    res, _ = fetcher.fetch(f"{scheme}://{LOOPBACK}:{port}/", connect_ip=LOOPBACK, kind="document")
    return res, time.monotonic() - t0


def _settled(baseline, wait=2.0):
    end = time.monotonic() + wait
    while threading.active_count() > baseline and time.monotonic() < end:
        time.sleep(0.05)
    return threading.active_count() <= baseline


def test_server_that_never_sends_headers_ends_at_the_deadline(serve):
    srv = serve(silent)
    res, took = _get(_fetcher(), "http", srv.port)
    assert res.outcome == "timeout" and took < 1.5 + 1.0


def test_tls_server_that_completes_the_handshake_then_stalls_ends_at_the_deadline(serve):
    srv = serve(silent, tls=True)
    baseline = threading.active_count()
    res, took = _get(_fetcher(), "https", srv.port)
    assert res.outcome == "timeout" and took < 1.5 + 1.0
    srv.stop.set()
    assert _settled(baseline + 2)                      # the server's own handler thread may still be winding down


def test_tls_server_that_never_answers_the_hello_ends_at_the_deadline(serve):
    s = socket.socket()
    s.bind((LOOPBACK, 0))
    s.listen(1)
    held = []
    threading.Thread(target=lambda: held.append(s.accept()), daemon=True).start()
    try:
        res, took = _get(_fetcher(), "https", s.getsockname()[1])
        assert res.outcome == "timeout" and took < 1.5 + 1.0
    finally:
        s.close()
        for c, _ in held:
            c.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="relies on shutdown waking a blocked read")
@pytest.mark.parametrize("tls", [False, True])
def test_shutdown_alone_wakes_a_blocked_read(serve, monkeypatch, tls):
    monkeypatch.setattr(web_fetch, "_SLICE", 30.0)               # no polling: only the watchdog's shutdown can end the read
    srv = serve(silent, tls=tls)
    res, took = _get(_fetcher(), "https" if tls else "http", srv.port)
    assert res.outcome == "timeout" and took < 1.5 + 1.0


@pytest.mark.parametrize("behave", [header_drip, body_drip])
@pytest.mark.parametrize("tls", [False, True])
def test_dripping_server_is_cut_at_the_deadline(serve, behave, tls):
    srv = serve(behave, tls=tls)
    res, took = _get(_fetcher(limits=_limits(total=1.5, read=5.0, max_bytes=10**9)), "https" if tls else "http", srv.port)
    assert res.outcome == "timeout" and took < 1.5 + 1.0


def close_delimited_drip(conn, stop):
    conn.recv(4096)
    conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
    while not stop.is_set():
        conn.sendall(b"x")
        time.sleep(0.2)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="relies on shutdown waking a blocked read")
@pytest.mark.parametrize("tls", [False, True])
def test_close_delimited_body_cut_at_the_deadline_is_a_timeout_not_a_partial_ok(serve, tls):
    srv = serve(close_delimited_drip, tls=tls)
    res, took = _get(_fetcher(limits=_limits(total=1.5, read=5.0, max_bytes=10**9)), "https" if tls else "http", srv.port)
    assert res.outcome == "timeout" and took < 1.5 + 1.0


@pytest.mark.parametrize("tls", [False, True])
def test_watchdog_only_shuts_down_and_the_worker_closes_each_socket_once(serve, monkeypatch, tls):
    shutdowns, closes = [], []
    real_shutdown, real_close = web_fetch._raw_shutdown, web_fetch._raw_close

    def shutdown(sock):
        shutdowns.append((threading.current_thread(), id(sock)))
        real_shutdown(sock)

    def close(sock):
        closes.append((threading.current_thread(), id(sock)))
        real_close(sock)
    monkeypatch.setattr(web_fetch, "_raw_shutdown", shutdown)
    monkeypatch.setattr(web_fetch, "_raw_close", close)
    srv = serve(silent, tls=tls)
    fds_before = len(os.listdir("/proc/self/fd")) if sys.platform.startswith("linux") else None
    res, _ = _get(_fetcher(), "https" if tls else "http", srv.port)
    assert res.outcome == "timeout"
    worker = threading.current_thread()
    assert shutdowns and all(t is not worker and t.daemon for t, _ in shutdowns)
    assert closes and all(t is worker for t, _ in closes)
    ids = [i for _, i in closes]
    assert len(ids) == len(set(ids))                                   # nothing closed twice
    if fds_before is not None:
        srv.close()
        time.sleep(0.2)
        assert len(os.listdir("/proc/self/fd")) <= fds_before          # no connection left half-open


def test_pacing_wait_longer_than_the_request_budget_does_not_time_the_request_out(serve):
    def ok(conn, stop):
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        conn.close()

    class SlowPacer:
        def wait(self, ip):
            time.sleep(1.6)
            return True
    srv = serve(ok)
    fetcher = _fetcher(GuardedFetcher, limits=_limits(total=1.0), allowed_endpoints={(LOOPBACK, srv.port)}, pacer=SlowPacer())
    res, body = fetcher.fetch(f"http://{LOOPBACK}:{srv.port}/", connect_ip=LOOPBACK, kind="favicon")
    assert res.outcome == "ok" and body == b"ok"


def test_a_raising_kill_switch_does_not_stop_the_watchdog(serve):
    def broken():
        raise RuntimeError("kill file unreadable")
    srv = serve(silent)
    res, took = _get(_fetcher(killed=broken), "http", srv.port)
    assert res.outcome == "timeout" and took < 1.5 + 1.0


def test_kill_switch_ends_a_stalled_request(serve):
    srv = serve(silent)
    t0 = time.monotonic()
    res, took = _get(_fetcher(limits=_limits(total=20.0), killed=lambda: time.monotonic() - t0 > 0.5), "http", srv.port)
    assert res.outcome == "timeout" and took < 2.0


def test_a_watchdog_that_cannot_start_fails_the_request_cleanly(serve, monkeypatch):
    class Refusing(threading.Thread):
        def start(self):
            raise RuntimeError("can't start new thread")
    srv = serve(silent)
    monkeypatch.setattr(web_fetch.threading, "Thread", Refusing)
    res, took = _get(_fetcher(), "http", srv.port)
    assert res.outcome == "fetch_error" and took < 1.0


def test_unsupported_encoding_drain_is_bounded_by_bytes(serve):
    def endless(conn, stop):
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\nContent-Length: 100000000\r\n\r\n")
        chunk = b"x" * 4096
        while not stop.is_set():
            conn.sendall(chunk)
    srv = serve(endless)
    res, took = _get(_fetcher(limits=_limits(total=10.0, max_bytes=20_000)), "http", srv.port)
    assert res.outcome == "unsupported_encoding" and took < 3.0


def test_httpcore_internals_the_fetcher_replaces_still_exist():
    import httpcore
    import httpx
    from httpcore._backends.sync import SyncStream
    assert callable(getattr(SyncStream, "read", None)) and callable(getattr(SyncStream, "write", None))
    assert callable(getattr(SyncStream, "start_tls", None))
    assert hasattr(httpcore, "SyncBackend")
    with httpx.Client(transport=httpx.HTTPTransport()) as client:
        pool = client._transport._pool
        assert hasattr(pool, "_network_backend")
    from pathlib import Path
    lock = (Path(__file__).resolve().parents[1] / "scanner" / "requirements.lock").read_text()
    assert f"httpcore=={httpcore.__version__}" in lock and f"httpx=={httpx.__version__}" in lock


def test_client_uses_the_guarded_backend():
    guard = web_fetch._SocketGuard()
    with web_fetch._guarded_client(guard) as client:
        assert isinstance(client._transport._pool._network_backend, web_fetch._GuardedBackend)


def test_connect_after_expiry_fails_fast():
    guard = web_fetch._SocketGuard()
    guard.expire()
    backend = web_fetch._GuardedBackend(guard)
    import httpcore
    with pytest.raises(httpcore.ConnectError):
        backend.connect_tcp(LOOPBACK, 9, timeout=1.0)
