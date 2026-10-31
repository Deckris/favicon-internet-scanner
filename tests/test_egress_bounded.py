import threading
import time
from types import SimpleNamespace

import pytest

from scanner.internet import preflight as pre


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setattr(pre, "_egress_dns", {})
    monkeypatch.setattr(pre, "_egress_worker", None)
    monkeypatch.setattr(pre, "_egress_last", None)


def test_hanging_resolver_fails_within_the_lifetime(monkeypatch):
    release = threading.Event()
    seen = {}

    def hang(host, resolvers, lifetime):
        seen["lifetime"] = lifetime
        release.wait(30)
        return [], 60.0

    monkeypatch.setattr(pre, "_resolve_a", hang)
    t = time.monotonic()
    try:
        assert pre._public_ip("https://check.example/ip", timeout=0.5) is None
        assert time.monotonic() - t < 4
        assert seen["lifetime"] <= 0.5
    finally:
        release.set()


def test_resolved_address_is_cached_and_used_with_host_header(monkeypatch):
    calls = []
    monkeypatch.setattr(pre, "_resolve_a", lambda host, resolvers, lifetime: calls.append(host) or (["127.0.0.1"], 60.0))
    srv = _serve_once()
    try:
        url = f"http://check.example:{srv.port}/ip"
        assert pre._public_ip(url, timeout=3) == "203.0.113.9"
        srv.thread.join(3)
        assert srv.requests[0].lower().count("host: check.example:%d" % srv.port) == 1
        srv.close()
        srv2 = _serve_once(port=srv.port)
        assert pre._public_ip(url, timeout=3) == "203.0.113.9"
        srv2.thread.join(3)
        assert calls == ["check.example"]
    finally:
        srv.close()


def test_no_second_thread_while_one_runs(monkeypatch):
    release = threading.Event()
    started = []

    def hang(host, resolvers, lifetime):
        started.append(1)
        release.wait(30)
        return [], 60.0

    monkeypatch.setattr(pre, "_resolve_a", hang)
    try:
        assert pre._public_ip("https://check.example/ip", timeout=0.2) is None
        before = threading.active_count()
        t = time.monotonic()
        assert pre._public_ip("https://other.example/ip", timeout=5) is None
        assert time.monotonic() - t < 1
        assert threading.active_count() == before and started == [1]
    finally:
        release.set()


def test_configured_resolvers_are_passed_on(monkeypatch):
    got = []
    monkeypatch.setattr(pre, "_public_ip", lambda url, timeout, resolvers=(), **kw: got.append(resolvers) or "198.51.100.1")
    cfg = SimpleNamespace(vantage=SimpleNamespace(egress_check="url", egress_check_urls=("https://a.example",)),
                          dns=SimpleNamespace(resolvers=("192.0.2.53",)))
    assert pre.current_egress(cfg) == "198.51.100.1" and got == [("192.0.2.53",)]


def test_cache_entry_is_dropped_when_every_cached_address_fails(monkeypatch):
    monkeypatch.setattr(pre, "_resolve_a", lambda host, resolvers, lifetime: (["127.0.0.1"], 60.0))
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                        # nothing listens here any more
    assert pre._fetch_text(f"http://check.example:{port}/ip", (), 1.0) is None
    assert "check.example" not in pre._egress_dns


def test_record_ttl_is_clamped(monkeypatch):
    monkeypatch.setattr(pre, "_resolve_a", lambda host, resolvers, lifetime: (["192.0.2.7"], 86400.0))
    t = time.monotonic()
    assert pre._egress_addresses("check.example", (), 1.0) == ["192.0.2.7"]
    assert pre._egress_dns["check.example"][0] - t <= pre._EGRESS_DNS_TTL_MAX + 1


def test_slow_dripping_server_does_not_outlast_the_deadline(monkeypatch):
    import socket
    monkeypatch.setattr(pre, "_resolve_a", lambda host, resolvers, lifetime: (["127.0.0.1"], 60.0))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    stop = threading.Event()

    def drip():
        c, _ = srv.accept()
        with c:
            c.recv(2048)
            c.sendall(b"HTTP/1.0 200 OK\r\n\r\n")
            while not stop.is_set():
                try:
                    c.sendall(b"1")
                except OSError:
                    return
                time.sleep(0.04)
    threading.Thread(target=drip, daemon=True).start()
    try:
        t = time.monotonic()
        assert pre._fetch_text(f"http://check.example:{srv.getsockname()[1]}/ip", (), 0.5) is None
        assert time.monotonic() - t < 1.5
    finally:
        stop.set()
        srv.close()


def test_last_good_value_is_returned_while_an_older_worker_lingers(monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(pre, "_resolve_a", lambda host, resolvers, lifetime: release.wait(30) or ([], 60.0))
    try:
        assert pre._public_ip("https://check.example/ip", timeout=0.2) is None
        monkeypatch.setattr(pre, "_egress_last", (time.monotonic(), "203.0.113.5"))
        assert pre._public_ip("https://check.example/ip", timeout=0.2, max_stale=60) == "203.0.113.5"
        assert pre._public_ip("https://check.example/ip", timeout=0.2) is None
        monkeypatch.setattr(pre, "_egress_last", (time.monotonic() - 100, "203.0.113.5"))
        assert pre._public_ip("https://check.example/ip", timeout=0.2, max_stale=60) is None
    finally:
        release.set()


def test_ipv6_resolver_entries_are_accepted():
    assert pre._split_nameserver("192.0.2.1") == ("192.0.2.1", None)
    assert pre._split_nameserver("192.0.2.1:5353") == ("192.0.2.1", 5353)
    assert pre._split_nameserver("2001:db8::1") == ("2001:db8::1", None)
    assert pre._split_nameserver("[2001:db8::1]:53") == ("2001:db8::1", 53)


def _serve_redirect(location):
    import socket
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(2)

    def run():
        for i in range(2):
            try:
                c, _ = srv.accept()
            except OSError:
                return
            with c:
                c.recv(2048)
                if i == 0:
                    c.sendall(b"HTTP/1.0 301 Moved\r\nLocation: " + location(srv.getsockname()[1]).encode() + b"\r\n\r\n")
                else:
                    c.sendall(b"HTTP/1.0 200 OK\r\n\r\n203.0.113.9\n")
    threading.Thread(target=run, daemon=True).start()
    return srv


def test_single_redirect_to_the_same_host_is_followed(monkeypatch):
    monkeypatch.setattr(pre, "_resolve_a", lambda host, resolvers, lifetime: (["127.0.0.1"], 60.0))
    srv = _serve_redirect(lambda port: f"http://check.example:{port}/final")
    try:
        assert pre._fetch_text(f"http://check.example:{srv.getsockname()[1]}/ip", (), 3.0) == "203.0.113.9"
    finally:
        srv.close()


def test_redirect_to_another_host_is_refused(monkeypatch):
    monkeypatch.setattr(pre, "_resolve_a", lambda host, resolvers, lifetime: (["127.0.0.1"], 60.0))
    srv = _serve_redirect(lambda port: "http://elsewhere.example/ip")
    try:
        assert pre._fetch_text(f"http://check.example:{srv.getsockname()[1]}/ip", (), 3.0) is None
    finally:
        srv.close()


class _serve_once:
    def __init__(self, port=0):
        import socket
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.requests = []
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        self.sock.settimeout(5)
        try:
            c, _ = self.sock.accept()
        except OSError:
            return
        with c:
            self.requests.append(c.recv(2048).decode("ascii", "replace"))
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n203.0.113.9\n")

    def close(self):
        self.sock.close()
