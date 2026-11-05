"""Clipped per-phase timeouts and TLS error classification, exercised without any socket."""
from __future__ import annotations

import contextlib
import ssl
import time
from urllib.parse import urlsplit

import httpcore
import httpx
import pytest

from scanner import web_fetch
from scanner.safety import TargetPolicy
from scanner.web_fetch import FetchLimits, WebFetcher

DOC_IP = "192.0.2.10"


def _limits(connect=3.0, read=30.0, total=5.0):
    return FetchLimits(connect_timeout=connect, read_timeout=read, total_timeout=total, max_bytes=10_000, max_decoded_bytes=10_000, max_redirects=1)


def _fetcher():
    lim = _limits()
    return WebFetcher(TargetPolicy.for_tests([f"{DOC_IP}/32"]), None, user_agent="t", document_limits=lim, favicon_limits=lim)


class _FakeClient:
    def __init__(self, error: BaseException):
        self.error = error
        self.timeouts: list[httpx.Timeout] = []

    def build_request(self, *args, **kwargs):
        return None

    def stream(self, method, url, *, timeout, **kwargs):
        self.timeouts.append(timeout)
        raise self.error


def _run(monkeypatch, error: BaseException, deadline: float | None = None):
    client = _FakeClient(error)

    @contextlib.contextmanager
    def request_client(guard):
        yield client

    monkeypatch.setattr(web_fetch, "_request_client", request_client)
    parts = urlsplit("https://host.invalid/")
    when = time.monotonic() + 5.0 if deadline is None else deadline
    outcome = _fetcher()._one_request_inner(parts, "host.invalid", 443, DOC_IP, _limits(), 5.0, when, web_fetch._SocketGuard())
    return outcome, client


def _chain(*errors: BaseException, via: str = "__cause__") -> BaseException:
    for outer, inner in zip(errors, errors[1:]):
        setattr(outer, via, inner)
    return errors[0]


def test_timeouts_keep_their_limits_while_the_deadline_is_far():
    timeout = web_fetch._clipped_timeout(_limits(connect=3.0, read=30.0), time.monotonic() + 600)
    assert (timeout.connect, timeout.read, timeout.write, timeout.pool) == (3.0, 30.0, 30.0, 3.0)


def test_timeouts_are_clipped_to_what_is_left_of_the_deadline():
    timeout = web_fetch._clipped_timeout(_limits(connect=3.0, read=30.0), time.monotonic() + 1.0)
    for value in (timeout.connect, timeout.read, timeout.write, timeout.pool):
        assert 0.9 < value <= 1.0 + web_fetch._CLIP_MARGIN


def test_timeouts_after_the_deadline_leave_only_the_margin():
    timeout = web_fetch._clipped_timeout(_limits(), time.monotonic() - 10.0)
    assert timeout.connect == pytest.approx(web_fetch._CLIP_MARGIN)
    assert timeout.read == pytest.approx(web_fetch._CLIP_MARGIN)


def test_the_request_is_sent_with_the_clipped_timeout(monkeypatch):
    _outcome, client = _run(monkeypatch, httpx.ConnectError("refused"), deadline=time.monotonic() + 0.5)
    (timeout,) = client.timeouts
    assert timeout.connect <= 0.5 + web_fetch._CLIP_MARGIN
    assert timeout.read <= 0.5 + web_fetch._CLIP_MARGIN


def test_caused_by_walks_causes_and_contexts():
    deep = _chain(httpx.ConnectError("a"), httpcore.ConnectError("b"), ssl.SSLError("c"))
    assert web_fetch._caused_by(deep, ssl.SSLError)
    via_context = _chain(httpx.ConnectError("a"), OSError("b"), ssl.SSLCertVerificationError("c"), via="__context__")
    assert web_fetch._caused_by(via_context, ssl.SSLError)
    assert not web_fetch._caused_by(_chain(httpx.ConnectError("a"), OSError("b")), ssl.SSLError)
    assert not web_fetch._caused_by(None, ssl.SSLError)


def test_caused_by_is_bounded_on_a_cyclic_chain():
    first, second = OSError("a"), OSError("b")
    first.__cause__, second.__cause__ = second, first
    assert not web_fetch._caused_by(first, ssl.SSLError)


def test_a_tls_error_behind_the_httpcore_wrapper_is_classified_as_tls_error(monkeypatch):
    error = _chain(httpx.ConnectError("handshake failed"), httpcore.ConnectError("handshake failed"), ssl.SSLError("bad record"))
    outcome, _ = _run(monkeypatch, error)
    assert outcome.kind == "transport" and outcome.outcome == "tls_error"


def test_a_direct_tls_cause_is_still_classified_as_tls_error(monkeypatch):
    error = _chain(httpx.ConnectError("handshake failed"), ssl.SSLError("alert"))
    outcome, _ = _run(monkeypatch, error)
    assert outcome.outcome == "tls_error"


def test_a_plain_connect_failure_stays_connect_error(monkeypatch):
    error = _chain(httpx.ConnectError("refused"), httpcore.ConnectError("refused"), ConnectionRefusedError("refused"))
    outcome, _ = _run(monkeypatch, error)
    assert outcome.outcome == "connect_error"
