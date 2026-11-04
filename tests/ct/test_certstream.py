import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scanner.ct import certstream as cs

ROOT = Path(__file__).resolve().parents[2]
CERT = {
    "message_type": "certificate_update",
    "data": {
        "update_type": "X509LogEntry",
        "leaf_cert": {
            "all_domains": ["Example.TEST", "*.example.test", "www.example.test.", "www.example.test", 5],
            "sha256": "ab12cd", "serial_number": "01FF",
            "issuer": {"CN": "Example Issuing CA", "O": "Example Org"},
        },
        "source": {"name": "Example Log 2026", "url": "ct.alpha.example/2026/"},
        "seen": 1767225600.5,
    },
}


def test_certstream_basic():
    obs = cs.parse_certstream(CERT)
    assert [o.name for o in obs] == ["example.test", "www.example.test"]
    o = obs[0]
    assert (o.source, o.seen_at, o.cert_id, o.issuer, o.log) == (
        "certstream", "2026-01-01T00:00:00Z", "ab12cd", "Example Issuing CA", "ct.alpha.example/2026/")


def test_certstream_string_input_and_fallbacks():
    msg = json.loads(json.dumps(CERT))
    del msg["data"]["leaf_cert"]["sha256"]
    msg["data"]["leaf_cert"]["sha1"] = "ff"
    assert cs.parse_certstream(json.dumps(msg))[0].cert_id == "sha1:ff"
    del msg["data"]["leaf_cert"]["sha1"]
    assert cs.parse_certstream(msg)[0].cert_id == "01FF"


@pytest.mark.parametrize("msg", [{"message_type": "heartbeat"}, "not json", "[1]", 3, {}, {"message_type": "certificate_update"},
                                 {"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": "x"}}}])
def test_certstream_ignored(msg):
    assert cs.parse_certstream(msg) == []


def test_zonestream():
    msg = {"domain": "New.Example.TEST", "timestamp": 1767225600, "ct_name": "log1", "cert_index": 7}
    (o,) = cs.parse_zonestream(msg)
    assert (o.name, o.source, o.seen_at, o.cert_id) == ("new.example.test", "zonestream", "2026-01-01T00:00:00Z", "zonestream:log1:7")
    (o,) = cs.parse_zonestream(json.dumps({"fqdn": "a.b.example.test."}))
    assert o.name == "a.b.example.test" and o.seen_at is None and o.cert_id is None
    assert cs.parse_zonestream({"x": 1}) == [] and cs.parse_zonestream("zzz") == []


class FakeWS:
    def __init__(self, items):
        self.items = list(items)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def recv(self, timeout=None):
        self.timeouts.append(timeout)
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    timeouts = []


def zs(name):
    return json.dumps({"domain": name})


def make_connect(sessions, urls=None):
    queue = list(sessions)

    def connect(url):
        if urls is not None:
            urls.append(url)
        session = queue.pop(0)
        if isinstance(session, Exception):
            raise session
        return FakeWS(session)
    return connect


def run(connect, **kwargs):
    return list(cs.stream_websocket("wss://feed.invalid/", parse=cs.parse_zonestream, connect=connect, **kwargs))


def test_stream_max_messages():
    out = run(make_connect([[zs("a.test"), zs("b.test"), zs("c.test")]]), max_messages=2)
    assert [o.name for o in out] == ["a.test", "b.test"]


def test_stream_reconnects_with_backoff():
    urls, sleeps = [], []
    connect = make_connect([[zs("a.test"), ConnectionResetError("drop")], ConnectionRefusedError("no"), [zs("b.test")]], urls)
    out = run(connect, max_messages=2, reconnect_backoff_s=1.0, sleep=sleeps.append)
    assert [o.name for o in out] == ["a.test", "b.test"]
    assert urls == ["wss://feed.invalid/"] * 3
    assert sleeps == [1.0, 1.0 * 2]


def test_stream_gives_up_after_max_reconnects():
    sleeps = []
    with pytest.raises(OSError):
        run(make_connect([OSError("x")] * 5), max_reconnects=2, sleep=sleeps.append)
    assert len(sleeps) == 2


def test_stream_named_close_error_reconnects_and_other_errors_raise():
    class ConnectionClosedOK(Exception):
        pass
    sleeps = []
    out = run(make_connect([[ConnectionClosedOK()], [zs("a.test")]]), max_messages=1, sleep=sleeps.append)
    assert len(out) == 1 and len(sleeps) == 1
    with pytest.raises(ValueError):
        run(make_connect([[ValueError("bug")]]), sleep=sleeps.append)


def test_import_does_not_load_websockets():
    code = "import sys, scanner.ct.certstream; sys.exit('websockets' in sys.modules)"
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    assert subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env).returncode == 0


def test_wildcard_names_are_dropped():
    assert [o.name for o in cs.parse_certstream(CERT)] == ["example.test", "www.example.test"]
    assert cs.parse_zonestream({"domain": "*.example.test"}) == []


class Ticker:
    """A clock that moves only when told to; ``sleep`` advances it too."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class TimedWS(FakeWS):
    """Each item is a pair of seconds to advance and the payload."""

    def __init__(self, items, clock):
        super().__init__(items)
        self.clock = clock

    def recv(self, timeout=None):
        advance, item = self.items.pop(0)
        self.clock.now += advance
        if isinstance(item, Exception):
            raise item
        return item


def timed_connect(sessions, clock):
    queue = list(sessions)

    def connect(url):
        return TimedWS(queue.pop(0), clock)
    return connect


def test_short_connections_do_not_reset_the_backoff():
    clock = Ticker()
    drop = [(0.0, zs("a.test")), (0.0, ConnectionResetError("drop"))]
    connect = timed_connect([drop, drop, drop, [(0.0, zs("z.test"))]], clock)
    out = run(connect, max_messages=4, reconnect_backoff_s=1.0, sleep=clock.sleep, clock=clock)
    assert len(out) == 4
    assert clock.now == 1.0 + 2.0 + 4.0


def test_long_connection_resets_the_backoff():
    clock = Ticker()
    short = [(0.0, ConnectionResetError("drop"))]
    long_lived = [(70.0, zs("a.test")), (0.0, ConnectionResetError("drop"))]
    connect = timed_connect([short, short, long_lived, short, [(0.0, zs("b.test"))]], clock)
    out = run(connect, max_messages=2, reconnect_backoff_s=1.0, sleep=clock.sleep, clock=clock)
    assert len(out) == 2
    # 1 + 2 after the first two, then reset: 1 after the long connection, 2 after the next short one
    assert clock.now == 70.0 + 1.0 + 2.0 + 1.0 + 2.0


def test_many_messages_reset_the_backoff():
    clock = Ticker()
    busy = [(0.0, zs(f"h{i}.test")) for i in range(100)] + [(0.0, ConnectionResetError("drop"))]
    short = [(0.0, ConnectionResetError("drop"))]
    connect = timed_connect([short, busy, short, [(0.0, zs("end.test"))]], clock)
    out = run(connect, max_messages=101, reconnect_backoff_s=1.0, sleep=clock.sleep, clock=clock)
    assert len(out) == 101
    assert clock.now == 1.0 + 1.0 + 2.0


def test_max_seconds_stops_the_stream():
    clock = Ticker()
    session = [(10.0, zs(f"h{i}.test")) for i in range(100)]
    out = run(timed_connect([session], clock), max_seconds=35, clock=clock, sleep=clock.sleep)
    assert len(out) == 4


def test_max_seconds_applies_across_reconnects_and_caps_the_pause():
    clock = Ticker()
    connect = timed_connect([[(0.0, ConnectionResetError("drop"))]] * 3, clock)
    assert run(connect, max_seconds=8, reconnect_backoff_s=5.0, clock=clock, sleep=clock.sleep) == []
    assert clock.now == 8.0


def test_recv_gets_a_timeout_and_timeouts_are_tolerated():
    clock = Ticker()
    FakeWS.timeouts = []
    session = [TimeoutError("quiet"), zs("a.test")]
    connect = make_connect([session])
    out = run(connect, max_messages=1, clock=clock)
    assert [o.name for o in out] == ["a.test"]
    assert FakeWS.timeouts == [cs.RECV_TIMEOUT_S] * 2
