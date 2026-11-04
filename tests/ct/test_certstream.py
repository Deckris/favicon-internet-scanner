import json
import subprocess
import sys

import pytest

from scanner.ct import certstream as cs

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

    def recv(self):
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


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
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0
