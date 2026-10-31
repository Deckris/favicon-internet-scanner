"""The per-shard facts store: lossless round trips, write-out ordering, concurrent writers, bounded memory."""
import json
import tracemalloc
from concurrent.futures import ThreadPoolExecutor

import pytest

from scanner.internet import tls as tlsmod
from scanner.internet.candidates import EndpointNames
from scanner.internet.shardstore import EndpointFacts, IpFacts, ShardStore
from scanner.models import ZGrabResult
from scanner.zdns_runner import Resolution, parse_zdns_line, resolve
from tests.helpers import FIX


@pytest.fixture
def store(tmp_path):
    s = ShardStore(tmp_path / "work" / "facts.sqlite")
    yield s
    s.close()


def _tls(name, port=443, sni=None, mode="direct_ip", ip=None):
    line = (FIX / "zgrab_tls" / name).read_text(encoding="utf-8").splitlines()[0]
    r = tlsmod.parse_line(line, port=port, sni=sni, mode=mode)
    if ip is not None and r.ip != ip:
        r = tlsmod.TlsResult(ip, r.port, r.sni, r.zgrab_status, r.outcome, r.error, r.tls_version, r.cipher_suite,
                             r.certificate, r.cert_parse_error, r.raw_line_sha256)
    return r


def _zgrab(ip="10.0.0.5", port=80, cert=None):
    return ZGrabResult("ZGRAB-1", ip, port, "http", "direct_ip", None, None, "success", 301, "text/html", None,
                       "http://x.test/", "ab" * 32, 1234, None, None, cert, None, "cd" * 32)


def _fav(ip, port, host, sha="f" * 64, **kw):
    rec = {"kind": "hostname" if host else "direct_ip", "url": f"https://{host or ip}:{port}/", "scheme": "https",
           "hostname": host, "document_outcome": "ok", "http_status": 200, "document_title": "Café ☃",
           "favicon_sha256": sha, "favicon_is_image": True, "favicon_outcome": "ok", "icon_declared_kinds": {"icon": 1},
           "icon_offhost_hosts": ["cdn.example"], "icon_embedded_images": 0, "ip": ip, "port": port}
    rec.update(kw)
    return rec


# ---------------------------------------------------------------- round trips

@pytest.mark.parametrize("fixture", ["ok.jsonl", "nonhttp_ok.jsonl", "strict_no_sni.jsonl", "silent_close.jsonl", "reset.jsonl",
                                     "hang.jsonl", "plain_http.jsonl", "closed_port.jsonl", "handshake_failure.jsonl"])
def test_tls_result_round_trips_exactly(store, fixture):
    r = _tls(fixture, ip="10.0.0.1")
    store.put_tls(r)
    store.put_endpoints([("10.0.0.1", 443)])
    back = store.get_tls("10.0.0.1", 443)
    assert back == r and type(back.certificate) is type(r.certificate)
    if r.certificate:
        assert isinstance(back.certificate.san_dns, tuple) and isinstance(back.certificate.chain_sha256, tuple)
    assert store.get_tls("10.0.0.1", 80) is None


def test_zgrab_result_with_certificate_round_trips(store):
    cert = _tls("ok.jsonl").certificate
    r = _zgrab(cert=cert)
    store.put_http(r)
    assert store.get_http("10.0.0.5", 80) == r
    store.put_http_many([_zgrab("10.0.0.6", 8080)])
    assert store.get_http("10.0.0.6", 8080).port == 8080 and store.get_http("10.0.0.7", 80) is None


def test_resolution_and_names_round_trip(store):
    a = parse_zdns_line((FIX / "zdns" / "A_cn.test.jsonl").read_text(encoding="utf-8").splitlines()[0], "A")
    res = [resolve("cn.test", a, None), Resolution("nx.test", "nxdomain"), Resolution("e\ud800.test", "tool_error", error="boom\udfff")]
    store.put_resolutions(res)
    got = store.get_resolutions(["cn.test", "nx.test", "e\ud800.test", "absent.test"])
    assert got == {r.hostname: r for r in res} and got["cn.test"].cname_chain == ("c1.test", "target.test")
    assert store.get_resolution("absent.test") is None
    assert store.resolution_status_counts() == {"resolved": 1, "nxdomain": 1, "tool_error": 1}

    names = EndpointNames(names={"b.test": {"ptr", "certificate_san"}, "a.test": {"certificate_cn"}, "é.test": {"ptr"}},
                          wildcards={"*.w.test"}, dropped=["1.2.3.4", "bad\ud800"], truncated=True, source_count=9)
    store.put_names("10.0.0.1", 443, names)
    back = store.get_names("10.0.0.1", 443)
    assert back == names and list(back.names) == list(names.names)
    assert store.get_names("10.0.0.1", 80) == EndpointNames()


def test_favicon_record_round_trip_and_last_key_wins_with_first_position(store):
    a, b, c = _fav("10.0.0.1", 443, None), _fav("10.0.0.1", 443, "x.test"), _fav("10.0.0.2", 443, None)
    b2 = _fav("10.0.0.1", 443, "x.test", favicon_outcome="later", sha="1" * 64)
    # completion order differs from job order, and job 3 repeats job 1's key
    store.put_favicon(2, c)
    store.put_favicon(3, b2)
    store.put_favicon(1, b)
    store.put_favicon(0, a)
    assert [r["ip"] + str(r["hostname"]) for r in store.iter_favicons()] == ["10.0.0.1None", "10.0.0.1x.test", "10.0.0.2None"]
    assert store.get_favicon("10.0.0.1", 443, "x.test") == b2 and store.get_favicon("10.0.0.1", 443, None) == a
    assert store.get_favicon("10.0.0.9", 443, None) is None
    assert store.count_favicons() == 3 and store.count_favicon_outcome("later") == 1
    # same outcome as a dict assigned in job order
    ref = {}
    for rec in (a, b, c, b2):
        ref[(rec["ip"], rec["port"], rec["hostname"])] = rec
    assert list(store.iter_favicons()) == list(ref.values())


def test_favicon_records_feed_write_index_as_an_iterator(store, tmp_path):
    from scanner.internet import icon_store
    ic = icon_store.IconStore(tmp_path / "favicons")
    png = b"\x89PNG\r\n\x1a\n" + b"x" * 20
    import hashlib
    sha = hashlib.sha256(png).hexdigest()
    rel = ic.save(sha, png)
    store.put_favicon_many([(0, _fav("10.0.0.1", 443, None, sha=sha, favicon_file=rel)), (1, _fav("10.0.0.2", 80, "h.test", sha=sha))])
    recs = [json.loads(json.dumps(r)) for r in store.iter_favicons()]
    ic2 = icon_store.IconStore(tmp_path / "favicons2")
    ic2._files = dict(ic._files)
    assert ic.write_index(recs) == ic2.write_index(store.iter_favicons()) == 1
    assert (tmp_path / "favicons" / "index.jsonl").read_text() == (tmp_path / "favicons2" / "index.jsonl").read_text()


def test_synack_ptr_and_sent_markers(store):
    store.put_endpoints([("10.0.0.1", 80), ("10.0.0.1", 443), ("10.0.0.2", 80), ("10.0.0.3", 80)])
    store.put_synack_port(80, {"10.0.0.1": {"window": 0, "ttl": 64}, "10.0.0.2": {"window": 64240, "ttl": None}})
    store.put_synack("10.0.0.3", 80, None, 55)
    assert store.get_synack("10.0.0.1", 80) == {"window": 0, "ttl": 64} and store.get_synack("10.0.0.9", 80) == {}
    assert store.tarpit_ips(246) == {"10.0.0.1"}
    store.put_synack("10.0.0.2", 443, 10, 1)
    assert store.tarpit_ips(246) == {"10.0.0.1", "10.0.0.2"}
    assert store.mark_ptr_sent(["10.0.0.2", "10.0.0.1"]) == ["10.0.0.2", "10.0.0.1"]
    assert store.mark_ptr_sent(["10.0.0.1", "10.0.0.3"]) == ["10.0.0.3"]
    assert list(store.iter_unsent_ptr_ips()) == []
    store.unmark_ptr_sent(["10.0.0.2"])
    assert list(store.iter_unsent_ptr_ips()) == ["10.0.0.2"]
    store.put_ptr("10.0.0.1", ["a.rev.", "b\ud800.rev."], "NOERROR")
    assert store.get_ptr("10.0.0.1") == (["a.rev.", "b\ud800.rev."], "NOERROR") and store.get_ptr("10.0.0.2") == ([], None)
    assert store.fill_missing_ptr() == 2
    assert store.get_ptr("10.0.0.3") == ([], "NO_OUTPUT") and store.get_ptr("10.0.0.1")[1] == "NOERROR"


def test_tls_queries_and_late_tarpit_delete(store):
    store.put_endpoints([("10.0.0.%d" % i, p) for i in range(1, 5) for p in (80, 443)])
    for i, name in enumerate(["ok.jsonl", "plain_http.jsonl", "silent_close.jsonl", "ok.jsonl"], 1):
        store.put_tls(_tls(name, port=80, ip=f"10.0.0.{i}"))
    store.put_tls(_tls("plain_http.jsonl", port=443, ip="10.0.0.1"))
    store.put_tls(_tls("ok.jsonl", port=443, ip="10.0.0.9"))          # not an endpoint: never listed
    assert list(store.iter_endpoints_with_tls_outcome([tlsmod.NOT_TLS, tlsmod.CLOSED])) == [("10.0.0.1", 443), ("10.0.0.2", 80), ("10.0.0.3", 80)]
    assert list(store.iter_endpoints_with_tls_outcome([])) == []
    assert store.delete_tls_for_ips(["10.0.0.3", "10.0.0.1", "10.0.0.8"]) == [("10.0.0.1", 80), ("10.0.0.1", 443), ("10.0.0.3", 80)]
    assert store.get_tls("10.0.0.1", 80) is None and store.get_tls("10.0.0.2", 80) is not None and store.count_tls() == 3


# ---------------------------------------------------------------- ordering

IPS = ["10.0.0.9", "10.0.0.10", "9.255.0.1", "10.0.0.100", "1.2.3.4", "100.0.0.1", "10.0.1.0", "192.168.0.1"]


def test_ip_orders_match_python(store):
    eps = [(ip, p) for ip in IPS for p in (443, 80, 8080, 22)]
    store.put_endpoints(eps)
    assert list(store.iter_endpoints()) == sorted(eps)
    assert list(store.iter_endpoints(page=3)) == sorted(eps)
    key = lambda e: (tuple(int(o) for o in e[0].split(".")), e[1])
    assert list(store.iter_endpoints(order="numeric", page=5)) == sorted(eps, key=key)
    assert list(store.iter_endpoints(80)) == sorted(e for e in eps if e[1] == 80)
    assert list(store.iter_endpoints(80, order="numeric", page=3)) == sorted((e for e in eps if e[1] == 80), key=key)
    assert [g.ip for g in store.iter_ips(page=3)] == sorted(IPS)
    assert [g.ip for g in store.iter_ips(order="numeric", page=3)] == sorted(IPS, key=lambda i: tuple(int(o) for o in i.split(".")))
    assert list(store.iter_ip_names()) == sorted(IPS)
    assert store.count_endpoints() == len(eps) and store.count_unique_ips() == len(IPS)
    assert store.count_endpoints_by_port() == {22: 8, 80: 8, 443: 8, 8080: 8}


NAMES = ["b.test", "a.test", "é.test", "z中.test", "\U0001f600.test", ".test", "퟿.test", "x\ud800.test",
         "x\udfff.test", "x\ud83d.test", "x\ude00.test", "x.test", "X.test", "", "a", "ab", "a\u0000b"]


def test_hostname_order_matches_python_including_lone_surrogates(store):
    for i, n in enumerate(NAMES):
        store.put_names("10.0.0.%d" % (i + 1), 80, EndpointNames(names={n: {"ptr"}} if n else {}))
    want = sorted({n for n in NAMES if n})
    assert list(store.iter_candidate_names(page=4)) == want
    assert store.count_candidate_names() == len(want)
    for n in want:
        store.put_resolutions([Resolution(n, "nxdomain")])
        store.put_sni_skipped("10.0.0.1", 80, n, "cap")
    assert set(store.get_resolutions(want)) == set(want)
    store.put_endpoints([("10.0.0.1", 80)])
    assert set(store.group("10.0.0.1").endpoints[0].sni_skipped) == set(want)


# ---------------------------------------------------------------- groups

def test_group_returns_everything_about_an_address(store):
    ip = "10.0.0.5"
    store.put_endpoints([(ip, 443), (ip, 80), ("10.0.0.6", 80)])
    store.put_synack(ip, 80, 64240, 60)
    ok = _tls("ok.jsonl", ip=ip)
    store.put_tls(ok)
    store.put_tls(_tls("plain_http.jsonl", port=80, ip=ip))
    store.put_http(_zgrab(ip, 80))
    store.put_ptr(ip, ["p.rev"], "NOERROR")
    nm = EndpointNames(names={"good.test": {"ptr", "certificate_cn"}, "other.test": {"certificate_san"}})
    store.put_names(ip, 443, nm)
    store.put_resolutions([Resolution("good.test", "resolved", a=(ip,)), Resolution("unrelated.test", "nxdomain")])
    sni = _tls("ok.jsonl", sni="good.test", mode="hostname_aware", ip=ip)
    store.put_sni(sni)
    store.put_sni_skipped(ip, 443, "other.test", "cap")
    store.put_favicon(0, _fav(ip, 443, None))
    store.put_favicon(1, _fav(ip, 443, "good.test"))
    g = store.group(ip)
    assert isinstance(g, IpFacts) and g.ip == ip and (g.ptr_names, g.ptr_status) == (["p.rev"], "NOERROR")
    assert [e.port for e in g.endpoints] == [80, 443]
    e80, e443 = g.endpoints
    assert isinstance(e80, EndpointFacts) and (e80.synack_window, e80.synack_ttl) == (64240, 60)
    assert e80.tls.outcome == tlsmod.NOT_TLS and e80.http == _zgrab(ip, 80) and e80.names == EndpointNames() and not e80.sni_ok
    assert e443.tls == ok and e443.http is None and e443.synack_window is None and e443.names == nm
    assert e443.sni == {"good.test": sni} and e443.sni_ok and e443.sni_skipped == {"other.test": "cap"}
    assert set(e443.favicons) == {None, "good.test"} and e443.favicons["good.test"]["hostname"] == "good.test"
    assert g.resolutions == {"good.test": Resolution("good.test", "resolved", a=(ip,))}
    assert store.sni_ok(ip, 443) and not store.sni_ok(ip, 80)
    empty = store.group("10.9.9.9")
    assert empty.endpoints == [] and empty.ptr_status is None
    assert [x.ip for x in store.group_many(["10.0.0.6", ip, "10.0.0.6"])] == ["10.0.0.6", ip, "10.0.0.6"]


def test_iteration_tolerates_writes_between_pages(store):
    store.put_endpoints([("10.0.0.%d" % i, 80) for i in range(1, 40)])
    seen = []
    for g in store.iter_ips(page=4):
        store.put_favicon(len(seen), _fav(g.ip, 80, None))
        seen.append(g.ip)
    assert seen == sorted(seen) and len(seen) == 39 and store.count_favicons() == 39


# ---------------------------------------------------------------- lifecycle, threads, memory

def test_reopen_reset_and_delete(tmp_path):
    p = tmp_path / "w" / "facts.sqlite"
    s = ShardStore(p)
    s.put_endpoints([("10.0.0.1", 80)])
    s.close()
    s.close()
    s = ShardStore(p)
    assert s.count_endpoints() == 1
    s.close()
    s = ShardStore(p, reset=True)
    assert s.count_endpoints() == 0
    s.put_endpoints([("10.0.0.1", 80)])
    s.delete()
    assert not p.exists() and not (tmp_path / "w" / "facts.sqlite-wal").exists()


def test_non_ascii_address_is_refused(store):
    with pytest.raises(ValueError):
        store.put_endpoints([("10.0.0.١", 80)])


def test_sixty_four_threads_write_concurrently(tmp_path):
    s = ShardStore(tmp_path / "facts.sqlite", batch_size=50)
    errors = []

    def work(t):
        try:
            for i in range(150):
                ip = f"10.{t}.{i // 250}.{i % 250}"
                idx = t * 1000 + i
                s.put_endpoints([(ip, 80)])
                s.put_favicon(idx, _fav(ip, 80, None, sha="%064x" % idx))
                s.put_sni_skipped(ip, 80, "h.test", "cap")
                if i % 25 == 0:
                    s.count_endpoints()           # readers interleave with the writers
        except Exception as exc:                  # pragma: no cover
            errors.append(exc)

    with ThreadPoolExecutor(64) as pool:
        list(pool.map(work, range(64)))
    assert not errors
    assert s.count_endpoints() == 64 * 150 and s.count_favicons() == 64 * 150
    first = [r["favicon_sha256"] for r in s.iter_favicons()]
    assert first == sorted(first) and len(set(first)) == 64 * 150     # job order = index order
    assert sum(1 for _ in s.iter_ips(page=500)) == 64 * 150
    s.close()


def test_memory_stays_flat_for_200k_rows(tmp_path):
    s = ShardStore(tmp_path / "facts.sqlite")
    tracemalloc.start()
    try:
        for i in range(200_000):
            s.put_synack(f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}", 80, 64240, 64)
        peak = tracemalloc.get_traced_memory()[1]
        assert s._query("SELECT COUNT(*) FROM synack")[0][0] == 200_000
    finally:
        tracemalloc.stop()
        s.close()
    assert peak < 50 * 1024 * 1024


def test_batched_buffer_is_flushed_before_a_read_and_on_close(tmp_path):
    p = tmp_path / "facts.sqlite"
    s = ShardStore(p, batch_size=10_000)
    s.put_endpoints([("10.0.0.1", 80)])
    assert s.count_endpoints() == 1
    s.put_endpoints([("10.0.0.2", 80)])
    s.close()
    s = ShardStore(p)
    assert s.count_endpoints() == 2
    s.close()
