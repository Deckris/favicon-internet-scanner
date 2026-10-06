"""Regression tests for hostile input found in review: odd line separators, surrogates, deep wildcards, suffix boundaries."""
import json
from types import SimpleNamespace

from scanner.certificates import normalize_hostname
from scanner.internet import tls
from scanner.internet.enrich import tarpit_assessment
from scanner.safety import HostnamePolicyInput, ProductionPolicyInput, TargetPolicy
from tests.helpers import FIX
from tests.test_pipeline import IP_OK, go, rows_of, tools


def test_unicode_line_separators_inside_a_record_do_not_split_it(tmp_path):
    base = (FIX / "zgrab_tls" / "ok.jsonl").read_text(encoding="utf-8").splitlines()[0]
    hostile = base.replace('"good.test"', '"good\u0085.test"', 1)          # Go's JSON encoder leaves U+0085 unescaped
    assert hostile != base and "\n" not in hostile

    def fake(cmd, input="", **kw):
        obj_line = hostile.replace('"ip": "', '"ip": "', 1)
        return SimpleNamespace(returncode=0, stdout=obj_line + "\n", stderr="")
    cfg = SimpleNamespace(measurement=SimpleNamespace(zgrab_batch_size=5, zgrab_connect_timeout=4.0, zgrab_target_timeout=8.0, zgrab_senders=5))
    ip = json.loads(base)["ip"]
    port = json.loads(base).get("port", 443)
    _job, results = tls.run_tls_batches([(ip, port, None)], mode="direct_ip", cfg=cfg, policy=TargetPolicy.for_tests([f"{ip}/32"]),
                                        run_dir=tmp_path, executor=fake)
    assert len(results) == 1 and results[0].outcome == tls.OK                # one record in, one success out


def test_deeply_nested_wildcards_and_huge_names_are_rejected_fast():
    assert normalize_hostname("*." * 5000 + "x.example.com") is None
    assert normalize_hostname("*.*.example.com") is None
    assert normalize_hostname("*.example.com") == "*.example.com"            # the one valid wildcard shape still works
    assert normalize_hostname("a" * 2000 + ".example.com") is None


def test_hostname_suffix_allowlist_respects_label_boundaries():
    policy = TargetPolicy.production(ProductionPolicyInput("ref", ("1.0.0.0/8",), HostnamePolicyInput("suffix_allowlist", ("example.com",))))
    assert policy.check_hostname("example.com", stage="t") is None
    assert policy.check_hostname("shop.example.com", stage="t") is None
    assert policy.check_hostname("evilexample.com", stage="t") is not None   # was allowed by a bare endswith()
    assert policy.check_hostname("example.com.evil.net", stage="t") is not None
    dotted = TargetPolicy.production(ProductionPolicyInput("ref", ("1.0.0.0/8",), HostnamePolicyInput("suffix_allowlist", (".example.com",))))
    assert dotted.check_hostname("evilexample.com", stage="t") is not None and dotted.check_hostname("a.example.com", stage="t") is None


def test_names_with_control_characters_never_pass_the_policy():
    policy = TargetPolicy.production(ProductionPolicyInput("ref", ("1.0.0.0/8",), HostnamePolicyInput("any_public")))
    for bad in ("a.example.com\n", "a.example.com\r", "a.exa\x00mple.com", "a.example.com\t", " a.example.com"):
        assert policy.check_hostname(bad, stage="t") is not None, repr(bad)


def test_surrogate_in_ptr_still_produces_every_output_and_an_honest_manifest(tmp_path):
    from scanner.internet.config import load_config
    from tests.helpers import write_config
    cfg = load_config(write_config(tmp_path))
    ft = tools(ptr={IP_OK: ["bad\ud800name.test."]})
    run_dir = go(cfg, ft)
    for name in ("endpoints.jsonl", "hostname_resolution.jsonl", "hostname_resolution.csv", "tool_jobs.jsonl"):
        assert (run_dir / "normalized" / name).stat().st_size > 0, name
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["complete"] is True and not manifest["stage_errors"]
    assert rows_of(run_dir)


def test_unrun_tls_stage_is_unknown_not_silent_and_ptr_names_are_capped(tmp_path):
    ep = lambda proto: {"protocol": proto, "window": 64240, "doc_sha256": None, "doc_status": None}      # noqa: E731
    assert not tarpit_assessment([ep("not_attempted")] * 5, 5, 4)["tarpit_suspect"]                     # a failed stage is not evidence
    assert tarpit_assessment([ep("tcp_only")] * 5, 5, 4)["tarpit_suspect"]
    from scanner.internet.config import load_config
    from tests.helpers import write_config
    cfg = load_config(write_config(tmp_path))
    names = [f"h{i}.rev.example." for i in range(300)]
    run_dir = go(cfg, tools(ptr={IP_OK: names}))
    row = [r for r in rows_of(run_dir) if r["target_ip"] == IP_OK][0]
    assert len(row["ptr_names"]) <= 20 and row["ptr_name_count"] == 300


def test_brotli_bomb_is_stopped_before_it_is_expanded():
    import brotli
    import pytest
    from scanner.web_fetch import _StreamDecoder, _TooLarge
    bomb = brotli.compress(b"\0" * 200_000_000, quality=1)
    dec = _StreamDecoder("br", 1_000_000)
    with pytest.raises(_TooLarge):
        dec.feed(bomb)
    assert dec._total < 5_000_000                                            # never held the 200 MB


def test_server_that_drips_headers_cannot_outlive_the_deadline():
    import socket
    import threading
    import time
    from scanner.web_fetch import FetchLimits, WebFetcher
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def drip():
        conn, _ = srv.accept()
        conn.recv(4096)
        try:
            conn.sendall(b"HTTP/1.1 200 OK\r\n")
            for _ in range(60):
                time.sleep(1)
                conn.sendall(b"X-A: b\r\n")
        except OSError:
            pass
    threading.Thread(target=drip, daemon=True).start()
    port = srv.getsockname()[1]
    lim = FetchLimits(connect_timeout=2.0, read_timeout=5.0, total_timeout=3.0, max_bytes=10_000, max_decoded_bytes=10_000, max_redirects=1)
    fetcher = WebFetcher(TargetPolicy.for_tests(["127.0.0.1/32"]), None, user_agent="t", document_limits=lim, favicon_limits=lim)
    t0 = time.monotonic()
    res, _body = fetcher.fetch(f"http://127.0.0.1:{port}/", connect_ip="127.0.0.1", kind="document")
    assert time.monotonic() - t0 < 8
    assert res.outcome == "timeout"


def test_icon_url_with_an_impossible_port_is_a_clean_failure_not_an_exception():
    from scanner.safety import TargetPolicy
    from scanner.web_fetch import FetchLimits, WebFetcher
    lim = FetchLimits(connect_timeout=1.0, read_timeout=1.0, total_timeout=2.0, max_bytes=1000, max_decoded_bytes=1000, max_redirects=1)
    fetcher = WebFetcher(TargetPolicy.for_tests(["127.0.0.1/32"]), None, user_agent="t", document_limits=lim, favicon_limits=lim)
    res, _ = fetcher.fetch("http://127.0.0.1:99999999/x", connect_ip="127.0.0.1", kind="favicon")
    assert res.outcome != "ok"


def test_kill_switch_ends_a_request_that_is_still_dripping_its_response():
    import socket
    import threading
    import time
    from types import SimpleNamespace as NS

    from scanner.internet import favicon as fav
    from scanner.safety import TargetPolicy
    from scanner.internet.selftest import _NoDns

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def drip():
        c, _ = srv.accept()
        try:
            c.recv(4096)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
            for _ in range(100):
                c.sendall(b"a")
                time.sleep(0.2)
        except OSError:
            pass
    threading.Thread(target=drip, daemon=True).start()
    port = srv.getsockname()[1]
    stop = {"now": False}
    threading.Timer(1.0, lambda: stop.update(now=True)).start()
    lim = fav._limits(NS(fetch=NS(connect_timeout=4, read_timeout=8, total_timeout=30, max_redirects=3, max_decoded_bytes=4194304)), 1 << 20)
    fetcher = fav.GuardedFetcher(TargetPolicy.for_tests(["127.0.0.1/32"]), _NoDns(), user_agent="t", allowed_endpoints={("127.0.0.1", port)},
                                 document_limits=lim, favicon_limits=lim, killed=lambda: stop["now"])
    started = time.monotonic()
    fav.probe_identity(fetcher, scheme="http", ip="127.0.0.1", port=port, hostname=None, max_icons=1)
    assert time.monotonic() - started < 5          # without the kill check this waits for the 30 s total timeout
    srv.close()
