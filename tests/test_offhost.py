"""Off-host icons, unverified-name page requests and the favicon positive control. Loopback only."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml

from scanner.internet import favicon as fav
from scanner.internet.config import ConfigError, load_config
from scanner.internet.selftest import run_selftest
from scanner.safety import TargetPolicy
from scanner.web_fetch import FetchLimits
from tests.helpers import FakeFetcher, config_dict, make_png, write_approval, write_config, write_exclusions
from tests.test_pipeline import IP_ELSE, IP_OK, cfg, go, rows_of, tools     # noqa: F401  (cfg is a fixture)

PNG = make_png()


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def do_GET(self):      # noqa: N802
        if self.path.startswith("/icon"):
            body, ctype, status = PNG, "image/png", 200
        elif self.path == "/to-other-port":
            self.send_response(302)
            self.send_header("Location", "http://cdn.example.test:22/x.png")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        else:
            body, ctype, status = b"nope", "text/plain", 404
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    s = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield s
    s.shutdown()
    s.server_close()


class _Dns:
    def resolve_a(self, hostname):
        return ["127.0.0.1"] if hostname.endswith(".example.test") else []


def offhost(port, monkeypatch, **kw):
    monkeypatch.setattr(fav, "OFFHOST_PORTS", (port,))
    lim = FetchLimits(connect_timeout=2, read_timeout=2, total_timeout=5, max_bytes=100_000, max_decoded_bytes=100_000, max_redirects=2)
    args = dict(max_total=10, max_per_host=2, min_interval=0.0)
    args.update(kw)
    return fav.OffhostIconFetcher(TargetPolicy.for_tests(["127.0.0.1/32"]), _Dns(), user_agent="t", document_limits=lim,
                                  favicon_limits=lim, retry_statuses=(), max_retries=0, retry_after_cap=0.0, **args)


def test_selftest_positive_and_negative_controls(tmp_path):
    result = run_selftest(load_config(write_config(tmp_path), require_approval=False))
    by = {c["case"]: c for c in result["cases"]}
    assert result["ok"], result
    assert by["declared"]["got_image"] and by["fallback"]["got_image"]
    assert by["catchall"]["got_image"] is False and by["catchall"]["outcome"] == "not_an_image"      # HTTP 200 HTML is not an icon


def test_offhost_fetch_returns_real_image_and_is_logged(server, monkeypatch):
    port = server.server_address[1]
    f = offhost(port, monkeypatch)
    res, body = f.fetch(f"http://cdn.example.test:{port}/icon.png", connect_ip=None, kind="favicon", context="https://1.2.3.4:443/")
    assert res.http_status == 200 and body == PNG
    entry = f.log[0]
    assert entry["referred_by"] == "https://1.2.3.4:443/" and entry["cached"] is False and entry["connect_ip"] == "127.0.0.1"


def test_offhost_same_url_is_fetched_once_and_caps_apply(server, monkeypatch):
    port = server.server_address[1]
    f = offhost(port, monkeypatch, max_per_host=2, max_total=3)
    url = lambda n: f"http://cdn.example.test:{port}/icon{n}.png"       # noqa: E731
    f.fetch(url(1), connect_ip=None, kind="favicon", context="a")
    f.fetch(url(1), connect_ip=None, kind="favicon", context="b")      # same URL, different page: served from cache
    assert [e["cached"] for e in f.log] == [False, True]
    f.fetch(url(2), connect_ip=None, kind="favicon", context="c")
    res, _ = f.fetch(url(3), connect_ip=None, kind="favicon", context="d")        # third distinct URL on one host
    assert res.outcome == "policy_refused" and res.failure_category == "host_cap"
    other = f.fetch(f"http://img.example.test:{port}/icon9.png", connect_ip=None, kind="favicon", context="e")[0]
    assert other.http_status == 200
    res, _ = f.fetch(f"http://third.example.test:{port}/icon1.png", connect_ip=None, kind="favicon", context="f")
    assert res.failure_category == "run_cap"                                          # max_total=3 requests actually sent


def test_offhost_refuses_ip_literals_other_ports_documents_and_pinned_ips(server, monkeypatch):
    port = server.server_address[1]
    f = offhost(port, monkeypatch)
    assert f.fetch(f"http://127.0.0.1:{port}/icon.png", connect_ip=None, kind="favicon")[0].outcome == "policy_refused"
    assert f.fetch("http://cdn.example.test:22/icon.png", connect_ip=None, kind="favicon")[0].failure_category == "offhost_port"
    assert f.fetch(f"http://cdn.example.test:{port}/", connect_ip=None, kind="document")[0].failure_category == "offhost_favicons_only"
    assert f.fetch(f"http://cdn.example.test:{port}/icon.png", connect_ip="127.0.0.1", kind="favicon")[0].failure_category == "offhost_favicons_only"
    redirected = f.fetch(f"http://cdn.example.test:{port}/to-other-port", connect_ip=None, kind="favicon")[0]
    assert redirected.outcome == "policy_refused"                                    # a redirect hop may not leave the web ports


def test_offhost_resolution_to_non_public_space_is_refused(server, monkeypatch):
    port = server.server_address[1]
    monkeypatch.setattr(fav, "OFFHOST_PORTS", (port,))
    lim = FetchLimits(connect_timeout=2, read_timeout=2, total_timeout=5, max_bytes=10_000, max_decoded_bytes=10_000, max_redirects=2)
    # production-style policy: loopback is reserved, so a name that resolves there must be refused
    from scanner.internet.population import population_cidrs
    from scanner.safety import HostnamePolicyInput, ProductionPolicyInput
    policy = TargetPolicy.production(ProductionPolicyInput("ref", tuple(population_cidrs()), HostnamePolicyInput("any_public")))
    f = fav.OffhostIconFetcher(policy, _Dns(), user_agent="t", document_limits=lim, favicon_limits=lim, retry_statuses=(),
                               max_retries=0, retry_after_cap=0.0, max_total=5, max_per_host=5, min_interval=0.0)
    res, body = f.fetch(f"http://cdn.example.test:{port}/icon.png", connect_ip=None, kind="favicon")
    assert body is None and res.outcome in ("policy_refused", "dns_failure")


def test_kill_switch_stops_offhost_requests(server, monkeypatch):
    port = server.server_address[1]
    f = offhost(port, monkeypatch, killed=lambda: True)
    res, _ = f.fetch(f"http://cdn.example.test:{port}/icon.png", connect_ip=None, kind="favicon")
    assert res.failure_category == "kill_switch"


def test_router_sends_only_unpinned_favicons_to_the_third_party_fetcher():
    seen = []

    class Rec:
        def __init__(self, name):
            self.name = name

        def fetch(self, url, *, connect_ip, kind, context=""):
            seen.append((self.name, kind, connect_ip))
            return None, None

    r = fav.RoutingFetcher(Rec("local"), Rec("offhost"))
    r.fetch("http://a/", connect_ip="1.1.1.1", kind="document")
    r.fetch("http://a/i.png", connect_ip="1.1.1.1", kind="favicon")
    r.fetch("http://cdn/i.png", connect_ip=None, kind="favicon")
    assert seen == [("local", "document", "1.1.1.1"), ("local", "favicon", "1.1.1.1"), ("offhost", "favicon", None)]


def _cfg_with(tmp_path, favicon_extra, ops=None):
    excl = write_exclusions(tmp_path)
    approval = write_approval(tmp_path, excl, **({"operations": ops} if ops else {}))
    d = config_dict(tmp_path, excl, approval)
    d["favicon"].update(favicon_extra)
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(d), encoding="utf-8")
    return p


def test_offhost_icons_need_their_own_approval_operation(tmp_path):
    extra = {"offhost_icons": {"enabled": True}}
    with pytest.raises(ConfigError, match="not authorized"):
        load_config(_cfg_with(tmp_path, extra))
    cfg = load_config(_cfg_with(tmp_path, extra, ["hostname_resolution", "favicon_fetch", "offhost_icon_fetch"]))
    assert cfg.favicon.offhost.enabled and cfg.favicon.offhost.max_per_host == 3 and cfg.favicon.offhost.max_total_fetches == 500


def test_new_favicon_options_default_to_off_and_are_validated(tmp_path):
    cfg = load_config(write_config(tmp_path))
    assert cfg.favicon.offhost.enabled is False and cfg.favicon.max_unverified_names_per_endpoint == 0
    with pytest.raises(ConfigError):
        load_config(_cfg_with(tmp_path, {"offhost_icons": {"enabled": "yes"}}))
    with pytest.raises(ConfigError):
        load_config(_cfg_with(tmp_path, {"offhost_icons": {"enabled": False, "bogus": 1}}))
    with pytest.raises(ConfigError):
        load_config(_cfg_with(tmp_path, {"max_unverified_names_per_endpoint": 99}))


def test_unverified_names_are_requested_on_the_scanned_ip_and_labelled(tmp_path):
    cfg = load_config(_cfg_with(tmp_path, {"max_unverified_names_per_endpoint": 2}))
    f = FakeFetcher()
    run_dir = go(cfg, tools(), fetcher=f)
    # IP_ELSE shows good.test's certificate, but good.test resolves to IP_OK, so the name does not verify
    assert ("https://good.test:443/", IP_ELSE, "document") in f.calls
    r = [x for x in rows_of(run_dir) if x["target_ip"] == IP_ELSE and x["hostname"] == "good.test"][0]
    assert r["final_hostname_status"] == "resolved_elsewhere" and r["hostname_favicon_outcome"] is not None
    assert all(ip in {IP_OK, IP_ELSE, "1.1.1.2", "1.1.1.3"} for _u, ip, _k in f.calls)       # still only scanned addresses
    summary = json.loads((run_dir / "report" / "summary.json").read_text())
    assert summary["counts"]["favicon_jobs_unverified_names"] >= 1


def test_default_makes_no_unverified_name_requests(cfg):
    f = FakeFetcher()
    go(cfg, tools(), fetcher=f)
    assert ("https://good.test:443/", IP_ELSE, "document") not in f.calls


def test_offhost_log_is_written_and_counted(tmp_path):
    p = _cfg_with(tmp_path, {"offhost_icons": {"enabled": True}},
                  ["hostname_resolution", "favicon_fetch", "offhost_icon_fetch"])
    cfg = load_config(p)

    class Routed(FakeFetcher):
        offhost = type("O", (), {"log": [
            {"url": "https://cdn.x.example/i.png", "referred_by": "https://1.1.1.1:443/", "outcome": "ok", "failure_category": None,
             "http_status": 200, "content_type": "image/png", "bytes": 10, "sha256": "a" * 64, "connect_ip": "9.9.9.9", "cached": False, "redirects": []},
            {"url": "https://cdn.x.example/i.png", "referred_by": "https://1.1.1.2:443/", "outcome": "ok", "failure_category": None,
             "http_status": 200, "content_type": "image/png", "bytes": 10, "sha256": "a" * 64, "connect_ip": "9.9.9.9", "cached": True, "redirects": []},
            {"url": "https://cdn.y.example/i.png", "referred_by": "https://1.1.1.2:443/", "outcome": "policy_refused", "failure_category": "host_cap",
             "http_status": None, "content_type": None, "bytes": 0, "sha256": None, "connect_ip": None, "cached": False, "redirects": []}]})()

    run_dir = go(cfg, tools(), fetcher=Routed())
    lines = [json.loads(l) for l in (run_dir / "normalized" / "offhost_icon_fetches.jsonl").read_text().splitlines()]
    assert len(lines) == 3
    counts = json.loads((run_dir / "report" / "summary.json").read_text())["counts"]
    assert counts["offhost_icon_requests"] == 1 and counts["offhost_icon_refused"] == 1
