"""JavaScript-set icons: candidate choice, request policy, budgets, extraction through a fake browser driver, config."""
from __future__ import annotations

import json
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from scanner.favicon_discovery import manifest_icon_links, policy_for
from scanner.internet import favicon as fav
from scanner.internet import js_icons, pipeline, profile
from scanner.internet.config import ConfigError, load_config
from tests.helpers import FakeFetcher, make_png, write_config
from tests.test_config import _rewrite
from tests.test_offhost import _cfg_with
from tests.test_pipeline import tools

PNG = make_png()
IP = "198.51.100.7"


def result(url, kind, status, body, ctype):
    from scanner.models import FetchResult
    return FetchResult(
        kind=kind, requested_url=url, connect_ip=IP, host_header=None, sni=None, outcome="ok" if status == 200 else "http_status",
        failure_category=None, http_status=status, content_type=ctype, content_encoding=None, retry_after=None,
        body_sha256="y" * 64, body_bytes=len(body or b""), redirect_chain=(), final_url=url, certificate=None), body


class NoIconFetcher(FakeFetcher):
    """Pages without an icon: every icon request fails except /js-icon.png; /app.webmanifest names /m-icon.png."""

    def fetch(self, url, *, connect_ip, kind, context=""):
        self.calls.append((url, connect_ip, kind))
        if url.endswith("/app.webmanifest"):
            return result(url, kind, 200, json.dumps({"icons": [{"src": "m-icon.png", "sizes": "192x192", "type": "image/png"}]}).encode(), "application/json")
        if kind == "favicon":
            if url.endswith(("/js-icon.png", "/m-icon.png")):
                return result(url, kind, 200, PNG, "image/png")
            return result(url, kind, 404, b"nope", "text/plain")
        return super().fetch(url, connect_ip=connect_ip, kind=kind, context=context)


class FakeDriver:
    def __init__(self, links=None, manifest=None, delay=0.0, fail=None, log=None):
        self.links, self.manifest, self.delay, self.fail, self.log = links, manifest, delay, fail, log if log is not None else []
        self.started = self.closed = 0

    def start(self):
        if self.fail:
            raise self.fail
        self.started += 1

    def close(self):
        self.closed += 1

    def render(self, request, policy):
        self.log.append(("render", request.url))
        if self.delay:
            time.sleep(self.delay)
        # the page asks for more than it may have; the policy decides, the driver obeys
        for url, kind in (("http://%s/app.js" % request.ip, "script"), ("http://cdn.example.test/lib.js", "script"),
                          ("http://%s/pic.png" % request.ip, "image")):
            policy.decide(url, kind)
        links = self.links if self.links is not None else [{"rel": "icon", "href": f"http://{request.ip}:{request.port}/js-icon.png", "sizes": "32x32"}]
        return js_icons.RenderedPage(links=links, manifest_url=self.manifest, requests=policy.requests, blocked=policy.blocked,
                                     blocked_hosts=list(policy.blocked_hosts), render_ms=5)


class Pacer:
    def __init__(self, allow=True, log=None):
        self.allow, self.log = allow, log if log is not None else []

    def wait(self, ip):
        self.log.append(("wait", ip))
        return self.allow

    def done(self, ip, result=None):
        self.log.append(("done", ip, getattr(result, "outcome", None)))


def js_cfg(**over):
    base = dict(enabled=True, max_pages_per_shard=100, page_timeout_seconds=1.0, concurrency=2, wait_ms=0)
    base.update(over)
    return SimpleNamespace(**base)


def page_record(ip=IP, port=80, fetcher=None):
    return {**fav.probe_identity(fetcher or NoIconFetcher(), scheme="http", ip=ip, port=port, hostname=None, max_icons=2), "ip": ip, "port": port}


def stage(records, driver, *, pacer=None, fetcher=None, manifest=True, cfg=None, factory=None, **kw):
    return js_icons.run_stage(
        records, cfg_js=cfg or js_cfg(), driver_factory=factory or (lambda: driver), fetcher=fetcher or NoIconFetcher(),
        pacer=pacer or Pacer(), allowed_endpoints={(r["ip"], r["port"]) for r in records}, fill=fav.fill_icon_fields,
        max_icons=2, concurrency=kw.pop("concurrency", 1), manifest=manifest, **kw)


# ---- which pages -------------------------------------------------------------------------------------------------------

def test_only_pages_without_any_icon_image_are_candidates():
    bare = page_record(IP)
    with_icon = page_record("198.51.100.8", fetcher=FakeFetcher())
    named = {**page_record("198.51.100.9"), "kind": "hostname"}
    failed = {**bare, "document_outcome": "timeout", "http_status": None, "ip": "198.51.100.10"}
    assert bare["favicon_is_image"] is False and with_icon["favicon_is_image"] is True
    picked, over = js_icons.candidate_pages([bare, with_icon, named, failed], 10)
    assert [r["ip"] for r in picked] == [IP] and over == 0


def test_the_page_cap_limits_the_pages_and_counts_the_rest():
    recs = [page_record(f"198.51.100.{n}") for n in range(20, 26)]
    picked, over = js_icons.candidate_pages(recs, 4)
    assert len(picked) == 4 and over == 2


# ---- the browser's request policy --------------------------------------------------------------------------------------

def test_policy_allows_only_the_pages_own_address_and_port_and_no_images():
    p = js_icons.BrowserRequestPolicy(IP, {(IP, 80)})
    assert p.decide(f"http://{IP}/", "document") and p.decide(f"http://{IP}:80/a.js", "script") and p.decide(f"http://{IP}/x", "xhr")
    for url, kind in ((f"http://{IP}/i.png", "image"), (f"http://{IP}/f.woff", "font"), (f"http://{IP}/v.mp4", "media"),
                      ("http://cdn.example.test/lib.js", "script"), ("http://203.0.113.5/lib.js", "script"),
                      (f"http://{IP}:8080/a.js", "script"), (f"https://{IP}/a.js", "script"), (f"ws://{IP}/s", "websocket"),
                      ("data:text/javascript,1", "script"), ("file:///etc/passwd", "document"), (f"http://{IP}:bad/", "script")):
        assert not p.decide(url, kind), (url, kind)
    assert "cdn.example.test" in p.blocked_hosts and p.blocked >= 8


def test_policy_caps_the_requests_of_one_page():
    p = js_icons.BrowserRequestPolicy(IP, {(IP, 80)}, max_requests=3)
    assert [p.decide(f"http://{IP}/{n}.js", "script") for n in range(5)] == [True, True, True, False, False]


# ---- the stage with a fake driver --------------------------------------------------------------------------------------

def test_icon_set_by_script_is_fetched_through_the_guarded_fetcher_and_recorded():
    rec = page_record()
    fetcher = NoIconFetcher()
    pacer_log = []
    driver = FakeDriver(log=pacer_log)
    res = stage([rec], driver, pacer=Pacer(log=pacer_log), fetcher=fetcher)
    assert res.status == "ok"
    new = res.replacements[(IP, 80, None)]
    assert new["favicon_source"] == "javascript" and new["favicon_is_image"] is True and new["favicon_outcome"] == "image"
    assert new["js_icon_urls"] == [f"http://{IP}:80/js-icon.png"] and new["js_render_ms"] == 5 and new["js_total_ms"] >= 0
    assert (f"http://{IP}:80/js-icon.png", IP, "favicon") in fetcher.calls
    assert rec["favicon_is_image"] is False, "the original record is left alone"
    row = res.rows[0]
    assert row["image_found"] and row["blocked"] == 2 and "cdn.example.test" in row["blocked_hosts"]
    assert pacer_log[0] == ("wait", IP) and pacer_log[1][0] == "render" and pacer_log[-1] == ("done", IP, "ok"), "paced before the load"


def test_a_page_with_no_script_set_icon_keeps_its_record():
    res = stage([page_record()], FakeDriver(links=[{"rel": "stylesheet", "href": "x.css"}]))
    assert res.replacements == {} and res.rows[0]["icon_urls"] == [] and res.status == "ok"


def test_pacer_refusal_means_the_page_is_never_loaded():
    log = []
    res = stage([page_record()], FakeDriver(log=log), pacer=Pacer(allow=False))
    assert log == [] and res.rows[0]["status"] == "skipped" and res.replacements == {}


def test_kill_switch_stops_the_stage_before_a_page_loads():
    log = []
    res = stage([page_record()], FakeDriver(log=log), killed=lambda: True)
    assert log == [] and res.replacements == {}


def test_page_over_its_time_budget_is_recorded_and_the_driver_replaced():
    made = []

    def factory():
        made.append(FakeDriver(delay=30.0 if not made else 0.0))
        return made[-1]
    started = time.monotonic()
    recs = [page_record(), page_record("198.51.100.8")]
    res = stage(recs, None, factory=factory, cfg=js_cfg(page_timeout_seconds=1.0))
    assert time.monotonic() - started < 8
    assert [r["status"] for r in sorted(res.rows, key=lambda r: r["ip"])] == ["timeout", "ok"]
    assert len(made) == 2 and made[0].closed == 1, "the wedged driver was closed and a fresh one started"
    assert res.counts()["js_pages_timeout"] == 1


def test_missing_browser_is_recorded_as_unavailable():
    res = stage([page_record()], None, factory=lambda: FakeDriver(fail=js_icons.DriverUnavailable("no browser")))
    assert res.status == "unavailable" and res.detail == "no browser" and res.counts()["js_icons"] == "unavailable"


def test_the_playwright_package_missing_is_unavailable_not_an_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "playwright", None)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    with pytest.raises(js_icons.DriverUnavailable, match="not installed"):
        js_icons.PlaywrightDriver("ua").start()
    res = stage([page_record()], None, factory=lambda: js_icons.PlaywrightDriver("ua"))
    assert res.status == "unavailable"


def test_manifest_icons_are_used_only_when_manifest_parsing_is_on_and_no_link_icon_exists():
    page = lambda: FakeDriver(links=[], manifest=f"http://{IP}:80/app.webmanifest")             # noqa: E731
    on = stage([page_record()], page(), manifest=True)
    assert on.replacements[(IP, 80, None)]["js_manifest_used"] is True
    assert on.replacements[(IP, 80, None)]["js_icon_urls"] == [f"http://{IP}:80/m-icon.png"]
    off = stage([page_record()], page(), manifest=False)
    assert off.replacements == {}
    elsewhere = stage([page_record()], FakeDriver(links=[], manifest="http://cdn.example.test/app.webmanifest"))
    assert elsewhere.replacements == {}, "a manifest on another host is not requested"
    fetcher = NoIconFetcher()
    stage([page_record()], FakeDriver(links=[], manifest="http://cdn.example.test/app.webmanifest"), fetcher=fetcher)
    assert not any("cdn.example.test" in c[0] for c in fetcher.calls)


def test_manifest_parser_resolves_limits_and_respects_the_switch():
    text = json.dumps({"icons": [{"src": "a.png", "sizes": "48x48"}, {"src": "/b.png"}, {"nosrc": 1}, {"src": "c.png", "type": "image/png"}]})
    assert manifest_icon_links("http://h/x/app.json", text) == []
    links = manifest_icon_links("http://h/x/app.json", text, policy=policy_for(True), limit=2)
    assert [l["href"] for l in links] == ["http://h/x/a.png", "http://h/b.png"] and links[0]["sizes"] == "48x48"
    assert manifest_icon_links("http://h/m", "{not json", policy=policy_for(True)) == []
    assert policy_for(False)["manifest"] is False and policy_for(True)["javascript"] is True


def test_concurrency_default_follows_cores_and_memory():
    assert profile.javascript_concurrency(2, 3.8) == 1
    assert profile.javascript_concurrency(16, 64) == 8
    assert profile.javascript_concurrency(64, 512) == profile.MAX_BROWSERS
    assert profile.javascript_concurrency(16, 2.0) == 1
    assert profile.javascript_concurrency(8, None) == 4


def test_several_pages_run_on_several_drivers():
    made, lock = [], threading.Lock()

    def factory():
        with lock:
            made.append(FakeDriver(delay=0.2))
            return made[-1]
    recs = [page_record(f"198.51.100.{n}") for n in range(30, 36)]
    res = stage(recs, None, factory=factory, concurrency=3)
    assert len(res.rows) == 6 and len(made) == 3 and all(d.closed == 1 for d in made)


# ---- configuration -----------------------------------------------------------------------------------------------------

def test_javascript_block_defaults_to_off_and_validates(tmp_path):
    js = load_config(write_config(tmp_path)).favicon.javascript
    assert js.enabled is False and js.concurrency is None and js.max_pages_per_shard >= 1 and js.page_timeout_seconds > 0
    cfg = load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(javascript={"enabled": True, "max_pages_per_shard": 50,
                                                                                    "page_timeout_seconds": 12, "concurrency": 3, "wait_ms": 800})))
    assert (cfg.favicon.javascript.enabled, cfg.favicon.javascript.max_pages_per_shard, cfg.favicon.javascript.concurrency) == (True, 50, 3)
    for bad in ({"enabled": "yes"}, {"enabled": True, "bogus": 1}, {"enabled": True, "max_pages_per_shard": 0},
                {"enabled": True, "page_timeout_seconds": 0}, {"enabled": True, "page_timeout_seconds": 500},
                {"enabled": True, "concurrency": 0}, {"enabled": True, "wait_ms": -1}):
        with pytest.raises(ConfigError):
            load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(javascript=bad)))


def test_enabling_javascript_changes_the_config_checksum_and_leaving_it_out_does_not(tmp_path):
    base = load_config(write_config(tmp_path))
    explicit_off = load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(javascript={"enabled": False})))
    on = load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(javascript={"enabled": True})))
    assert on.checksum != base.checksum and explicit_off.favicon.javascript.enabled is False


# ---- inside a run ------------------------------------------------------------------------------------------------------

class PipelineFetcher(NoIconFetcher):
    def fetch(self, url, *, connect_ip, kind, context=""):
        if kind == "favicon" and url.endswith("/js-icon.png"):
            self.calls.append((url, connect_ip, kind))
            return result(url, kind, 200, PNG, "image/png")
        return super().fetch(url, connect_ip=connect_ip, kind=kind, context=context)


def test_disabled_means_no_browser_no_extra_output(tmp_path, monkeypatch):
    monkeypatch.setattr(js_icons, "default_driver_factory", lambda cfg: pytest.fail("a browser was requested"))
    cfg = load_config(write_config(tmp_path))
    run_dir = pipeline.run(cfg, run_id="r1", executor=tools(), fetcher=PipelineFetcher(), skip_preflight=True, offline_preflight=True)
    counts = json.loads((run_dir / "report" / "summary.json").read_text())["counts"]
    assert not [k for k in counts if k.startswith("js_")] and not (run_dir / "normalized" / "js_icon_pages.jsonl").exists()
    assert all("favicon_source" not in json.loads(l) for l in (run_dir / "raw" / "favicon_records.jsonl").read_text().splitlines())


def _enabled(tmp_path):
    return load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(javascript={"enabled": True, "concurrency": 1, "wait_ms": 0})))


def test_enabled_run_replaces_iconless_records_and_writes_the_page_log(tmp_path, monkeypatch):
    drivers = []
    monkeypatch.setattr(js_icons, "default_driver_factory", lambda cfg: (lambda: drivers.append(FakeDriver()) or drivers[-1]))
    run_dir = pipeline.run(_enabled(tmp_path), run_id="r1", executor=tools(), fetcher=PipelineFetcher(), skip_preflight=True, offline_preflight=True)
    counts = json.loads((run_dir / "report" / "summary.json").read_text())["counts"]
    assert counts["js_icons"] == "ok" and counts["js_icons_found"] >= 1 and counts["js_pages_attempted"] >= 1
    pages = [json.loads(l) for l in (run_dir / "normalized" / "js_icon_pages.jsonl").read_text().splitlines()]
    assert pages and all(p["status"] == "ok" for p in pages) and any(p["image_found"] for p in pages)
    assert (run_dir / "favicons" / "index.jsonl").read_text().strip(), "the icon found by script is stored like any other"


def test_enabled_run_without_a_browser_carries_on(tmp_path, monkeypatch):
    def broken(cfg):
        return lambda: FakeDriver(fail=js_icons.DriverUnavailable("chromium cannot start"))
    monkeypatch.setattr(js_icons, "default_driver_factory", broken)
    run_dir = pipeline.run(_enabled(tmp_path), run_id="r1", executor=tools(), fetcher=PipelineFetcher(), skip_preflight=True, offline_preflight=True)
    counts = json.loads((run_dir / "report" / "summary.json").read_text())["counts"]
    assert counts["js_icons"] == "unavailable" and counts["js_icons_detail"] == "chromium cannot start" and counts["js_icons_found"] == 0
    assert (run_dir / "manifest.json").exists() or (run_dir / "report" / "summary.json").exists()
