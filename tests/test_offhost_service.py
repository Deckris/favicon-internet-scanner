"""Off-host icons with several favicon processes: one parent-side fetcher, one request per URL, per-destination pacing."""
from __future__ import annotations

import json
import threading
import time

import pytest

from scanner.internet import favicon as fav
from scanner.internet import pacing, pipeline
from scanner.internet.config import ConfigError, load_config
from scanner.safety import TargetPolicy
from scanner.web_fetch import FetchLimits, _RequestOutcome
from tests.helpers import FakeFetcher, ProcessFetcher, make_png
from tests.test_offhost import _cfg_with
from tests.test_pipeline import tools

PNG = make_png()
OPS = ["hostname_resolution", "favicon_fetch", "offhost_icon_fetch"]
DEST = "203.0.113.9"


class _Dns:
    """Names under .example.test resolve to DEST unless the table says otherwise."""

    def __init__(self, table=None):
        self.table = table or {}

    def resolve_a(self, hostname):
        return [self.table.get(hostname, DEST)] if hostname.endswith(".example.test") else []


class StubWire(fav.OffhostIconFetcher):
    """The real off-host fetcher over a fake network: answers a PNG and records when each address was contacted."""

    def __init__(self, *args, hold=0.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.contacts: list[tuple[str, float, float]] = []
        self.hold = hold
        self._contact_lock = threading.Lock()

    def _one_request_inner(self, parts, hostname, port, connect_ip, limits, timeout, deadline, guard):
        start = time.monotonic()
        if self.hold:
            time.sleep(self.hold)
        with self._contact_lock:
            self.contacts.append((connect_ip, start, time.monotonic()))
        return _RequestOutcome(
            kind="status", outcome="ok", http_status=200, content_type="image/png", content_encoding=None, location=None,
            body=PNG, body_bytes=len(PNG), certificate=None, retry_after_seconds=None, connect_ip=connect_ip,
            host_header=hostname, sni=None, final_url=f"{parts.scheme}://{hostname}{parts.path}")


def stub(pace=0.0, cap=0, dns=None, exclusions=(), hold=0.0, **over):
    lim = FetchLimits(connect_timeout=2, read_timeout=2, total_timeout=5, max_bytes=100_000, max_decoded_bytes=100_000, max_redirects=2)
    limiter = pacing.SubnetLimiter(cap) if cap else None
    pacer = pacing.IpPacer(pace, limiter=limiter, poll=0.05) if pace or limiter else None
    args = dict(max_total=100, max_per_host=10, min_interval=0.0, pacer=pacer, hold=hold)
    args.update(over)
    return StubWire(TargetPolicy.for_tests(["203.0.113.0/24"], exclusions), dns or _Dns(), user_agent="t", document_limits=lim,
                    favicon_limits=lim, retry_statuses=(), max_retries=0, retry_after_cap=0.0, **args)


class OffhostPageFetcher(ProcessFetcher):
    """Serves a page that declares one icon on another host; any other request is answered as FakeFetcher does."""

    def __init__(self, pacer, icons):
        super().__init__(pacer, None, None, None, 0.0)
        self.icons = icons

    def fetch(self, url, *, connect_ip, kind, context=""):
        res, body = super().fetch(url, connect_ip=connect_ip, kind=kind, context=context)
        if kind == "document":
            ip = connect_ip or ""
            body = f'<html><head><link rel="icon" href="{self.icons[ip]}"></head></html>'.encode()
        return res, body


class OffhostPageFactory:
    def __init__(self, icons):
        self.icons = icons

    def __call__(self, pacer, owned=None, killed=None):
        return OffhostPageFetcher(pacer, self.icons)


def jobs_for(addresses):
    return [{"scheme": "http", "ip": f"198.51.100.{i}", "port": 80, "hostname": None} for i in range(1, addresses + 1)]


def run(service, jobs, icons, processes=3):
    return fav.run_favicon_stage_processes(
        OffhostPageFactory(icons), jobs, processes=processes, workers=8, pace=0.0, max_icons=2, offhost_service=service)


def test_one_url_named_by_many_pages_is_fetched_once_across_processes():
    f = stub()
    service = fav.OffhostService(f, threads=8)
    jobs = jobs_for(12)
    out = run(service, jobs, {j["ip"]: "http://cdn.example.test/i.png" for j in jobs})
    assert [r["favicon_outcome"] for r in out] == ["image"] * 12
    assert len(f.contacts) == 1
    assert len(f.log) == 12 and sum(e["cached"] for e in f.log) == 11
    assert {r["favicon_url"] for r in out} == {"http://cdn.example.test/i.png"}


def test_same_content_under_different_urls_is_counted():
    f = stub()
    service = fav.OffhostService(f, threads=8)
    jobs = jobs_for(6)
    out = run(service, jobs, {j["ip"]: f"http://c{n}.example.test/i.png" for n, j in enumerate(jobs)})
    assert len(out) == 6 and len(f.contacts) == 6
    assert sum(e["duplicate_content"] for e in f.log) == 5, "the first URL owns the content, the other five are copies"
    assert len({e["sha256"] for e in f.log}) == 1


def test_url_is_normalised_and_a_final_address_is_cached_too():
    f = stub()
    one = f.fetch("HTTP://CDN.example.test/i.png#top", connect_ip=None, kind="favicon", context="a")
    two = f.fetch("http://cdn.example.test/i.png", connect_ip=None, kind="favicon", context="b")
    assert one is two and len(f.contacts) == 1 and f.log[1]["cached"]


def test_concurrent_askers_for_one_url_share_one_request():
    f = stub(hold=0.3)
    results = []
    threads = [threading.Thread(target=lambda: results.append(
        f.fetch("http://cdn.example.test/i.png", connect_ip=None, kind="favicon", context="p"))) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(f.contacts) == 1 and len(results) == 6 and all(r[1] == PNG for r in results)


def test_one_destination_is_paced_whatever_the_host_name():
    pace = 0.3
    f = stub(pace=pace)
    service = fav.OffhostService(f, threads=8)
    jobs = jobs_for(6)
    out = run(service, jobs, {j["ip"]: f"http://c{n}.example.test/i.png" for n, j in enumerate(jobs)})
    assert all(r["favicon_outcome"] == "image" for r in out)
    times = sorted(t for _ip, t, _end in f.contacts)
    assert len(times) == 6 and {ip for ip, _s, _e in f.contacts} == {DEST}
    assert min(b - a for a, b in zip(times, times[1:])) >= pace - 0.03


def test_destinations_in_one_network_are_never_in_flight_together():
    dns = _Dns({f"c{n}.example.test": f"203.0.113.{10 + n}" for n in range(4)})
    f = stub(pace=0.05, cap=1, dns=dns, hold=0.15)
    service = fav.OffhostService(f, threads=8)
    jobs = jobs_for(4)
    run(service, jobs, {j["ip"]: f"http://c{n}.example.test/i.png" for n, j in enumerate(jobs)}, processes=2)
    spans = sorted((s, e) for _ip, s, e in f.contacts)
    assert len(spans) == 4
    assert all(b[0] >= a[1] - 0.005 for a, b in zip(spans, spans[1:])), "two connections to one /24 overlapped"


def test_exclusions_and_private_space_are_still_refused():
    dns = _Dns({"bad.example.test": "203.0.113.66", "lan.example.test": "10.1.2.3"})
    f = stub(dns=dns, exclusions=["203.0.113.66/32"])
    service = fav.OffhostService(f, threads=4)
    jobs = jobs_for(2)
    out = run(service, jobs, {jobs[0]["ip"]: "http://bad.example.test/i.png", jobs[1]["ip"]: "http://lan.example.test/i.png"}, processes=2)
    assert f.contacts == []
    assert not any(".example.test" in (r["favicon_url"] or "") for r in out)       # only the page's own /favicon.ico is left
    assert {e["outcome"] for e in f.log} <= {"policy_refused", "dns_failure"}


def test_ip_literals_and_other_ports_are_refused_by_the_service():
    f = stub()
    service = fav.OffhostService(f, threads=2)
    jobs = jobs_for(2)
    out = run(service, jobs, {jobs[0]["ip"]: "http://203.0.113.9/i.png", jobs[1]["ip"]: "http://cdn.example.test:22/i.png"}, processes=2)
    assert f.contacts == [] and not any("203.0.113" in (r["favicon_url"] or "") or "example.test" in (r["favicon_url"] or "") for r in out)


def test_caps_are_counted_once_for_all_processes():
    f = stub(max_total=4)
    service = fav.OffhostService(f, threads=8)
    jobs = jobs_for(10)
    out = run(service, jobs, {j["ip"]: f"http://c{n}.example.test/i.png" for n, j in enumerate(jobs)})
    assert len(f.contacts) == 4 and sum("example.test" in (r["favicon_url"] or "") for r in out) == 4
    assert {e["failure_category"] for e in f.log if e["outcome"] == "policy_refused"} == {"run_cap"}


def test_a_lost_service_refuses_instead_of_hanging():
    import multiprocessing
    ctx = multiprocessing.get_context("spawn")
    mine, theirs = ctx.Pipe(duplex=True)
    from scanner.internet.offhost_service import OffhostClient
    client = OffhostClient(theirs)
    mine.close()
    res, body = client.fetch("http://cdn.example.test/i.png", connect_ip=None, kind="favicon", context="p")
    assert res.outcome == "policy_refused" and res.failure_category == "offhost_service_unavailable" and body is None


def test_several_processes_with_off_host_icons_need_the_approval_flag(tmp_path):
    extra = {"processes": 2, "offhost_icons": {"enabled": True}}
    with pytest.raises(ConfigError, match="not authorized"):
        load_config(_cfg_with(tmp_path, extra))
    cfg = load_config(_cfg_with(tmp_path, extra, OPS))
    assert cfg.favicon.processes == 2 and cfg.favicon.offhost.enabled


def test_pipeline_records_cache_hits_with_two_processes(tmp_path, monkeypatch):
    cfg = load_config(_cfg_with(tmp_path, {"processes": 2, "reuse_http_document": False, "offhost_icons": {"enabled": True}}, OPS))
    made = []

    def make(cfg_, resolver, exclusions, **kw):
        made.append(kw)
        return stub(pace=0.0, killed=kw["killed"], state_path=kw["state_path"])
    monkeypatch.setattr(fav, "make_offhost_fetcher", make)

    run_dir = pipeline.run(cfg, run_id="r1", executor=tools(), fetcher_factory=OffhostPageFactory(_AnyIcon()), skip_preflight=True, offline_preflight=True)
    assert made and made[0]["pacer"] is not None
    counts = json.loads((run_dir / "report" / "summary.json").read_text())["counts"]
    log = [json.loads(l) for l in (run_dir / "normalized" / "offhost_icon_fetches.jsonl").read_text().splitlines()]
    assert counts["offhost_icon_distinct_urls"] == 1 and counts["offhost_icon_requests"] == 1
    assert counts["offhost_icon_cache_hits"] == len(log) - 1 >= 1
    assert "offhost_icon_duplicate_content" in counts


class _AnyIcon(dict):
    def __missing__(self, ip):
        return "http://cdn.example.test/shared.png"


def test_disabled_offhost_builds_no_service(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(fav, "OffhostService", lambda *a, **k: called.append(1))
    from tests.helpers import ProcessFetcherFactory, write_config
    from tests.test_config import _rewrite
    cfg = load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(processes=2)))
    pipeline.run(cfg, run_id="r1", executor=tools(), fetcher_factory=ProcessFetcherFactory(), skip_preflight=True, offline_preflight=True)
    assert called == []
