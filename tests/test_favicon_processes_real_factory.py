"""The favicon stage over several processes with the real FetcherFactory, against local servers (no Internet traffic).

The other process tests use fake factories; these build the fetcher the way a real run does, from the configuration.
"""
from __future__ import annotations

import http.server
import io
import json
import threading

import pytest

from scanner.internet import favicon as fav
from scanner.internet import icon_store, pipeline
from scanner.internet.config import load_config
from scanner.safety import TargetPolicy
from tests.helpers import FakeFetcher, ProcessFetcherFactory, write_config
from tests.test_config import _rewrite
from tests.test_pipeline import tools

ADDRESSES = ("127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4")


class LoopbackFactory(fav.FetcherFactory):
    """The real factory, with a policy that approves the loopback addresses the local servers listen on."""

    def __call__(self, pacer, owned=None, killed=None):
        real = fav.fetch_policy
        fav.fetch_policy = lambda cfg, ips: TargetPolicy.for_tests(["127.0.0.0/8"])
        try:
            return super().__call__(pacer, owned, killed)
        finally:
            fav.fetch_policy = real


def png(shade: int) -> bytes:
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), (shade, 30, 30)).save(buf, format="PNG")
    return buf.getvalue()


def serve(address: str, shade: int):
    icon = png(shade)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/fav.png":
                body, kind = icon, "image/png"
            else:
                body, kind = b'<html><head><link rel="icon" href="/fav.png"></head></html>', "text/html"
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer((address, 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def servers():
    started = []
    try:
        for i, address in enumerate(ADDRESSES):
            started.append(serve(address, 40 + 50 * i))
    except OSError:
        pytest.skip("the loopback addresses 127.0.0.2-4 cannot be bound here")
    yield started
    for s in started:
        s.shutdown()
        s.server_close()


def jobs_for(servers) -> list[dict]:
    jobs = []
    for address, s in zip(ADDRESSES, servers):
        port = s.server_address[1]
        jobs.append({"scheme": "http", "ip": address, "port": port, "hostname": None})
        jobs.append({"scheme": "http", "ip": address, "port": port, "hostname": f"site-{port}.example.com"})
    return jobs


def stage(cfg, jobs, processes, store_dir):
    """Run the stage as the pipeline does and return (logged, sunk, icon store)."""
    endpoints = {(j["ip"], j["port"]) for j in jobs}
    ips = sorted({j["ip"] for j in jobs})
    logged, sunk = [], {}
    icons = icon_store.IconStore(store_dir)
    common = dict(workers=8, max_icons=2, icon_store=icons, on_record=logged.append, record_sink=lambda i, rec: sunk.__setitem__(i, rec))
    if processes > 1:
        factory = LoopbackFactory(cfg, ips, endpoints, max_active_requests=fav.split_cap(cfg.favicon.max_active_requests, processes))
        fav.run_favicon_stage_processes(factory, jobs, processes=processes, pace=0.0, **common)
    else:
        fav.run_favicon_stage(LoopbackFactory(cfg, ips, endpoints)(None), jobs, **common)
    return logged, sunk, icons


def digest(records):
    keys = ("ip", "port", "hostname", "favicon_outcome", "favicon_sha256", "favicon_url", "favicon_bytes", "document_outcome")
    return sorted(json.dumps({k: r.get(k) for k in keys}, sort_keys=True) for r in records)


def test_two_processes_with_the_real_factory_give_the_records_of_one(tmp_path, servers):
    cfg = load_config(write_config(tmp_path))
    jobs = jobs_for(servers)
    one_log, one_sink, one_icons = stage(cfg, jobs, 1, tmp_path / "one")
    two_log, two_sink, two_icons = stage(cfg, jobs, 2, tmp_path / "two")

    assert len(one_sink) == len(two_sink) == len(jobs)
    assert len(one_log) == len(two_log) == len(jobs)
    assert {r["favicon_outcome"] for r in one_sink.values()} == {"image"}
    assert digest(one_sink.values()) == digest(two_sink.values())
    assert digest(one_log) == digest(two_log)
    sha = lambda records: {r["favicon_sha256"] for r in records}
    assert len(sha(one_sink.values())) == len(ADDRESSES)
    assert sha(one_sink.values()) == sha(two_sink.values()) == sha(two_log)
    assert len(one_icons) == len(two_icons) == len(ADDRESSES)


def test_a_failing_worker_process_is_reported_not_swallowed():
    failures = []
    sunk = {}
    jobs = [{"scheme": "http", "ip": f"198.51.100.{i}", "port": 80, "hostname": None} for i in range(1, 7)]
    fav.run_favicon_stage_processes(ProcessFetcherFactory(broken=True), jobs, processes=2, workers=4, pace=0.0, max_icons=2,
                                    record_sink=lambda i, rec: sunk.__setitem__(i, rec), on_failure=lambda why, lost: failures.append((why, lost)))
    assert len(sunk) == len(jobs) and {r["favicon_outcome"] for r in sunk.values()} == {"error"}
    assert sum(lost for _, lost in failures) == len(jobs)
    assert all("cannot build a fetcher" in why for why, _ in failures)


def test_a_stage_whose_workers_all_fail_is_not_a_complete_run(tmp_path):
    cfg = load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(processes=2)))
    run_dir = pipeline.run(cfg, run_id="r", executor=tools(), fetcher_factory=ProcessFetcherFactory(broken=True),
                           skip_preflight=True, offline_preflight=True)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["complete"] is False
    assert "cannot build a fetcher" in manifest["stage_errors"]["favicon_workers"]


def test_fewer_stored_favicon_records_than_jobs_is_a_stage_error(tmp_path, monkeypatch):
    real = fav.run_favicon_stage

    def lossy(fetcher, jobs, **kw):
        sink = kw["record_sink"]
        return real(fetcher, jobs, **{**kw, "record_sink": lambda i, rec: sink(i, rec) if i else None})
    monkeypatch.setattr(fav, "run_favicon_stage", lossy)
    cfg = load_config(write_config(tmp_path))
    run_dir = pipeline.run(cfg, run_id="r", executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["complete"] is False
    assert "favicon_records_missing" in manifest["stage_errors"]
