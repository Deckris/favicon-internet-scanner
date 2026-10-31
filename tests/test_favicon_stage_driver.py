"""The favicon stage driver: bounded submission, stop handling and a lookup that never returns."""
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from scanner.internet import favicon as fav
from tests.helpers import FakeFetcher

ROOT = Path(__file__).resolve().parent.parent


def _jobs(n, per_ip=1):
    return [{"scheme": "http", "ip": f"10.0.{i // 250}.{i % 250 + 1}", "port": 80, "hostname": None if k == 0 else f"h{k}.example"}
            for i in range(n) for k in range(per_ip)]


class BlockingFetcher:
    """Serves every address normally except ``stuck_ip``, whose lookup never returns."""

    def __init__(self, stuck_ip=None, delay=0.0):
        self.stuck_ip, self.delay = stuck_ip, delay
        self.never = threading.Event()
        self.lock = threading.Lock()
        self.active = self.peak = 0
        self.inner = FakeFetcher()

    def fetch(self, url, *, connect_ip, kind, context=""):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            if connect_ip == self.stuck_ip:
                self.never.wait()
            if self.delay:
                time.sleep(self.delay)
            return self.inner.fetch(url, connect_ip=connect_ip, kind=kind)
        finally:
            with self.lock:
                self.active -= 1


def test_stuck_lookup_does_not_hold_the_stage_after_the_deadline():
    jobs = _jobs(40)
    stuck = jobs[7]["ip"]
    fetcher = BlockingFetcher(stuck_ip=stuck)
    deadline = time.monotonic() + 1.0
    seen = []
    t0 = time.monotonic()
    out = fav.run_favicon_stage(fetcher, jobs, workers=8, max_icons=2, killed=lambda: time.monotonic() > deadline,
                                on_record=seen.append, grace=0.5)
    assert time.monotonic() - t0 < 4.0
    assert [(r["ip"], r["port"]) for r in out] == [(j["ip"], j["port"]) for j in jobs]
    by_ip = {r["ip"]: r for r in out}
    assert by_ip[stuck]["favicon_outcome"] == "skipped_kill_switch"
    assert sum(r["favicon_outcome"] == "skipped_kill_switch" for r in out) == 1
    assert len(seen) == len(jobs) - 1


def test_unstarted_groups_are_recorded_as_skipped_once_killed():
    jobs = _jobs(60)
    fetcher = BlockingFetcher(delay=0.05)
    deadline = time.monotonic() + 0.3
    out = fav.run_favicon_stage(fetcher, jobs, workers=2, max_icons=2, killed=lambda: time.monotonic() > deadline)
    assert len(out) == len(jobs)
    outcomes = [r["favicon_outcome"] for r in out]
    assert "skipped_kill_switch" in outcomes and outcomes[0] != "skipped_kill_switch"
    assert all(set(r) >= {"ip", "port", "scheme", "hostname", "kind"} for r in out)


def test_kill_switch_stops_the_stage_quickly():
    jobs = _jobs(200)
    fetcher = BlockingFetcher(delay=0.2)
    flag = threading.Event()
    threading.Timer(0.3, flag.set).start()
    t0 = time.monotonic()
    out = fav.run_favicon_stage(fetcher, jobs, workers=4, max_icons=2, killed=flag.is_set)
    assert time.monotonic() - t0 < 1.5
    assert len(out) == len(jobs)
    assert sum(r["favicon_outcome"] == "skipped_kill_switch" for r in out) > 100


def test_keyboard_interrupt_propagates_promptly():
    jobs = _jobs(50)
    fetcher = BlockingFetcher(stuck_ip=jobs[0]["ip"])
    calls = {"n": 0}

    def killed():
        calls["n"] += 1
        if calls["n"] > 3:
            raise KeyboardInterrupt
        return False
    t0 = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        fav.run_favicon_stage(fetcher, jobs, workers=4, max_icons=2, killed=killed)
    assert time.monotonic() - t0 < 2.5


def test_no_more_lookups_run_than_there_are_workers():
    fetcher = BlockingFetcher(delay=0.01)
    out = fav.run_favicon_stage(fetcher, _jobs(300), workers=4, max_icons=2)
    assert len(out) == 300 and fetcher.peak <= 4


def test_in_flight_futures_never_exceed_twice_the_workers(monkeypatch):
    jobs = _jobs(120)
    fetcher = BlockingFetcher(delay=0.01)
    live, peak = set(), [0]
    lock = threading.Lock()
    original = fav._DaemonPool.submit

    def tracking(self, fn, *args):
        fut = original(self, fn, *args)
        with lock:
            live.add(fut)
            peak[0] = max(peak[0], sum(not f.done() for f in live))
        return fut
    monkeypatch.setattr(fav._DaemonPool, "submit", tracking)
    fav.run_favicon_stage(fetcher, jobs, workers=3, max_icons=2)
    assert peak[0] <= 6


def test_records_keep_the_job_order_and_reuse_earlier_ones():
    jobs = _jobs(30, per_ip=3)
    earlier = {(jobs[4]["ip"], 80, jobs[4]["hostname"]): {"ip": jobs[4]["ip"], "port": 80, "hostname": jobs[4]["hostname"],
                                                        "favicon_outcome": "image", "marker": True}}
    fetcher = BlockingFetcher(delay=0.001)
    out = fav.run_favicon_stage(fetcher, jobs, workers=8, max_icons=2, done=earlier)
    assert [(r["ip"], r["hostname"]) for r in out] == [(j["ip"], j["hostname"]) for j in jobs]
    assert out[4].get("marker") is True


def test_fingerprint_cache_returns_the_same_result_for_the_same_bytes():
    from tests.helpers import make_png
    calls = []

    def compute(data):
        calls.append(data)
        return object()
    cache = fav.FingerprintCache(capacity=2)
    original = fav.compute_fingerprint
    fav.compute_fingerprint = compute
    try:
        a = cache(make_png())
        assert cache(make_png()) is a and len(calls) == 1 and cache.hits == 1
        cache(b"one")
        cache(b"two")           # evicts the png (capacity 2)
        cache(make_png())
        assert len(calls) == 4
    finally:
        fav.compute_fingerprint = original


def test_process_exits_with_a_lookup_still_stuck():
    script = textwrap.dedent(f"""
        import sys, threading, time
        sys.path.insert(0, {str(ROOT)!r})
        from scanner.internet import favicon as fav
        import importlib.util
        spec = importlib.util.spec_from_file_location("helpers_for_stage", {str(ROOT / "tests" / "helpers.py")!r})
        helpers = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helpers)
        FakeFetcher = helpers.FakeFetcher

        class Stuck:
            def fetch(self, url, *, connect_ip, kind, context=""):
                if connect_ip == "10.0.0.2":
                    threading.Event().wait()
                return FakeFetcher().fetch(url, connect_ip=connect_ip, kind=kind)
        jobs = [{{"scheme": "http", "ip": f"10.0.0.{{i}}", "port": 80, "hostname": None}} for i in range(1, 6)]
        end = time.monotonic() + 0.8
        out = fav.run_favicon_stage(Stuck(), jobs, workers=70, max_icons=2, killed=lambda: time.monotonic() > end, grace=0.3)
        print(sorted(r["favicon_outcome"] for r in out))
    """)
    t0 = time.monotonic()
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30, cwd=ROOT)
    assert proc.returncode == 0, proc.stderr
    assert "skipped_kill_switch" in proc.stdout
    assert time.monotonic() - t0 < 20
