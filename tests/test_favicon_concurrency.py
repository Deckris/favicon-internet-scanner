"""Many addresses in flight in the favicon stage: the per-address pause holds, live requests stay bounded."""
from __future__ import annotations

import threading
import time

import pytest

from scanner.internet import favicon as fav
from scanner.internet import pacing
from scanner.internet.config import ConfigError, load_config
from scanner.web_fetch import WebFetcher
from tests.helpers import FakeFetcher, write_config
from tests.test_config import _rewrite


class Clocked(FakeFetcher):
    """Records when each address was contacted and how many addresses are being worked on at once."""

    def __init__(self, pacer) -> None:
        super().__init__()
        self.pacer, self.lock = pacer, threading.Lock()
        self.times: dict[str, list[float]] = {}
        self.working = self.peak = 0

    def fetch(self, url, *, connect_ip, kind, context=""):
        with self.lock:
            self.working += 1
            self.peak = max(self.peak, self.working)
        try:
            assert self.pacer.wait(connect_ip)
            with self.lock:
                self.times.setdefault(connect_ip, []).append(time.monotonic())
            return super().fetch(url, connect_ip=connect_ip, kind=kind, context=context)
        finally:
            with self.lock:
                self.working -= 1


def test_gap_per_address_holds_with_many_addresses_in_flight():
    interval = 0.3
    pacer = pacing.IpPacer(interval, poll=0.05)
    fetcher = Clocked(pacer)
    jobs = [{"scheme": "http", "ip": f"198.51.100.{i}", "port": 80, "hostname": None} for i in range(1, 251)]
    jobs += [{"scheme": "https", "ip": jobs[i]["ip"], "port": 443, "hostname": None} for i in range(0, 250, 3)]
    out = fav.run_favicon_stage(fetcher, jobs, workers=300, max_icons=2)
    assert [(r["ip"], r["port"]) for r in out] == [(j["ip"], j["port"]) for j in jobs], "output order is preserved"
    gaps = [b - a for stamps in fetcher.times.values() for a, b in zip(stamps, stamps[1:])]
    assert gaps and min(gaps) >= interval - 0.02, f"two requests to one address {min(gaps):.3f} s apart"


def test_more_addresses_than_the_old_worker_limit_are_in_flight_at_once():
    count = 600
    barrier = threading.Barrier(count, timeout=120)       # releases only if every address is being worked on at the same time

    class AllTogether(FakeFetcher):
        def fetch(self, url, *, connect_ip, kind, context=""):
            if kind == "document":
                barrier.wait()
            return super().fetch(url, connect_ip=connect_ip, kind=kind, context=context)

    jobs = [{"scheme": "http", "ip": f"198.{51 + i // 250}.100.{i % 250 + 1}", "port": 80, "hostname": None} for i in range(count)]
    out = fav.run_favicon_stage(AllTogether(), jobs, workers=count, max_icons=1)
    assert len(out) == count and all(r["favicon_outcome"] == "image" for r in out)


def test_worker_stack_size_is_restored():
    before = threading.stack_size()
    fetcher = Clocked(pacing.IpPacer(0))
    fav.run_favicon_stage(fetcher, [{"scheme": "http", "ip": f"198.51.100.{i}", "port": 80, "hostname": None} for i in range(1, 200)],
                          workers=128, max_icons=1)
    assert threading.stack_size() == before


def test_longest_chains_are_started_first():
    order: list[str] = []
    lock = threading.Lock()

    class Recorder(FakeFetcher):
        def fetch(self, url, *, connect_ip, kind, context=""):
            with lock:
                if connect_ip not in order:
                    order.append(connect_ip)
            return super().fetch(url, connect_ip=connect_ip, kind=kind, context=context)

    jobs = [{"scheme": "http", "ip": "198.51.100.1", "port": 80, "hostname": None},
            {"scheme": "http", "ip": "198.51.100.2", "port": 80, "hostname": None},
            {"scheme": "http", "ip": "198.51.100.2", "port": 8080, "hostname": None},
            {"scheme": "http", "ip": "198.51.100.2", "port": 8090, "hostname": None}]
    fav.run_favicon_stage(Recorder(), jobs, workers=1, max_icons=1)
    assert order[0] == "198.51.100.2"


def test_live_requests_never_exceed_the_cap(monkeypatch):
    live = peak = 0
    lock = threading.Lock()

    def slow(self, parts, hostname, port, connect_ip, limits, timeout, deadline):
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        time.sleep(0.02)
        with lock:
            live -= 1
        return fav.GuardedFetcher._outcome("ok", connect_ip, hostname, port, parts.scheme)

    monkeypatch.setattr(WebFetcher, "_one_request", slow)
    guarded = object.__new__(fav.GuardedFetcher)
    guarded.allowed_endpoints = frozenset((f"198.51.100.{i}", 80) for i in range(1, 41))
    guarded.pacer = None
    guarded._active = threading.BoundedSemaphore(3)

    class Parts:
        scheme = "http"

    def call(i: int) -> None:
        guarded._one_request(Parts, "h", 80, f"198.51.100.{i}", None, None, None)

    threads = [threading.Thread(target=call, args=(i,)) for i in range(1, 41)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert 1 <= peak <= 3


def test_pacer_poll_interval_is_used_for_long_waits():
    clock = {"t": 0.0}
    naps: list[float] = []

    def sleep(seconds: float) -> None:
        naps.append(seconds)
        clock["t"] += seconds

    pacer = pacing.IpPacer(15, now=lambda: clock["t"], sleep=sleep, poll=2.0)
    assert pacer.wait("203.0.113.5") and not naps
    assert pacer.wait("203.0.113.5")
    assert naps and max(naps) == 2.0 and sum(naps) == pytest.approx(15)


def test_config_bounds(tmp_path):
    assert load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(workers=4096))).favicon.workers == 4096
    with pytest.raises(ConfigError, match="favicon.workers"):
        load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(workers=8193)))
    cfg = load_config(write_config(tmp_path))
    assert (cfg.favicon.icon_selection, cfg.favicon.fallback, cfg.favicon.max_active_requests) == ("first_image", "always_if_no_image", 512)
    with pytest.raises(ConfigError, match="favicon.icon_selection"):
        load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(icon_selection="best")))
    with pytest.raises(ConfigError, match="favicon.fallback"):
        load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(fallback="never")))
    with pytest.raises(ConfigError, match="favicon.max_active_requests"):
        load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(max_active_requests=0)))


def test_fingerprint_cache_returns_the_same_result_and_decodes_each_icon_once(monkeypatch):
    from tests.helpers import make_png
    calls = []
    real = fav.compute_fingerprint

    def counting(data):
        calls.append(len(data))
        return real(data)

    monkeypatch.setattr(fav, "compute_fingerprint", counting)
    cache = fav.FingerprintCache(capacity=2)
    png = make_png()
    first, second = cache(png), cache(png)
    assert first is second and first.as_dict() == real(png).as_dict() and len(calls) == 1
    assert (cache.hits, cache.misses) == (1, 1)
    cache(b"not an image"), cache(b"other bytes"), cache(png)       # capacity 2: the oldest entry was evicted
    assert len(calls) == 4
