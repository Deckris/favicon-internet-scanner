"""Per-address pacing: slot spacing, rounds without repeated addresses, gaps between steps, stop conditions."""
from types import SimpleNamespace

from scanner.internet import pacing
from scanner.internet.favicon import GuardedFetcher


class Clock:
    def __init__(self):
        self.t = 100.0
        self.sleeps = []

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.t += seconds


def test_pacer_spaces_requests_to_one_address_and_leaves_others_alone():
    c = Clock()
    p = pacing.IpPacer(15, now=c.now, sleep=c.sleep)
    starts = []
    for ip in ("1.1.1.1", "1.1.1.1", "2.2.2.2", "1.1.1.1"):
        assert p.wait(ip)
        starts.append((ip, c.t))
    first = [t for ip, t in starts if ip == "1.1.1.1"]
    assert first[1] - first[0] >= 15 and first[2] - first[1] >= 15
    assert starts[2][1] - 100.0 < 31                       # the other address was not held back by the first


def test_pacer_disabled_and_stopped():
    c = Clock()
    off = pacing.IpPacer(0, now=c.now, sleep=c.sleep)
    assert off.wait("1.1.1.1") and off.wait("1.1.1.1") and c.sleeps == []
    stopped = pacing.IpPacer(15, killed=lambda: True, now=c.now, sleep=c.sleep)
    assert stopped.wait("1.1.1.1")                          # first request has no wait
    assert stopped.wait("1.1.1.1") is False                 # second would have to wait: refuses once stopped


def test_split_rounds_never_repeats_an_address_within_a_round():
    items = [("a", 80), ("a", 443), ("b", 80), ("a", 8080), ("c", 80), ("b", 443)]
    rounds = pacing.split_rounds(items, lambda t: t[0])
    assert [len(r) for r in rounds] == [3, 2, 1]
    for r in rounds:
        assert len({ip for ip, _ in r}) == len(r)
    assert sorted(x for r in rounds for x in r) == sorted(items)


def test_gap_waits_only_after_a_mark():
    c = Clock()
    g = pacing.Gap(15, now=c.now, sleep=c.sleep)
    assert g.wait() and c.sleeps == []
    g.mark()
    c.t += 4
    assert g.wait() and 10.9 < sum(c.sleeps) < 11.1


def test_paced_rounds_keep_the_minimum_between_rounds_and_stop_on_kill():
    c = Clock()
    g = pacing.Gap(15, now=c.now, sleep=c.sleep)
    starts = []

    def run(batch):
        starts.append(c.t)
        c.t += 2                                            # a round takes 2 s
        return batch
    out = pacing.paced_rounds([("a", 1), ("a", 2), ("a", 3)], lambda t: t[0], g, run)
    assert len(out) == 3 and all(b - a >= 17 for a, b in zip(starts, starts[1:]))   # end of one round + 15 s gap
    stop = {"now": False}
    g2 = pacing.Gap(15, killed=lambda: stop["now"], now=c.now, sleep=lambda s: (stop.update(now=True), c.sleep(s)))
    assert len(pacing.paced_rounds([("a", 1), ("a", 2), ("a", 3)], lambda t: t[0], g2, run)) == 1       # the stop fired during the wait, so round two never started


def test_fetcher_asks_the_pacer_before_connecting_and_skips_when_stopped():
    seen = []

    class Pacer:
        def __init__(self, ok):
            self.ok = ok

        def wait(self, ip):
            seen.append(ip)
            return self.ok
    f = object.__new__(GuardedFetcher)
    f.allowed_endpoints = frozenset({("1.1.1.1", 80)})
    f.pacer = Pacer(False)
    parts = SimpleNamespace(scheme="http")
    out = f._one_request(parts, "h", 80, "1.1.1.1", None, None, None)
    assert out.outcome == "skipped_kill_switch" and seen == ["1.1.1.1"]
    refused = f._one_request(parts, "h", 22, "1.1.1.1", None, None, None)      # not an approved endpoint: no wait at all
    assert refused.outcome == "policy_refused" and seen == ["1.1.1.1"]


def test_zmap_port_runs_are_spaced_by_the_minimum_interval(tmp_path):
    import time

    from scanner.internet import pipeline
    from scanner.internet.config import load_config
    from tests.helpers import FakeFetcher, write_config
    from tests.test_pipeline import tools

    cfg = load_config(write_config(tmp_path))
    cfg.measurement.min_seconds_between_probes_per_ip = 0.4
    ft, starts = tools(), []

    def executor(command, **kw):
        if command[0] == "zmap" and "--dryrun" not in command:
            starts.append(time.monotonic())
        return ft(command, **kw)
    pipeline.run(cfg, run_id="t1", executor=executor, fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)
    assert len(starts) == len(cfg.measurement.ports) > 1
    assert all(b - a >= 0.4 for a, b in zip(starts, starts[1:]))
