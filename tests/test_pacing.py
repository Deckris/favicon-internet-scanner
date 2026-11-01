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


class LateClock(Clock):
    """The sleep that reaches the deadline overshoots by ``late`` seconds once, as a busy CPU wakes a thread late."""

    def __init__(self, late):
        super().__init__()
        self.late = list(late)

    def sleep(self, seconds):
        late = self.late.pop(0) if self.late and len(self.sleeps) == 9 else 0.0     # the tenth one-second slice
        super().sleep(seconds + late)


def test_a_late_wake_up_pushes_the_next_request_back_instead_of_shortening_the_gap():
    c = LateClock([3.0])
    p = pacing.IpPacer(10, now=c.now, sleep=c.sleep, poll=100)
    released = []
    for _ in range(3):
        assert p.wait("1.1.1.1")
        released.append(c.t)
        c.t += 0.5                                          # the request itself
    gaps = [b - a for a, b in zip(released, released[1:])]
    assert gaps[0] >= 13 - 1e-9                             # woke 3 s late
    assert min(gaps) >= 10 - 1e-9, gaps                     # the next one still waits the full interval


def test_pacer_disabled_and_stopped():
    c = Clock()
    off = pacing.IpPacer(0, now=c.now, sleep=c.sleep)
    assert off.wait("1.1.1.1") and off.wait("1.1.1.1") and c.sleeps == []
    stopped = pacing.IpPacer(15, killed=lambda: True, now=c.now, sleep=c.sleep)
    assert stopped.wait("1.1.1.1") is False                 # once stopped nothing is sent, not even a first request
    assert stopped.wait("1.1.1.1") is False


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


def test_ledger_holds_each_address_back_from_its_own_last_contact_only():
    c = Clock()
    led = pacing.ContactLedger(15, now=c.now, sleep=c.sleep)
    assert led.claim(["a"]) and c.sleeps == []
    c.t += 2
    led.release(["a"])                                      # contact with a ended at 102
    assert led.claim(["b"]) and c.t == 102                  # another address is not held back
    led.release(["b"])
    assert led.claim(["a"]) and 116.9 < c.t < 117.1         # a waits until 15 s after its contact ended
    led.release(["a"])
    led.mark_all()                                          # a sweep touching everyone ended now
    t_sweep = c.t
    assert led.claim(["c"]) and c.t >= t_sweep + 15


def test_ledger_stops_on_kill_and_respects_an_extra_check():
    c = Clock()
    led = pacing.ContactLedger(15, killed=lambda: c.t > 110, now=c.now, sleep=c.sleep)
    led.mark_all()
    assert led.claim(["a"]) is False                        # the stop fired during the wait
    c2 = Clock()
    led2 = pacing.ContactLedger(0, now=c2.now, sleep=c2.sleep)
    assert led2.claim(["a"], extra=lambda now: now >= 105) and c2.t >= 105


def test_paced_batches_keep_composition_and_order_and_match_rounds_with_one_worker():
    items = [("a", 1), ("b", 1), ("a", 2), ("c", 1), ("b", 2), ("a", 3)]
    c = Clock()
    seen = []

    def run(batch):
        seen.append(list(batch))
        c.t += 2
        return batch
    out = pacing.paced_batches(items, lambda t: t[0], pacing.ContactLedger(15, now=c.now, sleep=c.sleep), run, batch_size=2)
    assert out == seen == [[("a", 1), ("b", 1)], [("c", 1)], [("a", 2), ("b", 2)], [("a", 3)]]


def test_paced_batches_in_parallel_never_contact_an_address_within_the_pause():
    import threading
    import time
    pace = 0.15
    items = [(ip, port) for port in (1, 2, 3) for ip in ("a", "b", "c", "d", "e")]
    log, lock = [], threading.Lock()

    def run(batch):
        start = time.monotonic()
        time.sleep(0.03)
        with lock:
            log.extend((ip, start, time.monotonic()) for ip, _ in batch)
        return batch
    out = pacing.paced_batches(items, lambda t: t[0], pacing.ContactLedger(pace), run, batch_size=2, workers=4)
    assert sorted(x for b in out for x in b) == sorted(items)
    for ip in "abcde":
        spans = sorted((s, e) for i, s, e in log if i == ip)
        assert all(s2 - e1 >= pace - 0.005 for (_s1, e1), (s2, _e2) in zip(spans, spans[1:])), (ip, spans)


def test_paced_batches_stop_starting_batches_after_a_kill_or_an_error():
    stop = {"now": False}

    def run(batch):
        stop["now"] = True
        return batch
    led = pacing.ContactLedger(0, killed=lambda: stop["now"])
    assert len(pacing.paced_batches([("a", 1), ("b", 1), ("c", 1)], lambda t: t[0], led, run, batch_size=1)) == 1
    calls = []

    def boom(batch):
        calls.append(batch)
        raise RuntimeError("tool crashed")
    import pytest
    with pytest.raises(RuntimeError):
        pacing.paced_batches([("a", 1), ("b", 1), ("c", 1)], lambda t: t[0], pacing.ContactLedger(0), boom, batch_size=1, workers=1)
    assert len(calls) == 1


class CountingEvent:
    """A stop event on a fake clock that records every wait, so wake-ups can be counted."""

    def __init__(self, clock):
        self.clock = clock
        self.waits = []

    def is_set(self):
        return False

    def wait(self, seconds):
        self.waits.append(seconds)
        self.clock.t += seconds
        return False


def test_a_long_wait_is_one_sleep_to_the_deadline_with_a_stop_event():
    c = Clock()
    event = CountingEvent(c)
    p = pacing.IpPacer(30, now=c.now, stop_event=event, poll=100)
    assert p.wait("1.1.1.1")
    assert p.wait("1.1.1.1")
    assert c.t - 100.0 == 30
    assert len(event.waits) <= 30 and max(event.waits) <= 1.0     # looks at the kill switch about once a second
    quiet = pacing.IpPacer(30, now=c.now, stop_event=CountingEvent(c), poll=1.0)
    assert quiet.wait("2.2.2.2")


def test_waiters_do_not_wake_between_the_deadline_and_the_kill_switch_checks():
    c = Clock()
    p = pacing.IpPacer(60, now=c.now, sleep=c.sleep)
    assert p.wait("1.1.1.1") and p.wait("1.1.1.1")
    assert len(c.sleeps) == 60                                     # 1 s checks, no 0.25 s polling
    assert min(c.sleeps) == 1.0


def test_gap_is_kept_between_many_waiters_on_one_address_and_they_are_served_in_order():
    import threading
    import time as _time
    pacer = pacing.IpPacer(0.05, poll=0.5)
    released, lock = [], threading.Lock()
    started = threading.Barrier(7)

    def worker(i):
        started.wait()
        _time.sleep(0.004 * i)                                     # arrival order 0..5
        assert pacer.wait("9.9.9.9")
        with lock:
            released.append((i, _time.monotonic()))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    [t.start() for t in threads]
    started.wait()
    [t.join(10) for t in threads]
    assert [i for i, _ in released] == [0, 1, 2, 3, 4, 5]
    times = [t for _, t in released]
    assert min(b - a for a, b in zip(times, times[1:])) >= 0.05 - 0.003


def test_a_stop_wakes_a_waiter_at_once():
    import threading
    import time as _time
    event = threading.Event()
    pacer = pacing.IpPacer(60, stop_event=event, poll=1.0)
    assert pacer.wait("1.1.1.1")
    out = []
    t = threading.Thread(target=lambda: out.append(pacer.wait("1.1.1.1")))
    t.start()
    _time.sleep(0.05)
    started = _time.monotonic()
    event.set()
    t.join(5)
    assert out == [False] and _time.monotonic() - started < 0.5


def test_a_burned_reservation_does_not_shorten_the_gap_for_the_next_caller():
    c = Clock()
    stop = [False]
    p = pacing.IpPacer(10, killed=lambda: stop[0], now=c.now, sleep=c.sleep)
    assert p.wait("1.1.1.1")
    def sleep_then_stop(seconds):
        c.sleep(seconds)
        stop[0] = True
    p._sleep = sleep_then_stop
    assert not p.wait("1.1.1.1")                                   # reserved 110, then stopped
    stop[0] = False
    p._sleep = c.sleep
    assert p.wait("1.1.1.1")
    assert c.t >= 120 - 1e-9                                       # behind the burned slot, never inside the pause
