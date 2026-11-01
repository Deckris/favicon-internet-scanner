"""A network that stays full or held is given up on after a bounded wait; a Retry-After hold is short."""
from types import SimpleNamespace

from scanner.internet import favicon as fav
from scanner.internet import pacing
from scanner.internet.pacing import WAIT_BUSY, WAIT_OK, ContactLedger, IpPacer, SubnetLimiter


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


def test_retry_after_hold_is_capped_at_thirty_seconds_by_default():
    c = Clock()
    lim = SubnetLimiter(4, now=c)
    lim.observe("10.0.0.1", http_status=429, retry_after=900)
    c.t += 29
    assert not lim.try_acquire({"10.0.0": 1})
    c.t += 2
    assert lim.try_acquire({"10.0.0": 1})


def test_retry_after_hold_follows_the_configured_value():
    c = Clock()
    lim = pacing.limiter_for(SimpleNamespace(max_connections_per_subnet=4, retry_after_max_hold_seconds=5))
    lim._now = c
    lim.observe("10.0.0.1", http_status=503, retry_after=600)
    c.t += 6
    assert lim.try_acquire({"10.0.0": 1})


def _pacer(c, lim, max_wait, pause=5.0):
    return IpPacer(pause, now=c, sleep=c.sleep, limiter=lim, max_wait=max_wait)


def test_a_request_waits_at_most_the_max_wait_then_sends_nothing():
    c = Clock()
    lim = SubnetLimiter(1, now=c)
    assert lim.try_acquire({"10.0.0": 1})                 # the network is full
    pacer = _pacer(c, lim, max_wait=10)
    start = c.t
    assert pacer.admit("10.0.0.7") == WAIT_BUSY
    assert 10 <= c.t - start < 10.5
    assert lim.in_flight("10.0.0.7") == 1                 # nothing was taken
    assert pacer.wait("10.0.0.7") is False
    assert pacer._last == {}                              # the pause clock never started


def test_a_held_network_is_given_up_on_after_the_max_wait():
    c = Clock()
    lim = SubnetLimiter(4, now=c, max_hold=900)
    lim.observe("10.0.0.1", http_status=429, retry_after=900)
    pacer = _pacer(c, lim, max_wait=20)
    assert pacer.admit("10.0.0.9") == WAIT_BUSY
    assert lim.in_flight("10.0.0.9") == 0


def test_a_skipped_request_does_not_shorten_or_start_the_pause():
    c = Clock()
    lim = SubnetLimiter(1, now=c)
    pacer = _pacer(c, lim, max_wait=3, pause=5)
    assert pacer.admit("10.0.0.7") == WAIT_OK
    t0 = c.t
    pacer.done("10.0.0.7")
    assert lim.try_acquire({"10.0.0": 1})                 # another address now fills the network
    assert pacer.admit("10.0.0.8") == WAIT_BUSY
    lim.release({"10.0.0": 1})
    assert pacer.admit("10.0.0.7") == WAIT_OK
    assert c.t - t0 >= 5                                  # the first address kept its full pause
    pacer.done("10.0.0.7")
    assert "10.0.0.8" not in pacer._last                  # the skipped address was never contacted


def test_waiting_for_the_pause_is_not_counted_against_the_max_wait():
    c = Clock()
    lim = SubnetLimiter(2, now=c)
    pacer = _pacer(c, lim, max_wait=2, pause=30)
    assert pacer.admit("10.0.0.7") == WAIT_OK
    pacer.done("10.0.0.7")
    assert pacer.admit("10.0.0.7") == WAIT_OK
    assert c.t - 1000 >= 30


def _guarded(pacer):
    f = object.__new__(fav.GuardedFetcher)
    f.allowed_endpoints = frozenset({("10.0.0.7", 80)})
    f.pacer, f._active = pacer, None
    return f


def test_guarded_fetcher_returns_skipped_network_busy_without_a_request(monkeypatch):
    c = Clock()
    lim = SubnetLimiter(1, now=c)
    assert lim.try_acquire({"10.0.0": 1})
    f = _guarded(_pacer(c, lim, max_wait=5))
    sent = []
    monkeypatch.setattr(fav.WebFetcher, "_one_request", lambda *a, **k: sent.append(a))
    out = f._one_request(SimpleNamespace(scheme="http"), "10.0.0.7", 80, "10.0.0.7", None, 5, None)
    assert out.outcome == "skipped_network_busy" and not sent


def test_guarded_fetcher_still_reports_a_stop_as_the_kill_switch():
    c = Clock()
    f = _guarded(IpPacer(0, killed=lambda: True, now=c, sleep=c.sleep))
    out = f._one_request(SimpleNamespace(scheme="http"), "10.0.0.7", 80, "10.0.0.7", None, 5, None)
    assert out.outcome == "skipped_kill_switch"


class BusyFetcher:
    def __init__(self):
        self.calls = []

    def fetch(self, url, *, connect_ip, kind, context=""):
        self.calls.append(url)
        res = SimpleNamespace(outcome="skipped_network_busy", http_status=None, final_url=None, content_type=None)
        return res, None


def test_the_favicon_record_carries_the_busy_outcome():
    rec = fav.probe_identity(BusyFetcher(), scheme="http", ip="10.0.0.7", port=80, hostname=None, max_icons=2)
    assert rec["favicon_outcome"] == "skipped_network_busy"
    assert rec["document_outcome"] == "skipped_network_busy"


def test_a_busy_lookup_is_logged_and_not_repeated_in_the_stage():
    fetcher = BusyFetcher()
    jobs = [{"scheme": "http", "ip": "10.0.0.7", "port": 80, "hostname": None}]
    seen = []
    out = fav.run_favicon_stage(fetcher, jobs, workers=1, max_icons=2, on_record=seen.append)
    assert [r["favicon_outcome"] for r in out] == ["skipped_network_busy"] and len(fetcher.calls) == 1
    assert len(seen) == 1                                 # logged, so a resumed attempt reuses it


def test_the_ledger_gives_up_a_claim_after_the_max_wait():
    c = Clock()
    lim = SubnetLimiter(1, now=c)
    assert lim.try_acquire({"10.0.0": 1})
    ledger = ContactLedger(5, now=c, sleep=c.sleep, limiter=lim, max_wait=10)
    got = ledger.claim_some(["10.0.0.5", "10.0.0.6"])
    assert got == [] and 10 <= c.t - 1000 < 11
    assert ledger._busy == set() and ledger._last == {}


def test_a_batch_on_a_busy_network_is_deferred_once_then_skipped_and_the_rest_still_runs():
    c = Clock()
    lim = SubnetLimiter(1, now=c)
    assert lim.try_acquire({"10.9.9": 1})                 # held for the whole stage
    ledger = ContactLedger(0, now=c, sleep=c.sleep, limiter=lim, max_wait=10)
    items = [("10.9.9.1", 1), ("10.0.0.1", 2), ("10.0.1.1", 3)]
    ran, skipped = [], []

    def run(batch):
        ran.append([t[0] for t in batch])
        return [t[0] for t in batch]
    out = pacing.paced_batches(items, lambda t: t[0], ledger, run, batch_size=1, on_skip=skipped.append)
    assert sorted(ran) == [["10.0.0.1"], ["10.0.1.1"]]
    assert skipped == [[("10.9.9.1", 1)]]
    assert sorted(x for part in out for x in part) == ["10.0.0.1", "10.0.1.1"]
    assert c.t - 1000 >= 20                               # one wait before the deferral, one after
    assert lim.in_flight("10.9.9.1") == 1                 # only the outside holder remains
