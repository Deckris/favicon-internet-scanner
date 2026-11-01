"""Simultaneous connections per /24 (IPv4) and /48 (IPv6), shared by the ledger, the pacer and the batch splitter."""
import threading
import time

import pytest

from scanner.internet import pacing
from scanner.internet.pacing import ContactLedger, IpPacer, SubnetLimiter, network_key


@pytest.fixture
def strict():
    previous = pacing.set_strict(True)
    pacing.reset_violations()
    yield
    pacing.set_strict(previous)
    pacing.reset_violations()


def test_network_keys():
    assert network_key("192.0.2.77") == network_key("192.0.2.1") != network_key("192.0.3.1")
    assert network_key("2001:db8:1:2::1") == network_key("2001:db8:1:2:ffff::9") == network_key("2001:db8:1:2:3:4:5:6")
    assert network_key("2001:db8:2:2::1") != network_key("2001:db8:1:2::1")
    assert network_key("2001:db8:1:2::1") != network_key("192.0.2.1")


def test_cap_is_enforced_and_released():
    lim = SubnetLimiter(3)
    key = {"192.0.2": 1}
    assert [lim.try_acquire(key) for _ in range(4)] == [True, True, True, False]
    assert lim.try_acquire({"198.51.100": 1})
    lim.release(key)
    assert lim.try_acquire(key)


def test_acquire_is_all_or_nothing():
    lim = SubnetLimiter(1)
    assert lim.try_acquire({"10.0.0": 1})
    assert not lim.try_acquire({"10.0.1": 1, "10.0.0": 1})
    assert lim.in_flight("10.0.1.1") == 0          # the free network was not left taken by the refused request


def test_a_request_above_the_limit_is_never_admitted_even_when_the_network_is_idle():
    lim = SubnetLimiter(4)
    assert not lim.try_acquire({"a": 6})
    assert lim.try_acquire({"a": 4})
    assert not lim.try_acquire({"a": 1})


def test_counters_vanish_when_idle():
    lim = SubnetLimiter(4)
    for i in range(5000):
        k = {f"net{i}": 1}
        assert lim.try_acquire(k)
        lim.release(k)
    assert lim.tracked() == (0, 0)


def test_blocking_acquire_waits_instead_of_dropping():
    lim = SubnetLimiter(1)
    assert lim.try_acquire({"a": 1})
    got = []
    t = threading.Thread(target=lambda: got.append(lim.acquire({"a": 1}, poll=0.01)))
    t.start()
    time.sleep(0.05)
    assert not got
    lim.release({"a": 1})
    t.join(2)
    assert got == [True]


def test_blocking_acquire_gives_up_on_a_stop():
    lim = SubnetLimiter(1)
    lim.try_acquire({"a": 1})
    stop = threading.Event()
    threading.Timer(0.05, stop.set).start()
    assert lim.acquire({"a": 1}, stop_event=stop, poll=0.01) is False


def test_split_by_network_caps_every_group():
    items = [f"10.0.0.{i}" for i in range(10)] + ["10.0.1.1", "10.0.1.2"]
    groups = pacing.split_by_network(items, lambda x: x, network_key, 4)
    assert [len(g) for g in groups] == [6, 4, 2]
    for g in groups:
        assert sum(1 for x in g if x.startswith("10.0.0.")) <= 4
    assert sorted(x for g in groups for x in g) == sorted(items)


def test_paced_batches_never_exceed_the_cap_with_parallel_workers(strict):
    limiter = SubnetLimiter(2)
    ledger = ContactLedger(0, limiter=limiter)
    items = [f"10.0.{n}.{i}" for n in range(3) for i in range(1, 11)]
    peak = {}
    lock = threading.Lock()

    def run(batch):
        with lock:
            for ip in batch:
                peak[network_key(ip)] = max(peak.get(network_key(ip), 0), limiter.in_flight(ip))
        time.sleep(0.005)
        return batch

    out = pacing.paced_batches(items, lambda ip: ip, ledger, run, batch_size=6, workers=4)
    assert sorted(ip for b in out for ip in b) == sorted(items)       # nothing dropped
    assert max(peak.values()) <= 2
    assert limiter.tracked() == (0, 0)
    assert pacing.violations()[0] == 0


def test_ledger_and_limiter_do_not_deadlock_under_contention(strict):
    limiter = SubnetLimiter(1)
    ledger = ContactLedger(0, limiter=limiter)
    items = [f"10.0.0.{i}" for i in range(1, 41)]
    done = []
    t = threading.Thread(target=lambda: done.append(
        pacing.paced_batches(items, lambda ip: ip, ledger, lambda b: b, batch_size=3, workers=8)))
    t.start()
    t.join(20)
    assert not t.is_alive() and sum(len(b) for b in done[0]) == 40


def test_ledger_observe_backs_off_through_the_limiter():
    class R:
        ip, zgrab_status = "10.0.0.1", "connection-timeout"

    limiter = SubnetLimiter(4, settle=0)
    ledger = ContactLedger(0, limiter=limiter)
    ledger.observe([R(), R(), R()])
    assert limiter.limit_for("10.0.0.2") == 2


def test_pacer_takes_and_returns_a_network_slot():
    limiter = SubnetLimiter(1)
    pacer = IpPacer(0, limiter=limiter, poll=0.01)
    assert pacer.wait("10.0.0.1")
    assert limiter.in_flight("10.0.0.2") == 1
    got = []
    t = threading.Thread(target=lambda: got.append(pacer.wait("10.0.0.2")))
    t.start()
    time.sleep(0.05)
    assert not got                                    # another address of the same /24 waits for the slot
    pacer.done("10.0.0.1")
    t.join(2)
    assert got == [True]
    pacer.done("10.0.0.2")
    assert limiter.tracked() == (0, 0)


def test_pacer_done_reports_throttling_with_retry_after():
    class Reply:
        outcome, http_status, retry_after_seconds = "http_status", 429, 5.0

    limiter = SubnetLimiter(4)
    pacer = IpPacer(0, limiter=limiter)
    assert pacer.wait("10.0.0.1")
    pacer.done("10.0.0.1", Reply())
    assert limiter.limit_for("10.0.0.1") == 2
    assert not limiter.try_acquire({"10.0.0": 1})      # held for the Retry-After


def test_pacer_still_spaces_one_address_with_a_limiter():
    t = [100.0]
    limiter = SubnetLimiter(4)
    pacer = IpPacer(5, now=lambda: t[0], sleep=lambda s: t.__setitem__(0, t[0] + s), limiter=limiter)
    assert pacer.wait("10.0.0.1")
    pacer.done("10.0.0.1")
    assert pacer.wait("10.0.0.1")
    assert t[0] - 100.0 >= 5


def test_strict_mode_raises_on_a_claim_inside_the_pause(strict):
    t = [100.0]
    ledger = ContactLedger(5, now=lambda: t[0])
    ledger._last["10.0.0.1"] = 98.0
    ledger._due = lambda ip: float("-inf")           # bypass the wait to stand in for a broken caller
    with pytest.raises(pacing.PacingViolation):
        ledger.claim(["10.0.0.1"])


def test_pacer_never_grants_inside_the_pause_in_strict_mode(strict):
    t = [100.0]
    pacer = IpPacer(5, now=lambda: t[0], sleep=lambda s: t.__setitem__(0, t[0] + s))
    for _ in range(4):
        assert pacer.wait("10.0.0.1")
    assert pacing.violations()[0] == 0


def test_violations_are_counted_not_raised_when_not_strict():
    previous = pacing.set_strict(False)
    pacing.reset_violations()
    try:
        SubnetLimiter(2).release({"a": 1})
        count, messages = pacing.violations()
        assert count == 1 and "released more" in messages[0]
    finally:
        pacing.set_strict(previous)
        pacing.reset_violations()


def test_subnet_cap_config_default_and_range(tmp_path):
    import yaml
    from scanner.internet.config import ConfigError, load_config
    from tests.helpers import write_config

    p = write_config(tmp_path)
    assert load_config(p).measurement.max_connections_per_subnet == 4
    d = yaml.safe_load(p.read_text())
    for bad in (0, 65):
        d["measurement"]["max_connections_per_subnet"] = bad
        p.write_text(yaml.safe_dump(d))
        with pytest.raises(ConfigError, match="max_connections_per_subnet"):
            load_config(p)
    d["measurement"]["max_connections_per_subnet"] = 2
    p.write_text(yaml.safe_dump(d))
    assert load_config(p).measurement.max_connections_per_subnet == 2


class Tick:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def test_an_idle_backed_off_network_is_admitted_by_its_current_limit_not_the_cap():
    c = Tick()
    lim = SubnetLimiter(4, now=c, recover_after=10_000)
    lim.observe("10.0.0.1", http_status=503)
    assert lim.limit_for("10.0.0.9") == 2
    assert not lim.try_acquire({"10.0.0": 4})
    ips = [f"10.0.0.{i}" for i in range(1, 6)] + ["10.0.1.1"]
    got = lim.try_acquire_some(ips)
    assert got == ["10.0.0.1", "10.0.0.2", "10.0.1.1"]
    assert lim.in_flight("10.0.0.1") == 2 and lim.try_acquire_some(["10.0.0.7"]) == []


def test_paced_batches_cut_a_batch_to_the_current_limit_and_run_the_rest_later():
    c = Tick()
    lim = SubnetLimiter(4, now=c, recover_after=10_000)
    lim.observe("10.0.0.1", http_status=503)
    ledger = ContactLedger(0, limiter=lim, now=c)
    items = [(f"10.0.0.{i}", i) for i in range(1, 9)]
    sizes, concurrent, peak = [], [0], [0]

    def run(batch):
        concurrent[0] += len(batch)
        peak[0] = max(peak[0], concurrent[0])
        sizes.append([t[1] for t in batch])
        concurrent[0] -= len(batch)
        return [t[1] for t in batch]
    out = pacing.paced_batches(items, lambda t: t[0], ledger, run, batch_size=4)
    assert sorted(i for part in out for i in part) == list(range(1, 9))
    assert all(len(s) <= 2 for s in sizes) and len(sizes) == 4
    assert [i for part in out for i in part] == list(range(1, 9))          # results come back in item order
    assert lim.tracked()[0] == 0


def test_a_claim_for_several_slots_is_not_starved_by_single_slot_requests():
    lim = SubnetLimiter(2)
    assert lim.try_acquire({"a": 1})                       # one holder
    waiter = lim.ticket()
    assert not lim.try_acquire({"a": 2}, waiter)            # waits in line
    assert not lim.try_acquire({"a": 1})                    # a later single request does not jump the line
    later = lim.ticket()
    assert not lim.try_acquire({"a": 1}, later)             # nor does a later ticket
    assert lim.try_acquire({"b": 1})                        # other networks are unaffected
    lim.release({"a": 1})
    assert lim.try_acquire({"a": 2}, waiter)
    lim.release({"a": 2})
    assert not lim.try_acquire({"a": 1})                    # the next in line is the later ticket, not a newcomer
    assert lim.try_acquire({"a": 1}, later)


def test_a_waiter_that_gives_up_frees_the_line():
    lim = SubnetLimiter(1)
    assert lim.try_acquire({"a": 1})
    waiter = lim.ticket()
    assert not lim.try_acquire({"a": 1}, waiter)
    lim.release({"a": 1})
    assert not lim.try_acquire({"a": 1})
    lim.withdraw(waiter)
    assert lim.try_acquire({"a": 1})


def test_a_ledger_claim_for_two_slots_gets_in_while_single_holders_come_and_go():
    c = Tick()
    lim = SubnetLimiter(2, now=c)
    ledger = ContactLedger(0, limiter=lim, now=c, sleep=lambda s: None)
    assert ledger.claim(["10.0.0.1"])
    state = {"n": 0}

    def sleep(_s):
        state["n"] += 1
        if state["n"] == 1:
            assert not lim.try_acquire({"10.0.0": 1})        # the waiting claim holds its place
        if state["n"] == 2:
            ledger.release(["10.0.0.1"])
    ledger._sleep = sleep
    assert ledger.claim(["10.0.0.2", "10.0.0.3"])
    assert lim.in_flight("10.0.0.2") == 2


def test_mapped_and_scoped_ipv6_addresses_take_their_ipv4_or_prefix_key():
    assert network_key("::ffff:192.0.2.9") == network_key("192.0.2.1")
    assert network_key("::ffff:192.0.3.9") != network_key("::ffff:192.0.2.9")
    assert network_key("::ffff:192.0.2.9") != network_key("::ffff:0:0")
    assert network_key("fe80::1%eth0") == network_key("fe80::2%eth1") == network_key("fe80::3")


def test_a_retry_after_that_is_not_a_number_does_not_raise():
    c = Tick()
    lim = SubnetLimiter(4, now=c)
    for bad in ("Wed, 21 Oct 2026 07:28:00 GMT", "soon", float("nan"), float("inf"), object(), -3):
        lim.observe("10.0.0.1", http_status=429, retry_after=bad)
    assert lim.limit_for("10.0.0.1") < 4
    assert lim.try_acquire({"10.0.0": 1}) or lim.in_flight("10.0.0.1") == 0

    class Result:
        outcome, http_status, retry_after_seconds = "ok", 503, "later"
    pacer = IpPacer(0, limiter=lim, now=c)
    pacer.done("10.0.0.2", Result())


def test_the_ledger_forgets_addresses_whose_pause_has_passed(monkeypatch):
    monkeypatch.setattr(pacing, "_PRUNE_EVERY", 8)
    c = Tick()
    ledger = ContactLedger(5, now=c, sleep=lambda s: None)
    for i in range(100):
        ip = f"10.1.{i // 200}.{i % 200}"
        assert ledger.claim([ip])
        ledger.release([ip])
        c.t += 1.0
    assert len(ledger._last) <= 5 + 8                       # only the last pause window plus a few not yet swept
