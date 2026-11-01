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


def test_oversized_request_runs_when_the_network_is_idle():
    lim = SubnetLimiter(4)
    assert lim.try_acquire({"a": 6})
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
