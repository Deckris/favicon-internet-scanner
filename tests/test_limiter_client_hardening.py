"""The limiter client rides out a daemon that is slow, late or gone, and keeps working next to older and newer daemons.

The tests talk to ``Server``, a small threaded stand-in for the daemon that runs the real ``LimiterCore`` but lets a test
delay, drain slowly, mute or cut the connection, and that records every request it sees.
"""
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tarfile
import textwrap
import threading
import time
from pathlib import Path

import pytest

from scanner.internet import limiterclient, limiterd, pacing
from scanner.internet.limiterclient import LimiterClient, LimiterOutage, LimiterRefused, LimiterUnavailable
from scanner.internet.limiterd import LimiterCore
from tests.limiter_support import Jitter, Server, deadline, make_client, old_env, old_tree, run_old, server  # noqa: F401
from tests.test_limiterd import NET, ROOT, SLOW, Clock, _hung_server, start_daemon, unix_only, until

pytestmark = unix_only

OTHER = "198.51.100"


# ---------------------------------------------------------------------------------------------------- helpers

def ips_in(net, n):
    return [f"{net}.{i}" for i in range(1, n + 1)]


def fail_ping(client, clock, times):
    """Let the client fail ``times`` attempts; the delay it chose before each next attempt."""
    delays = []
    for _ in range(times):
        assert not client.ping()
        delays.append(client.retry_in())
        clock.t += delays[-1] + 0.001
    return delays


# ----------------------------------------------------------------------------------- start-up and the reconnect delay

def test_require_waits_for_a_daemon_that_starts_late(tmp_path):
    path = tmp_path / "late.sock"
    late = Server(path)
    timer = threading.Timer(0.8, late.start)
    timer.start()
    client = make_client(path)
    try:
        started = time.monotonic()
        client.require(wait=30.0)
        assert 0.7 < time.monotonic() - started < 10.0
        assert client.ping() and not client.unreachable()
    finally:
        timer.cancel()
        client.close()
        late.stop()


def test_require_gives_up_after_the_wait_and_reports_the_last_error(tmp_path):
    client = make_client(tmp_path / "absent.sock")
    started = time.monotonic()
    with pytest.raises(LimiterUnavailable) as caught:
        client.require(wait=0.6)
    took = time.monotonic() - started
    assert 0.5 <= took < 5.0
    assert "absent.sock" in str(caught.value) and ("FileNotFoundError" in str(caught.value) or "No such file" in str(caught.value))


def test_a_refused_client_is_not_retried_by_require(tmp_path, server):
    s = server(gap=0.4)
    loose = make_client(s.path, gap=1.0)                       # a longer pause than the daemon enforces: refused for good
    started = time.monotonic()
    with pytest.raises(LimiterRefused):
        loose.require(wait=30.0)
    assert time.monotonic() - started < 3.0
    assert len(s.ops("hello")) == 1


def test_require_without_a_wait_still_raises_at_once(tmp_path):
    client = make_client(tmp_path / "absent.sock", retry_after=5.0)
    started = time.monotonic()
    with pytest.raises(LimiterUnavailable, match="absent.sock"):
        client.require()
    with pytest.raises(LimiterUnavailable):
        make_client(tmp_path / "absent.sock").require(wait=0.0)
    assert time.monotonic() - started < 2.0


def test_the_wait_comes_from_the_environment_for_limiter_for(tmp_path, monkeypatch):
    import types
    m = types.SimpleNamespace(limiter_socket=str(tmp_path / "absent.sock"), max_connections_per_subnet=4,
                              min_seconds_between_probes_per_ip=5.0, retry_after_max_hold_seconds=60)
    monkeypatch.setenv("SCANNER_LIMITER_START_WAIT", "0.7")
    started = time.monotonic()
    with pytest.raises(LimiterUnavailable):
        pacing.limiter_for(m)
    assert 0.6 <= time.monotonic() - started < 6.0
    monkeypatch.delenv("SCANNER_LIMITER_START_WAIT")
    started = time.monotonic()
    with pytest.raises(LimiterUnavailable):
        pacing.limiter_for(m)
    assert time.monotonic() - started < 2.0


def test_backoff_grows_is_capped_and_is_jittered(tmp_path):
    clock = Clock()
    plain = make_client(tmp_path / "absent.sock", retry_after=0.5, now=clock, rng=Jitter(fixed=1.0))
    assert fail_ping(plain, clock, 7) == pytest.approx([0.5, 1.0, 2.0, 4.0, 4.0, 4.0, 4.0], abs=1e-6)
    assert plain.unreachable()
    clock = Clock()
    random_one = make_client(tmp_path / "absent.sock", retry_after=0.5, now=clock, rng=Jitter(seed=11))
    delays = fail_ping(random_one, clock, 8)
    for step, d in enumerate(delays):
        base = min(0.5 * 2 ** step, 4.0)
        assert 0.5 * base - 1e-6 <= d <= 1.5 * base + 1e-6
    assert len({round(d, 6) for d in delays[3:]}) > 1                      # at the cap the delays still differ


def test_backoff_resets_after_a_success(tmp_path):
    clock = Clock()
    path = tmp_path / "flaky.sock"
    client = make_client(path, retry_after=0.5, now=clock, rng=Jitter(fixed=1.0))
    assert fail_ping(client, clock, 3) == pytest.approx([0.5, 1.0, 2.0])
    s = Server(path).start()
    try:
        assert client.ping() and not client.unreachable()
        s.stop()
        assert not client.ping()
        assert client.retry_in() == pytest.approx(0.5, abs=1e-6)             # the first delay again, not 4
    finally:
        s.stop()
        client.close()


def test_unreachable_and_retry_in_follow_the_state_of_the_daemon(tmp_path):
    clock = Clock()
    path = tmp_path / "state.sock"
    client = make_client(path, retry_after=0.5, now=clock, rng=Jitter(fixed=1.0))
    assert not client.unreachable() and client.retry_in() <= 0
    assert not client.ping()
    assert client.unreachable() and 0 < client.retry_in() <= 0.5
    clock.t += 10
    assert client.retry_in() <= 0
    s = Server(path).start()
    try:
        assert client.ping()
        assert not client.unreachable()
    finally:
        client.close()
        s.stop()


# ----------------------------------------------------------------------------------------------------- big frames

def test_a_large_frame_gets_a_longer_timeout(tmp_path, server):
    s = server()
    s.drain = (64 * 1024, 0.05)                                  # takes about 1.6 s to read 2 MB
    client = make_client(s.path, io_timeout=0.5)
    try:
        pad = "x" * (2 * 1024 * 1024)
        reply = client._call({"op": "ping", "pad": pad})
        assert reply is not None and reply["ok"]
        assert not client.unreachable()
    finally:
        client.close()


def test_a_slow_drain_without_the_size_term_would_have_timed_out(tmp_path, server, old_tree):
    s = server()
    s.drain = (64 * 1024, 0.05)
    script = textwrap.dedent("""
        import sys
        from scanner.internet.limiterclient import LimiterClient
        c = LimiterClient(sys.argv[1], 4, 0.4, io_timeout=0.5, retry_after=0.05)
        r = c._call({"op": "ping", "pad": "x" * (2 * 1024 * 1024)})
        print("answered" if r else "failed")
    """)
    out = run_old(old_tree, script, s.path)
    assert out.strip() == "failed"


def test_a_hung_daemon_does_not_hold_close_for_long(tmp_path):
    close = _hung_server(tmp_path / "hung.sock")
    client = make_client(tmp_path / "hung.sock", io_timeout=0.2)
    try:
        assert not client.ping()
        started = time.monotonic()
        client.close()
        assert time.monotonic() - started < 2.5
    finally:
        close()


# -------------------------------------------------------------------------------------------- chunked release and observe

def _claim_everything(client, per_net=254):
    ips = ips_in(NET, per_net) + ips_in(OTHER, per_net)
    counts = client.counts(ips)
    assert client.try_acquire(counts, ips=ips, exclusive=True)
    return ips, counts


def test_release_is_chunked_and_the_daemon_ends_in_the_same_state(tmp_path, server):
    s = server(cap=300, gap=0.4)
    client = make_client(s.path, cap=300)
    reference = LimiterCore(300, 0.4, grace=30.0)
    try:
        ips, counts = _claim_everything(client)
        ref_conn = reference.open()
        assert reference.handle(ref_conn, {"op": "hello", "protocol": limiterd.PROTOCOL, "cap": 300, "gap": 0.4})["ok"]
        assert reference.handle(ref_conn, {"op": "claim", "ips": ips, "exclusive": True})["granted"]
        many = ips * 20                                       # 10160 entries, repeats are harmless
        client.release(counts, ips=many)
        reference.handle(ref_conn, {"op": "release", "counts": counts, "ips": many})
        frames = s.ops("release")
        assert len(frames) >= 5
        assert all(len(r["ips"]) <= 2000 for _, r in frames)
        assert frames[0][1]["counts"] == counts and all(r["counts"] == {} for _, r in frames[1:])
        assert sum(len(r["ips"]) for _, r in frames) == len(many)
        for key in (NET, OTHER):
            assert s.core.limiter.in_flight(f"{key}.1") == reference.limiter.in_flight(f"{key}.1") == 0
        assert s.core.snapshot()["in_flight_addresses"] == reference.snapshot()["in_flight_addresses"] == 0
        assert s.core.stats["stale_releases"] == reference.stats["stale_releases"]
    finally:
        client.close()


def test_a_failed_chunk_leaves_no_stale_lease_after_reconnect(tmp_path, server):
    s = server(cap=300, gap=0.4)
    client = make_client(s.path, cap=300)
    try:
        ips, counts = _claim_everything(client)
        s.cut_on["release"] = 2                                # the second slice ends the connection
        client.release(counts, ips=ips * 20)
        assert len(s.ops("release")) == 2                      # nothing more is sent after the failure
        assert client._held_counts == {} and client._held_ips == set()
        until(lambda: client.ping(), "the client to reconnect", timeout=20)
        assert s.core.snapshot()["in_flight_addresses"] == 0
        assert s.core.limiter.in_flight(f"{NET}.1") == 0 and s.core.limiter.in_flight(f"{OTHER}.1") == 0
        assert s.core.snapshot()["lingering"] == 0
    finally:
        client.close()


def test_observe_is_chunked_and_off_the_request_path(tmp_path, server):
    s = server()
    client = make_client(s.path, io_timeout=120.0)
    try:
        assert client.ping()
        s.mute.set()                                            # no reply is given until the loop below is done
        for i in range(2500):
            client.observe(f"{NET}.{i % 250 + 1}", timeout=False, http_status=200)     # would hang here if a call waited for one
        s.mute.clear()
        until(lambda: len(s.events()) == 2500, "every event to arrive", timeout=30)
        sizes = [len(r["events"]) for _, r in s.ops("observe")]
        assert max(sizes) <= 1000 and len(sizes) >= 3
    finally:
        client.close()


def test_bad_news_is_flushed_at_once_and_in_order(tmp_path, server, monkeypatch):
    s = server()
    monkeypatch.setattr(limiterclient, "OBSERVE_DELAY", 3600.0)            # a quiet report would wait for the close
    client = make_client(s.path)
    try:
        assert client.ping()
        client.observe(f"{NET}.1", timeout=False, http_status=200)
        client.observe(f"{NET}.2", timeout=True)
        client.observe(f"{NET}.3", timeout=False, http_status=200)
        client.observe(f"{NET}.4", timeout=False, http_status=429, retry_after=2)
        until(lambda: any(e.get("http_status") == 429 for e in s.events()), "the 429 to arrive", timeout=5)
        assert [e["ip"] for e in s.events()] == [f"{NET}.{i}" for i in (1, 2, 3, 4)]
    finally:
        client.close()


def test_a_quiet_success_is_not_sent_at_once_but_soon(tmp_path, server, monkeypatch):
    s = server()
    monkeypatch.setattr(limiterclient, "OBSERVE_DELAY", 1.0)
    client = make_client(s.path)
    try:
        assert client.ping()
        client.observe(f"{NET}.1", timeout=False, http_status=200)
        time.sleep(0.05)
        assert s.events() == []
        until(lambda: len(s.events()) == 1, "the flush", timeout=5)
    finally:
        client.close()


def test_observations_are_flushed_on_close_within_the_bound(tmp_path, server):
    s = server()
    client = make_client(s.path)
    assert client.ping()
    for i in range(300):
        client.observe(f"{NET}.{i % 250 + 1}", timeout=False, http_status=200)
    started = time.monotonic()
    client.close()
    assert time.monotonic() - started < 1.5
    assert len(s.events()) == 300
    ops = [op for _, op, _ in s.seen if op in ("observe", "goodbye")]
    assert ops[-1] == "goodbye" and "observe" in ops


def test_close_under_a_hung_daemon_stays_bounded_with_events_queued(tmp_path):
    close = _hung_server(tmp_path / "hung.sock")
    client = make_client(tmp_path / "hung.sock", io_timeout=0.2)
    try:
        for i in range(500):
            client.observe(f"{NET}.{i % 250 + 1}", timeout=True)
        started = time.monotonic()
        client.close()
        assert time.monotonic() - started < 3.0
    finally:
        close()


def test_observe_queue_drops_oldest_and_counts(tmp_path, server):
    s = server()
    s.mute.set()                                              # the sender is stuck in its first frame: the queue can only fill
    client = make_client(s.path, io_timeout=120.0)
    total = 230_000
    try:
        for i in range(total):
            client.observe(f"{NET}.{i % 250 + 1}", timeout=False, http_status=200, retry_after=float(i))
        time.sleep(0.3)
        dropped = client.observe_dropped
        assert total - 200_000 - 5_000 <= dropped <= total - 200_000          # the frame in the sender's hand is not in the queue
        s.mute.clear()
        until(lambda: s.events() and s.events()[-1]["retry_after"] == total - 1, "the newest events to arrive", timeout=60)
        ids = [int(e["retry_after"]) for e in s.events()]
        assert len(ids) + dropped == total and len(set(ids)) == len(ids)
        assert ids == sorted(ids) and max(ids) == total - 1
        kept_tail = ids[len(ids) - 200_000:]
        assert kept_tail == list(range(total - 200_000, total))                  # what was dropped was the oldest
    finally:
        s.mute.clear()
        client.close()


# ------------------------------------------------------------------------------ the wait hint and the local refusals

def test_try_acquire_hint_returns_the_reason_and_the_wait(tmp_path, server):
    s = server(cap=1, gap=2.0, bucket=0.05)
    a, b = make_client(s.path, cap=1, gap=2.0), make_client(s.path, cap=1, gap=2.0)
    try:
        granted, reason, wait = a.try_acquire_hint({NET: 1}, ips=[f"{NET}.9"])
        assert granted and reason is None
        granted, reason, wait = b.try_acquire_hint({NET: 1}, ips=[f"{NET}.10"])
        assert not granted and reason == "full" and 0 < wait <= 1.0
        a.release({NET: 1}, ips=[f"{NET}.9"])
        time.sleep(0.3)                                       # the refusal of b is believed for a moment
        granted, reason, wait = b.try_acquire_hint({NET: 1}, ips=[f"{NET}.9"])
        assert not granted and reason == "gap" and 1.0 < wait <= 2.1
    finally:
        a.close()
        b.close()


def _asks_for(server_, ip):
    return [t for t, r in server_.ops("claim") if ip in (r.get("ips") or [])]


def test_the_wait_hint_is_used_for_a_gap_and_backed_off_for_a_full_network(tmp_path, server):
    s = server(cap=1, gap=1.5, bucket=0.05)
    holder = make_client(s.path, cap=1, gap=1.5)
    waiter = make_client(s.path, cap=1, gap=1.5)
    try:
        assert holder.try_acquire({NET: 1}, ips=[f"{NET}.5"])
        holder.release({NET: 1}, ips=[f"{NET}.5"])
        pacer = pacing.IpPacer(0.0, limiter=waiter, max_wait=30)
        began = time.monotonic()
        assert pacer.admit(f"{NET}.5") == pacing.WAIT_OK
        took = time.monotonic() - began
        asks = _asks_for(s, f"{NET}.5")
        assert 1.3 < took < 2.4                                # the pause is respected, never shortened by the hint
        assert len(asks) <= 4                                  # one ask at the start, then at the hint, not every 0.25 s
        pacer.done(f"{NET}.5")
        # a full network: the asks spread out
        assert holder.try_acquire({NET: 1}, ips=[f"{NET}.77"])
        stop = threading.Event()
        threading.Timer(3.0, stop.set).start()
        busy = pacing.IpPacer(0.0, limiter=waiter, max_wait=30, stop_event=stop)
        assert busy.admit(f"{NET}.78") == pacing.WAIT_STOPPED
        asks = _asks_for(s, f"{NET}.78")
        gaps = [b - a for a, b in zip(asks, asks[1:])]
        assert 3 <= len(asks) <= 9                             # polling every 0.25 s would have made about 12
        assert gaps[-1] >= 0.6 and gaps[-1] >= gaps[0]
        assert max(gaps) <= 1.6
    finally:
        holder.close()
        waiter.close()


def test_a_hint_never_grants_early(tmp_path, server):
    """The wait the daemon names is when to ask again: asking before it is refused, asking at it is granted at once."""
    s = server(cap=1, gap=1.0, bucket=0.05)
    first, second = make_client(s.path, cap=1, gap=1.0), make_client(s.path, cap=1, gap=1.0)
    try:
        assert first.try_acquire({NET: 1}, ips=[f"{NET}.2"])
        first.release({NET: 1}, ips=[f"{NET}.2"])
        granted, reason, wait = second.try_acquire_hint({NET: 1}, ips=[f"{NET}.2"])
        assert not granted and reason == "gap" and 0.5 < wait <= 1.1
        time.sleep(wait / 2)
        granted, reason, left = second.try_acquire_hint({NET: 1}, ips=[f"{NET}.2"])
        assert not granted and reason == "gap" and left < wait          # half way through the pause nothing is granted
        assert second._held_counts == {} and s.core.limiter.in_flight(f"{NET}.1") == 0
        time.sleep(left + 0.15)
        before = len(s.ops("claim"))
        assert second.try_acquire({NET: 1}, ips=[f"{NET}.2"])           # the first ask after the hint is the grant
        assert len(s.ops("claim")) == before + 1
    finally:
        first.close()
        second.close()


def test_a_full_network_is_refused_locally_for_a_short_time_and_never_granted_locally(tmp_path, server):
    s = server(cap=2, gap=0.0)
    a, b = make_client(s.path, cap=2, gap=0.0), make_client(s.path, cap=2, gap=0.0)
    try:
        assert b.try_acquire({NET: 1}, ips=[f"{NET}.1"])
        assert a.try_acquire({NET: 1}, ips=[f"{NET}.2"])
        before = len(s.ops("claim"))
        for _ in range(20):
            assert not a.try_acquire({NET: 1}, ips=[f"{NET}.3"])
        assert len(s.ops("claim")) - before <= 2               # the first answer is remembered for a moment
        a.release({NET: 1}, ips=[f"{NET}.2"])                    # a release of that network drops the entry
        mid = len(s.ops("claim"))
        assert a.try_acquire({NET: 1}, ips=[f"{NET}.3"])
        assert len(s.ops("claim")) == mid + 1
        assert s.core.limiter.in_flight(f"{NET}.1") == 2
        # another network is not affected by the remembered refusal
        assert a.try_acquire({OTHER: 1}, ips=[f"{OTHER}.1"])
    finally:
        a.close()
        b.close()


def test_a_cached_refusal_is_forgotten_after_a_short_time(tmp_path, server):
    s = server(cap=1, gap=0.0)
    a, b = make_client(s.path, cap=1, gap=0.0), make_client(s.path, cap=1, gap=0.0)
    try:
        assert b.try_acquire({NET: 1}, ips=[f"{NET}.1"])
        assert not a.try_acquire({NET: 1}, ips=[f"{NET}.2"])
        b.release({NET: 1}, ips=[f"{NET}.1"])
        until(lambda: a.try_acquire({NET: 1}, ips=[f"{NET}.2"]), "the remembered refusal to lapse", timeout=3, poll=0.02)
    finally:
        a.close()
        b.close()


def test_a_client_that_holds_its_cap_asks_nobody_for_an_unticketed_claim(tmp_path, server):
    s = server(cap=2, gap=0.0)
    a = make_client(s.path, cap=2, gap=0.0)
    try:
        assert a.try_acquire({NET: 2}, ips=[f"{NET}.1", f"{NET}.2"])
        before = len(s.ops("claim"))
        assert not a.try_acquire({NET: 1}, ips=[f"{NET}.3"])
        assert len(s.ops("claim")) == before
        ticket = a.ticket()                                   # a place in line is kept at the daemon, so it is still asked
        assert not a.try_acquire({NET: 1}, ticket, ips=[f"{NET}.3"])
        assert len(s.ops("claim")) == before + 1
        a.withdraw(ticket)
    finally:
        a.close()


def test_the_cap_pre_check_matches_the_daemons_answer(tmp_path, server):
    cap = 3
    s = server(cap=cap, gap=0.0)
    clients = [make_client(s.path, cap=cap, gap=0.0) for _ in range(3)]
    rng = random.Random(2024)
    nets = (NET, OTHER)
    held = [{n: [] for n in nets} for _ in clients]
    serial = iter(range(1, 10 ** 6))
    at_cap = 0
    try:
        for step in range(800):
            who = rng.randrange(len(clients))
            net = rng.choice(nets)
            client = clients[who]
            mine = held[who][net]
            if mine and rng.random() < 0.45:
                ip = mine.pop(rng.randrange(len(mine)))
                client.release({net: 1}, ips=[ip])
                continue
            ip = f"{net}.{next(serial) % 250 + 1}"
            was_at_cap = len(mine) >= cap
            asked = len(s.ops("claim"))
            got = client.try_acquire({net: 1}, ips=[ip])
            if was_at_cap:
                at_cap += 1
                assert not got
                assert len(s.ops("claim")) == asked                         # refused without a message to the daemon
                assert s.core.limiter.in_flight(f"{net}.1") >= cap       # the daemon would have said no as well
            if got:
                mine.append(ip)
            assert s.core.limiter.in_flight(f"{net}.1") <= cap
            assert s.core.limiter.in_flight(f"{net}.1") == sum(len(h[net]) for h in held)
        assert at_cap >= 20                                                 # the walk did reach the cap often enough to mean something
    finally:
        for c in clients:
            c.close()


# --------------------------------------------------------------------------------------- outages and the max_wait

def test_outage_time_does_not_count_against_max_wait(tmp_path):
    close = _hung_server(tmp_path / "hung.sock")
    try:
        client = make_client(tmp_path / "hung.sock", io_timeout=0.1, retry_after=0.02, outage_limit=2.0)
        pacer = pacing.IpPacer(0.0, limiter=client, max_wait=0.3, poll=0.02)
        started = time.monotonic()
        with pytest.raises(LimiterOutage):
            pacer.admit(f"{NET}.1")
        assert time.monotonic() - started >= 1.8                   # it waited the outage out, not max_wait
        client = make_client(tmp_path / "hung.sock", io_timeout=0.1, retry_after=0.02, outage_limit=2.0)
        ledger = pacing.ContactLedger(0.0, limiter=client, max_wait=0.3)
        started = time.monotonic()
        with pytest.raises(LimiterOutage):
            ledger.claim_some([f"{NET}.2", f"{NET}.3"])
        assert time.monotonic() - started >= 1.8
    finally:
        close()


def test_a_full_network_still_ends_in_wait_busy(tmp_path, server):
    s = server(cap=1, gap=0.0)
    holder, waiter = make_client(s.path, cap=1, gap=0.0), make_client(s.path, cap=1, gap=0.0)
    try:
        assert holder.try_acquire({NET: 1}, ips=[f"{NET}.1"])
        pacer = pacing.IpPacer(0.0, limiter=waiter, max_wait=0.6, poll=0.02)
        started = time.monotonic()
        assert pacer.admit(f"{NET}.2") == pacing.WAIT_BUSY
        assert 0.5 <= time.monotonic() - started < 4.0
        ledger = pacing.ContactLedger(0.0, limiter=waiter, max_wait=0.6)
        assert ledger.claim_some([f"{NET}.3"]) == []
    finally:
        holder.close()
        waiter.close()


def test_a_daemon_that_returns_inside_the_outage_limit_loses_no_lookups(tmp_path):
    path = tmp_path / "late.sock"
    late = Server(path, cap=4, gap=0.0)
    timer = threading.Timer(1.5, late.start)
    timer.start()
    client = make_client(path, cap=4, gap=0.0, outage_limit=20.0)
    results = []
    lock = threading.Lock()

    def lookup(ip):
        pacer_result = pacers[ip].admit(ip)
        with lock:
            results.append(pacer_result)
        if pacer_result == pacing.WAIT_OK:
            pacers[ip].done(ip)
    ips = [f"{prefix}.{i}" for prefix in (NET, OTHER, "203.0.113") for i in range(1, 11)]
    pacers = {ip: pacing.IpPacer(0.0, limiter=client, max_wait=0.5, poll=0.02) for ip in ips}
    try:
        pool = [threading.Thread(target=lookup, args=(ip,)) for ip in ips]
        for t in pool:
            t.start()
        for t in pool:
            t.join(60)
        assert results.count(pacing.WAIT_OK) == len(ips)
    finally:
        timer.cancel()
        client.close()
        late.stop()


# ----------------------------------------------------------------------------------- older and newer peers together

OLD_CLIENT = textwrap.dedent("""
    import json, sys, threading, time
    from scanner.internet.limiterclient import LimiterClient
    import scanner.internet.limiterclient as m
    assert m.__file__.startswith(sys.argv[3]), m.__file__
    path, log, tree = sys.argv[1], sys.argv[2], sys.argv[3]
    cap, gap = 4, 0.25
    c = LimiterClient(path, cap, gap)
    def work():
        for _ in range(4):
            while not c.try_acquire({"192.0.2": 1}, ips=["192.0.2.7"], exclusive=True):
                time.sleep(0.02)
            with open(log, "a") as f:
                f.write("%.6f c\\n" % time.monotonic())
            c.release({"192.0.2": 1}, ips=["192.0.2.7"])
    pool = [threading.Thread(target=work) for _ in range(2)]
    [t.start() for t in pool]; [t.join() for t in pool]
    st = c.stats()
    c.observe("192.0.2.7", timeout=False, http_status=200)
    c.close()
    print(json.dumps({"stats_ok": isinstance(st, dict) and "connections" in st}))
""")


def _contact_new(path, log, rounds):
    c = LimiterClient(path, 4, 0.25)
    for _ in range(rounds):
        while not c.try_acquire({NET: 1}, ips=["192.0.2.7"], exclusive=True):
            time.sleep(0.02)
        with open(log, "a") as f:
            f.write(f"{time.monotonic():.6f} c\n")
        c.release({NET: 1}, ips=["192.0.2.7"])
    c.close()


def _mixed_fleet(daemon_tree, tmp_path, old_tree):
    """Old and new clients against one daemon: the pause between two contacts of an address holds for all of them."""
    proc, path, probe = start_daemon_in(tmp_path, daemon_tree)
    log = tmp_path / "contacts.log"
    try:
        old = subprocess.Popen([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv.pop(1)); exec(sys.argv.pop(1))",
                                str(old_tree), OLD_CLIENT, path, str(log), str(old_tree)], cwd=old_tree,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=old_env(old_tree))
        news = [threading.Thread(target=_contact_new, args=(path, str(log), 4)) for _ in range(2)]
        for t in news:
            t.start()
        out, err = old.communicate(timeout=SLOW)
        for t in news:
            t.join(SLOW)
        assert old.returncode == 0, err
        assert json.loads(out.strip().splitlines()[-1])["stats_ok"]
        times = sorted(float(line.split()[0]) for line in log.read_text().splitlines())
        assert len(times) == 4 * 2 + 4 * 2
        assert all(b - a >= 0.25 - 0.03 for a, b in zip(times, times[1:]))
        assert probe.stats()["in_flight_addresses"] == 0
    finally:
        probe.close()
        proc.terminate()
        proc.wait(SLOW)


def start_daemon_in(tmp_path, tree, cap=4, gap=0.25):
    path = tmp_path / "mixed.sock"
    proc = subprocess.Popen([sys.executable, "-m", "scanner.internet", "limiterd", "--socket", str(path),
                             "--max-connections-per-subnet", str(cap), "--min-seconds-between-probes", str(gap),
                             "--bucket-seconds", "0.05", "--startup-hold-seconds", "0"], cwd=tree, env=old_env(tree))
    probe = LimiterClient(str(path), cap, gap, retry_after=0.05)
    until(lambda: proc.poll() is None and path.exists() and probe.ping(), "the daemon to come up")
    return proc, str(path), probe


def test_old_and_new_clients_share_the_pause_on_a_current_daemon(tmp_path, old_tree):
    _mixed_fleet(ROOT, tmp_path, old_tree)


def test_old_and_new_clients_share_the_pause_on_an_old_daemon(tmp_path, old_tree):
    _mixed_fleet(old_tree, tmp_path, old_tree)


def test_a_new_client_works_against_an_old_daemon_and_keeps_the_cap(tmp_path, old_tree):
    proc, path, probe = start_daemon_in(tmp_path, old_tree)
    clients = [LimiterClient(path, 4, 0.25) for _ in range(3)]
    peak = [0]
    now_open = [0]
    lock = threading.Lock()

    def work(c):
        for _ in range(6):
            assert c.acquire({NET: 1})
            with lock:
                now_open[0] += 1
                peak[0] = max(peak[0], now_open[0])
            time.sleep(0.01)
            with lock:
                now_open[0] -= 1
            c.release({NET: 1})
    try:
        pool = [threading.Thread(target=work, args=(c,)) for c in clients for _ in range(3)]
        for t in pool:
            t.start()
        for t in pool:
            t.join(SLOW)
        assert peak[0] <= 4
        ips, counts = ips_in(NET, 4), {NET: 4}
        assert clients[0].try_acquire(counts, ips=ips, exclusive=True)
        clients[0].release(counts, ips=ips * 1500)                 # a chunked release: the old daemon takes every slice
        until(lambda: probe.stats()["in_flight_addresses"] == 0, "the release to arrive")
        assert probe.in_flight(f"{NET}.1") == 0
        for i in range(600):
            clients[1].observe(f"{NET}.{i % 250 + 1}", timeout=False, http_status=200)
        clients[1].observe(f"{NET}.1", timeout=False, http_status=429, retry_after=1)
        until(lambda: probe.limit_for(f"{NET}.1") < 4, "the back-off to be seen by every client")
    finally:
        for c in clients:
            c.close()
        probe.close()
        proc.terminate()
        proc.wait(SLOW)


def test_a_new_client_is_still_refused_by_an_old_daemon_that_is_stricter(tmp_path, old_tree):
    proc, path, probe = start_daemon_in(tmp_path, old_tree, cap=2, gap=1.0)
    try:
        loose = LimiterClient(path, 1, 0.4, retry_after=0.05)           # a lower cap than the daemon allows
        with pytest.raises(LimiterRefused):
            loose.try_acquire({NET: 1}, ips=[f"{NET}.1"])
        with pytest.raises(LimiterRefused):
            LimiterClient(path, 4, 2.0).require(wait=5.0)          # a longer pause than the daemon enforces
    finally:
        probe.close()
        proc.terminate()
        proc.wait(SLOW)


def test_old_client_ignores_new_stats_keys_in_a_reply(tmp_path, server, old_tree):
    s = server()
    s.core.stats.update({"loop_lag_max_ms": 1, "largest_frame": 2})
    script = textwrap.dedent("""
        import sys
        from scanner.internet.limiterclient import LimiterClient
        c = LimiterClient(sys.argv[1], 4, 0.4)
        st = c.stats()
        print("ok" if st and "connections" in st and "ok" not in st else "bad")
        c.close()
    """)
    assert run_old(old_tree, script, s.path).strip() == "ok"
