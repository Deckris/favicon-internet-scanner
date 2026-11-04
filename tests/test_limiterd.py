"""The machine-wide connection limiter: its rules (fake clock), and processes sharing one daemon over a Unix socket."""
import multiprocessing
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from scanner.internet import limiterd
from scanner.internet.limiterclient import LimiterClient
from scanner.internet.limiterd import ContactBuckets, LimiterCore

unix_only = pytest.mark.skipif(not hasattr(__import__("socket"), "AF_UNIX") or sys.platform == "win32",
                               reason="needs Unix domain sockets")
NET = "192.0.2"
ROOT = Path(__file__).resolve().parent.parent


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def ask(core, conn, op, **kw):
    return core.handle(conn, {"op": op, **kw})


def new_conn(core, cap=4, gap=0.0):
    conn = core.open()
    assert ask(core, conn, "hello", protocol=limiterd.PROTOCOL, cap=cap, gap=gap)["ok"]
    return conn


def ips_of(n, net=NET):
    return [f"{net}.{i}" for i in range(1, n + 1)]


def test_frames_round_trip_and_oversize_is_refused():
    frame = limiterd.pack_frame({"op": "ping", "n": [1, 2]})
    assert limiterd.unpack_length(frame[:4]) == len(frame) - 4
    assert limiterd.decode_frame(frame[4:]) == {"op": "ping", "n": [1, 2]}
    with pytest.raises(ValueError):
        limiterd.unpack_length((limiterd.MAX_FRAME + 1).to_bytes(4, "big"))
    with pytest.raises(ValueError):
        limiterd.decode_frame(b"[1]")


def test_cap_holds_across_connections_and_connection_close_frees_the_slots():
    core = LimiterCore(4, 0.0, now=Clock())
    a, b = new_conn(core), new_conn(core)
    assert ask(core, a, "claim", ips=ips_of(3))["granted"]
    assert ask(core, b, "claim", ips=["192.0.2.50"])["granted"]
    assert not ask(core, b, "claim", ips=["192.0.2.51"])["granted"]          # a fifth slot is not there
    assert ask(core, b, "claim", ips=["198.51.100.1"])["granted"]            # another network is unaffected
    core.close(a)                                                          # a's three slots come back with its connection
    assert ask(core, b, "claim", ips=["192.0.2.51", "192.0.2.52", "192.0.2.53"])["granted"]
    assert core.limiter.in_flight("192.0.2.1") == 4


def test_a_claim_is_all_or_nothing_and_partial_takes_what_fits():
    core = LimiterCore(2, 0.0, now=Clock())
    a = new_conn(core, cap=2)
    assert ask(core, a, "claim", ips=["192.0.2.1"])["granted"]
    assert not ask(core, a, "claim", ips=["192.0.2.2", "192.0.2.3", "198.51.100.1"])["granted"]
    assert core.limiter.in_flight("198.51.100.1") == 0
    reply = ask(core, a, "claim", ips=["192.0.2.2", "192.0.2.3", "198.51.100.1"], partial=True)
    assert reply["granted"] and reply["ips"] == ["192.0.2.2", "198.51.100.1"]


def test_release_is_limited_to_what_the_connection_holds():
    core = LimiterCore(2, 0.0, now=Clock())
    a, b = new_conn(core, cap=2), new_conn(core, cap=2)
    assert ask(core, a, "claim", counts={NET: 2})["granted"]
    ask(core, b, "release", counts={NET: 2})                                # b holds nothing: a's slots stay taken
    assert core.limiter.in_flight("192.0.2.1") == 2 and core.stats["stale_releases"] == 2
    ask(core, a, "release", counts={NET: 2})
    assert core.limiter.in_flight("192.0.2.1") == 0


def test_pause_between_contacts_holds_across_connections():
    clock = Clock()
    core = LimiterCore(4, 5.0, now=clock, bucket=0.5)
    a, b = new_conn(core), new_conn(core)
    assert ask(core, a, "claim", ips=["192.0.2.9"])["granted"]
    ask(core, a, "release", counts={NET: 1}, ips=[])
    reply = ask(core, b, "claim", ips=["192.0.2.9"])
    assert not reply["granted"] and reply["reason"] == "gap" and 4.9 < reply["wait"] <= 5.6
    clock.t += 3
    assert not ask(core, b, "claim", ips=["192.0.2.9"])["granted"]
    clock.t += 3
    assert ask(core, b, "claim", ips=["192.0.2.9"])["granted"]


def test_an_exclusive_claim_blocks_the_address_until_released_and_the_pause_runs_from_the_release():
    clock = Clock()
    core = LimiterCore(4, 5.0, now=clock, bucket=0.1)
    a, b = new_conn(core), new_conn(core)
    assert ask(core, a, "claim", ips=["192.0.2.9"], exclusive=True)["granted"]
    clock.t += 20
    assert not ask(core, b, "claim", ips=["192.0.2.9"])["granted"]          # still in flight, however old
    ask(core, a, "release", counts={NET: 1}, ips=["192.0.2.9"])
    clock.t += 4
    assert not ask(core, b, "claim", ips=["192.0.2.9"])["granted"]
    clock.t += 1.5
    assert ask(core, b, "claim", ips=["192.0.2.9"])["granted"]


def test_partial_claim_leaves_addresses_that_are_not_due():
    clock = Clock()
    core = LimiterCore(4, 5.0, now=clock, bucket=0.1)
    a = new_conn(core)
    assert ask(core, a, "claim", ips=["192.0.2.1"])["granted"]
    reply = ask(core, a, "claim", ips=["192.0.2.1", "192.0.2.2"], partial=True)
    assert reply["ips"] == ["192.0.2.2"]
    assert not ask(core, a, "claim", ips=["192.0.2.1", "192.0.2.3"])["granted"]


def test_a_connection_that_dies_in_flight_starts_the_pause():
    clock = Clock()
    core = LimiterCore(4, 5.0, now=clock, bucket=0.1)
    a, b = new_conn(core), new_conn(core)
    ask(core, a, "claim", ips=["192.0.2.1"], exclusive=True)
    core.close(a)
    assert not ask(core, b, "claim", ips=["192.0.2.1"])["granted"]
    clock.t += 5.5
    assert ask(core, b, "claim", ips=["192.0.2.1"])["granted"]


def test_leases_of_a_silent_connection_expire_and_it_is_told_to_reconnect():
    clock = Clock()
    core = LimiterCore(1, 0.0, now=clock, lease_ttl=30)
    a, b = new_conn(core, cap=1), new_conn(core, cap=1)
    assert ask(core, a, "claim", ips=["192.0.2.1"])["granted"]
    clock.t += 20
    ask(core, a, "ping")                                                    # a sign of life moves the deadline
    clock.t += 20
    core.sweep()
    assert not ask(core, b, "claim", ips=["192.0.2.2"])["granted"]
    clock.t += 20
    core.sweep()
    assert ask(core, b, "claim", ips=["192.0.2.2"])["granted"]
    assert ask(core, a, "ping")["close"] and core.stats["expired"] == 1


def test_waiters_are_served_in_arrival_order_across_connections():
    core = LimiterCore(2, 0.0, now=Clock())
    a, b, c = new_conn(core, cap=2), new_conn(core, cap=2), new_conn(core, cap=2)
    assert ask(core, a, "claim", counts={NET: 2})["granted"]
    assert not ask(core, b, "claim", counts={NET: 2}, ticket=1)["granted"]        # b waits for both slots
    ask(core, a, "release", counts={NET: 1})
    assert not ask(core, c, "claim", counts={NET: 1}, ticket=1)["granted"]        # a free slot, but b is ahead
    ask(core, a, "release", counts={NET: 1})
    assert ask(core, b, "claim", counts={NET: 2}, ticket=1)["granted"]
    core.close(b)
    assert ask(core, c, "claim", counts={NET: 1}, ticket=1)["granted"]


def test_a_waiter_that_goes_away_leaves_the_line():
    core = LimiterCore(1, 0.0, now=Clock())
    a, b, c = new_conn(core, cap=1), new_conn(core, cap=1), new_conn(core, cap=1)
    ask(core, a, "claim", counts={NET: 1})
    assert not ask(core, b, "claim", counts={NET: 1}, ticket=7)["granted"]
    core.close(b)
    ask(core, a, "release", counts={NET: 1})
    assert ask(core, c, "claim", counts={NET: 1}, ticket=1)["granted"]


def test_observations_from_any_client_lower_the_limit_for_all():
    clock = Clock()
    core = LimiterCore(4, 0.0, now=clock)
    a, b = new_conn(core), new_conn(core)
    ask(core, a, "observe", events=[{"ip": "192.0.2.1", "http_status": 429, "retry_after": 2}])
    assert ask(core, b, "query", ip="192.0.2.77")["limit"] == 2
    assert not ask(core, b, "claim", ips=["192.0.2.5"])["granted"]            # held for the Retry-After
    clock.t += 3
    assert ask(core, b, "claim", ips=["192.0.2.5"])["granted"]


def test_a_client_looser_than_the_daemon_is_refused():
    core = LimiterCore(2, 5.0, now=Clock())
    assert ask(core, core.open(), "hello", protocol=limiterd.PROTOCOL, cap=4, gap=5.0)["ok"]
    for cap, gap in ((1, 5.0), (4, 6.0)):
        assert not ask(core, core.open(), "hello", protocol=limiterd.PROTOCOL, cap=cap, gap=gap)["ok"]
    assert not ask(core, core.open(), "claim", ips=["192.0.2.1"])["ok"]       # no claim before hello


def test_the_ledger_keeps_only_the_pause_in_memory():
    ledger = ContactBuckets(5.0, 1.0)
    peak = 0
    for second in range(600):                       # 200 addresses a second for ten minutes: 120000 addresses in all
        now = 1000.0 + second
        for i in range(200):
            ledger.add(f"10.{second // 256}.{second % 256}.{i}", now)
        ledger.prune(now)
        peak = max(peak, len(ledger))
    assert peak <= 200 * 7 and ledger.buckets <= 7
    assert ledger.due_in("10.0.0.0", now) == 0.0
    ledger.prune(now + 60)
    assert len(ledger) == 0 and ledger.buckets == 0


def test_the_ledger_never_shortens_the_pause():
    ledger = ContactBuckets(5.0, 1.0)
    ledger.add("192.0.2.1", 100.2)
    assert ledger.due_in("192.0.2.1", 100.2) >= 5.0
    assert ledger.due_in("192.0.2.1", 105.3) > 0
    assert ledger.due_in("192.0.2.1", 106.01) == 0.0


# the client without a daemon (runs anywhere)

def test_client_fails_closed_without_a_daemon(tmp_path):
    client = LimiterClient(str(tmp_path / "absent.sock"), 4, 5.0, connect_timeout=0.1, retry_after=0.05)
    started = time.monotonic()
    assert not client.try_acquire({NET: 1}, ips=["192.0.2.1"])
    assert client.try_acquire_some(["192.0.2.1", "192.0.2.2"]) == []
    assert not client.try_acquire({NET: 1})
    stop = threading.Event()
    threading.Timer(0.3, stop.set).start()
    assert client.acquire({NET: 1}, stop_event=stop, poll=0.05) is False
    client.release({NET: 1})                                                  # harmless
    client.observe("192.0.2.1", timeout=True)
    assert client.limit_for("192.0.2.1") == 0 and not client.ping()
    assert time.monotonic() - started < 3


# processes sharing one daemon (Unix only)

def start_daemon(tmp_path, cap=4, gap=0.4, ttl=300.0):
    path = tmp_path / "limiter.sock"
    proc = subprocess.Popen([sys.executable, "-m", "scanner.internet", "limiterd", "--socket", str(path),
                             "--max-connections-per-subnet", str(cap), "--min-seconds-between-probes", str(gap),
                             "--bucket-seconds", "0.05", "--lease-ttl-seconds", str(ttl)], cwd=ROOT)
    probe = LimiterClient(str(path), cap, gap, retry_after=0.05)
    for _ in range(100):
        if path.exists() and probe.ping():
            break
        time.sleep(0.1)
    else:
        proc.kill()
        raise AssertionError("daemon did not come up")
    return proc, str(path), probe


@pytest.fixture
def daemon(tmp_path):
    proc, path, probe = start_daemon(tmp_path)
    yield path, probe
    probe.close()
    proc.terminate()
    proc.wait(10)


def _hammer(path, log, threads, rounds, cap, gap):
    """Take and give back slots of one /24, logging the time after each grant and before each release."""
    client = LimiterClient(path, cap, gap)

    def one():
        for _ in range(rounds):
            assert client.acquire({NET: 1})
            with open(log, "a") as f:
                f.write(f"{time.monotonic():.6f} +\n")
            time.sleep(0.005)
            with open(log, "a") as f:
                f.write(f"{time.monotonic():.6f} -\n")
            client.release({NET: 1})
    pool = [threading.Thread(target=one) for _ in range(threads)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    client.close()


def _contact(path, log, rounds, cap, gap):
    client = LimiterClient(path, cap, gap)
    for _ in range(rounds):
        while not client.try_acquire({NET: 1}, ips=["192.0.2.7"], exclusive=True):
            time.sleep(0.02)
        with open(log, "a") as f:
            f.write(f"{time.monotonic():.6f}\n")
        client.release({NET: 1}, ips=["192.0.2.7"])
    client.close()


def _hold(path, ready, count):
    client = LimiterClient(path, 4, 0.4)
    for i in range(count):
        assert client.try_acquire({NET: 1}, ips=[f"192.0.2.{100 + i}"])
    Path(ready).write_text("held")
    time.sleep(600)


def _spawn(target, *args):
    p = multiprocessing.get_context("spawn").Process(target=target, args=args)
    p.start()
    return p


@unix_only
def test_processes_never_exceed_the_cap_per_network(daemon, tmp_path):
    path, _ = daemon
    log = tmp_path / "events.log"
    procs = [_spawn(_hammer, path, str(log), 4, 5, 4, 0.4) for _ in range(3)]
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    events = sorted(line.split() for line in log.read_text().splitlines())
    assert len(events) == 3 * 4 * 5 * 2
    open_now = peak = 0
    for _, sign in events:
        open_now += 1 if sign == "+" else -1
        peak = max(peak, open_now)
    assert 2 <= peak <= 4


@unix_only
def test_the_pause_between_requests_to_one_address_holds_across_processes(daemon, tmp_path):
    path, _ = daemon
    log = tmp_path / "contacts.log"
    procs = [_spawn(_contact, path, str(log), 5, 4, 0.4) for _ in range(2)]
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    times = sorted(float(x) for x in log.read_text().split())
    assert len(times) == 10
    assert all(b - a >= 0.4 - 0.03 for a, b in zip(times, times[1:]))


@unix_only
def test_leases_are_freed_when_a_client_process_is_killed(daemon, tmp_path):
    path, probe = daemon
    ready = tmp_path / "ready"
    holder = _spawn(_hold, path, str(ready), 4)
    for _ in range(200):
        if ready.exists():
            break
        time.sleep(0.05)
    assert ready.exists()
    assert not probe.try_acquire({NET: 1}, ips=["192.0.2.200"])               # the cap is used up
    holder.kill()
    holder.join(10)
    for _ in range(100):
        if probe.try_acquire({NET: 1}, ips=["192.0.2.201"]):
            break
        time.sleep(0.05)
    else:
        raise AssertionError("slots of the killed process were not freed")
    assert probe.stats()["connections"] == 1


@unix_only
def test_a_hung_client_loses_its_leases_after_the_ttl(tmp_path):
    proc, path, probe = start_daemon(tmp_path, cap=1, ttl=1.0)
    hung = LimiterClient(path, 1, 0.4)
    try:
        assert hung.try_acquire({NET: 1})
        hung._closed.set()                                                    # no keep-alive, the socket stays open
        assert not probe.try_acquire({NET: 1})
        for _ in range(60):
            if probe.try_acquire({NET: 1}):
                break
            time.sleep(0.1)
        else:
            raise AssertionError("leases of the hung client did not expire")
    finally:
        probe.close()
        proc.terminate()
        proc.wait(10)


@unix_only
def test_the_socket_is_private_and_a_second_daemon_is_refused(daemon):
    path, _ = daemon
    assert oct(os.stat(path).st_mode & 0o777) == "0o660"
    again = subprocess.run([sys.executable, "-m", "scanner.internet", "limiterd", "--socket", path],
                           cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert again.returncode == 2 and "already listening" in again.stderr


@unix_only
def test_a_client_looser_than_the_daemon_gets_nothing(daemon):
    path, _ = daemon
    loose = LimiterClient(path, 4, 1.0, retry_after=0.05)
    assert not loose.try_acquire({NET: 1}, ips=["192.0.2.1"])


def test_the_socket_path_is_host_local_and_leaves_the_checksum_alone():
    from scanner.internet.config import config_checksum, shared_config_checksum
    raw = {"measurement": {"max_connections_per_subnet": 4}}
    with_socket = {"measurement": {"max_connections_per_subnet": 4, "limiter_socket": "/run/limiter.sock"}}
    assert config_checksum(raw) == config_checksum(with_socket)
    assert shared_config_checksum(raw) == shared_config_checksum(with_socket)
