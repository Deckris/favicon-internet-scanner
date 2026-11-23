"""The limiter under faults: a daemon that is frozen, killed or starved, clients that crowd it, send slowly or split their
frames at odd places, and the rules that must hold through all of it (cap, pause, nothing sent without a grant).

The runs here are scaled down (outage limits of seconds). The same scenarios at full length, and the one with a whole
campaign, run when ``LIMITER_FAULTS_FULL=1`` is set. Test addresses are the documentation ranges only.
"""
import importlib.util
import json
import multiprocessing
import os
import random
import re
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

import pytest

from scanner.internet import coordinator, limiterclient, limiterd, pacing
from scanner.internet.limiterclient import LimiterClient, LimiterOutage
from scanner.internet.limiterd import ContactBuckets, LimiterCore
from tests.limiter_support import (FULL, Server, deadline, make_client, old_tree, raw_hello, recv_exact, recv_reply,  # noqa: F401
                                   reference, start_lean, stop)
from tests.test_limiterd import NET, ROOT, SLOW, Clock, _hung_server, _spawn, unix_only, until

pytestmark = unix_only

full_only = pytest.mark.skipif(not FULL, reason="full-length run: set LIMITER_FAULTS_FULL=1")
NETS = ("192.0.2", "198.51.100", "203.0.113")
CAP, GAP = 2, 0.3
ADDRESSES = [f"{net}.{i}" for net in NETS for i in range(1, 13)]


# ------------------------------------------------------------------------------------------- a fleet of clients

def _stamp(path, sign, ip):
    os.write(path, f"{time.monotonic():.6f} {sign} {ip}\n".encode())


def _lookups(path, log, out, threads, rounds, cap, gap, outage_limit, start_wait, max_wait, hold, seed):
    """One client process: ``threads`` threads of ``rounds`` lookups each, as a favicon worker makes them."""
    pacing.set_strict(True)
    pacing.reset_violations()
    result = {"ok": 0, "busy": 0, "stopped": 0, "errors": [], "episodes": [], "lost": 0, "dropped": 0, "violations": 0}
    fd = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)

    class Stamping(LimiterClient):
        def _granted(self, counts, ips, exclusive):
            for ip in ips:                      # the contact is stamped the moment the grant is known
                _stamp(fd, "+", ip)
            super()._granted(counts, ips, exclusive)
    client = Stamping(path, cap, gap, outage_limit=outage_limit)
    try:
        client.require(start_wait)
    except Exception as exc:
        result["errors"].append(f"{type(exc).__name__}: {exc}")
        Path(out).write_text(json.dumps(result))
        return
    pacer = pacing.IpPacer(gap, limiter=client, max_wait=max_wait)
    lock = threading.Lock()
    answered = types.SimpleNamespace(outcome=None, http_status=200, retry_after_seconds=None)

    def one(k):
        rng = random.Random(seed * 1000 + k)
        for _ in range(rounds):
            ip = rng.choice(ADDRESSES)
            try:
                verdict = pacer.admit(ip)
            except Exception as exc:
                with lock:
                    result["errors"].append(f"{type(exc).__name__}: {exc}")
                return
            with lock:
                result["ok" if verdict == pacing.WAIT_OK else "busy" if verdict == pacing.WAIT_BUSY else "stopped"] += 1
            if verdict == pacing.WAIT_OK:
                time.sleep(hold)
                _stamp(fd, "-", ip)
                pacer.done(ip, answered)
    pool = [threading.Thread(target=one, args=(k,)) for k in range(threads)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    client.close()
    result.update(episodes=client.episodes(), lost=client.observe_lost, dropped=client.observe_dropped, violations=pacing.violations()[0])
    Path(out).write_text(json.dumps(result))


class Daemon:
    """The lean daemon as a process of its own, to be frozen, killed and started again."""

    def __init__(self, tmp_path, cap=CAP, gap=GAP, env=None, name="fleet.sock"):
        self.tmp_path, self.name, self.env, self.cap, self.gap = tmp_path, name, env, cap, gap
        self.flags = ["--max-connections-per-subnet", str(cap), "--min-seconds-between-probes", str(gap)]
        self.proc = None
        self.path = str(tmp_path / name)
        self.probe = None

    def start(self, hold=0.0):
        self.proc, self.path, probe = start_lean(self.tmp_path, *self.flags, "--startup-hold-seconds", str(hold), env=self.env, name=self.name,
                                                    limits=(self.cap, self.gap))
        if self.probe is not None:
            self.probe.close()
        self.probe = probe
        return self

    def freeze(self):
        os.kill(self.proc.pid, signal.SIGSTOP)

    def thaw(self):
        os.kill(self.proc.pid, signal.SIGCONT)

    def kill(self):
        self.proc.kill()
        self.proc.wait(SLOW)

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            try:
                os.kill(self.proc.pid, signal.SIGCONT)
            except OSError:
                pass
            stop(self.proc, self.probe)
        elif self.probe is not None:
            self.probe.close()

    def quiet(self):
        """Every slot and address handed back: what clients hold and what the daemon counts agree at zero."""
        stats = self.probe.stats()
        assert stats["in_flight_addresses"] == 0, stats
        for net in NETS:
            assert self.probe.in_flight(f"{net}.1") == 0, (net, stats)


def still_there(d):
    """Wait until the daemon answers a ping, or has ended; it must not have ended."""
    until(lambda: d.proc.poll() is not None or d.probe.ping(), "the thawed daemon to answer", timeout=60)
    assert d.proc.poll() is None, f"the daemon ended with {d.proc.returncode} after it was thawed"


@pytest.fixture
def daemon(tmp_path):
    made = []

    def make(**kw):
        d = Daemon(tmp_path, **kw)
        made.append(d)
        return d
    yield make
    for d in made:
        d.stop()


class Fleet:
    def __init__(self, tmp_path, d, procs, threads, rounds, *, outage_limit=60.0, start_wait=0.0, max_wait=30.0, hold=0.01):
        self.tmp_path, self.d, self.procs, self.threads, self.rounds = tmp_path, d, procs, threads, rounds
        self.log = str(tmp_path / "contacts.log")
        Path(self.log).write_text("")
        self.outs = [str(tmp_path / f"out{i}.json") for i in range(procs)]
        self.args = (outage_limit, start_wait, max_wait, hold)
        self.workers = []

    def start(self):
        self.workers = [_spawn(_lookups, self.d.path, self.log, out, self.threads, self.rounds, CAP, GAP, *self.args, i)
                        for i, out in enumerate(self.outs)]

    def lines(self):
        return Path(self.log).read_text().count("\n")

    def wait(self, timeout=SLOW):
        for w in self.workers:
            w.join(timeout)
            assert w.exitcode == 0, w.exitcode
        return [json.loads(Path(out).read_text()) for out in self.outs]

    def alive(self):
        return any(w.is_alive() for w in self.workers)


def audit(log, cap=CAP, gap=GAP, slack=GAP / 3):
    """The contact log read back: no address twice within the pause, no network over its cap."""
    rows = [line.split() for line in Path(log).read_text().splitlines() if line.strip()]
    by_ip: dict[str, list[float]] = {}
    events: dict[str, list[tuple[float, int]]] = {}
    for t, sign, ip in rows:
        net = ip.rsplit(".", 1)[0]
        if sign == "+":
            by_ip.setdefault(ip, []).append(float(t))
        events.setdefault(net, []).append((float(t), 1 if sign == "+" else -1))
    for ip, times in by_ip.items():
        times.sort()
        for a, b in zip(times, times[1:]):
            assert b - a >= gap - slack, f"{ip} contacted twice within {b - a:.3f} s"
    for net, evs in events.items():
        open_now = peak = 0
        for _, delta in sorted(evs, key=lambda e: (e[0], e[1])):
            open_now += delta
            peak = max(peak, open_now)
        assert peak <= cap, f"{net} had {peak} open"
    return sum(len(v) for v in by_ip.values())


def expect_clean(results, total, log):
    """Every lookup went through, none was skipped, the rules held. Reports of how requests went are best effort when the
    daemon was away (those queued for it are dropped), so they are only counted by the tests that keep it up."""
    assert [r["errors"] for r in results] == [[]] * len(results), [r["errors"] for r in results]
    assert sum(r["ok"] for r in results) == total
    assert sum(r["busy"] + r["stopped"] for r in results) == 0
    assert sum(r["violations"] for r in results) == 0
    assert audit(log) == total


# ----------------------------------------------------------------------------------------- frozen, killed, restarted

def test_a_frozen_daemon_for_a_few_seconds_loses_nothing(tmp_path, daemon):
    d = daemon().start()
    fleet = Fleet(tmp_path, d, procs=3, threads=4, rounds=60, outage_limit=60.0, max_wait=30.0)
    fleet.start()
    until(lambda: fleet.lines() >= 60 and fleet.alive(), "the clients to be at work", timeout=60)
    d.freeze()                                                       # longer than a client waits for one reply
    time.sleep(5.0)
    d.thaw()
    still_there(d)
    results = fleet.wait()
    expect_clean(results, 3 * 4 * 60, fleet.log)
    assert sum(len(r["episodes"]) for r in results) >= 1             # the clients really did lose the daemon for a while
    d.quiet()


def test_a_daemon_stopped_and_continued_again_and_again_keeps_running(tmp_path, daemon):
    """A freeze longer than the time after which the daemon writes its thread stacks, ended with the clients still busy."""
    d = daemon().start()
    stop_work = threading.Event()

    rounds = [0]

    def work():
        k = LimiterClient(d.path, CAP, GAP, retry_after=0.05)
        while not stop_work.is_set():
            rounds[0] += 1
            k.ping()
            if k.try_acquire({NET: 1}, ips=[f"{NET}.1"]):
                k.release({NET: 1}, ips=[f"{NET}.1"])
            time.sleep(0.005)
        k.close()
    pool = [threading.Thread(target=work) for _ in range(4)]
    for t in pool:
        t.start()
    try:
        for cycle in range(8 if not FULL else 40):
            seen = rounds[0]
            until(lambda: rounds[0] > seen + 20, "the clients to be at work")
            d.freeze()
            time.sleep(limiterd.STALL_DUMP_AFTER + 0.8)          # the length of the freeze is what is tested
            d.thaw()
            still_there(d)
    finally:
        stop_work.set()
        for t in pool:
            t.join(30)


def test_a_daemon_killed_and_started_again_loses_nothing_and_clients_reconcile(tmp_path, daemon):
    d = daemon().start()
    fleet = Fleet(tmp_path, d, procs=3, threads=4, rounds=60, outage_limit=60.0, max_wait=30.0)
    fleet.start()
    until(lambda: fleet.lines() >= 60 and fleet.alive(), "the clients to be at work", timeout=60)
    d.kill()
    time.sleep(1.0)
    d.start(hold=1.5)                                                # the clients tell it what they hold within the hold
    results = fleet.wait()
    expect_clean(results, 3 * 4 * 60, fleet.log)
    assert sum(len(r["episodes"]) for r in results) >= 1
    d.quiet()


def test_a_daemon_killed_over_and_over_never_breaks_the_rules(tmp_path, daemon):
    d = daemon().start()
    fleet = Fleet(tmp_path, d, procs=2, threads=4, rounds=80, outage_limit=60.0, max_wait=30.0)
    fleet.start()
    rng = random.Random(3)
    kills = 0
    until(lambda: fleet.lines() >= 30 or not fleet.alive(), "the clients to be at work", timeout=60)
    while fleet.alive() and kills < 4:
        time.sleep(rng.uniform(0.5, 1.5))
        if not fleet.alive():
            break
        d.kill()
        kills += 1
        time.sleep(rng.uniform(0.0, 0.5))
        d.start(hold=1.0)
    results = fleet.wait()
    expect_clean(results, 2 * 4 * 80, fleet.log)
    assert kills >= 1
    d.quiet()


def test_an_outage_past_the_limit_raises_and_the_same_client_resumes(tmp_path, daemon):
    d = daemon().start()
    limiterclient.reset_failures()
    client = LimiterClient(d.path, CAP, GAP, outage_limit=1.5, io_timeout=0.5, retry_after=0.1)
    try:
        assert client.try_acquire({NET: 1}, ips=[f"{NET}.1"], exclusive=True)
        d.freeze()
        began = time.monotonic()
        with pytest.raises(LimiterOutage, match="unreachable"):
            while True:
                client.limit_for(f"{NET}.2")                  # a question, so nothing can be granted behind the client's back
                time.sleep(0.02)
                assert time.monotonic() - began < 30
        took = time.monotonic() - began
        assert 1.4 <= took < 6.0
        assert limiterclient.failure_kinds().get("limiter", 0) >= 1
        d.thaw()
        until(client.ping, "the client to find the daemon again", timeout=30, poll=0.05)
        assert not client.unreachable()
        client.release({NET: 1}, ips=[f"{NET}.1"])
        assert client.try_acquire({NET: 1}, ips=[f"{NET}.2"])
        client.release({NET: 1}, ips=[f"{NET}.2"])
    finally:
        limiterclient.reset_failures()
        client.close()
    d.quiet()


def test_workers_that_start_while_the_daemon_is_frozen_all_start_and_lose_nothing(tmp_path, daemon):
    d = daemon().start()
    d.freeze()
    fleet = Fleet(tmp_path, d, procs=8, threads=2, rounds=15, outage_limit=60.0, start_wait=60.0, max_wait=30.0)
    fleet.start()
    time.sleep(3.0)                                                  # long enough for every worker to try and wait
    assert fleet.alive()
    thawed = time.monotonic()
    d.thaw()
    results = fleet.wait()
    expect_clean(results, 8 * 2 * 15, fleet.log)
    first = min(float(l.split()[0]) for l in Path(fleet.log).read_text().splitlines())
    assert first >= thawed                                           # not one contact was made while the daemon was frozen
    d.quiet()


def test_a_start_wait_of_nothing_fails_at_once_while_the_daemon_is_frozen(tmp_path, daemon):
    d = daemon().start()
    d.freeze()
    try:
        client = LimiterClient(d.path, CAP, GAP, io_timeout=0.4, connect_timeout=0.4, hello_timeout=0.4, retry_after=0.05)
        began = time.monotonic()
        with pytest.raises(limiterclient.LimiterUnavailable):
            client.require()
        assert time.monotonic() - began < 3.0
    finally:
        d.thaw()


# ------------------------------------------------------------------------------------------------- crowds and CPU

def _hog(stop_path):
    end = time.monotonic() + 600
    while not os.path.exists(stop_path) and time.monotonic() < end:
        for _ in range(20000):
            pass


def _heavy_hello(path, stop_path, sizes):
    """A client that keeps declaring a very large state: hello frames of several megabytes, one connection each."""
    sent = 0
    while not os.path.exists(stop_path):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(60)
        try:
            s.connect(path)
            body = json.dumps({"op": "hello", "protocol": limiterd.PROTOCOL, "cap": CAP, "gap": GAP, "client": f"heavy-{os.getpid()}-{sent}",
                               "busy": ["203.0.113.250"] * sizes}, separators=(",", ":")).encode()
            s.sendall(len(body).to_bytes(4, "big") + body)
            recv_reply(s)
            s.sendall(limiterd.pack_frame({"op": "goodbye"}))
            recv_reply(s)
        except OSError:
            pass
        finally:
            s.close()
        sent += 1
        time.sleep(0.2)


def pings(path, seconds, every=0.02):
    client = LimiterClient(path, CAP, GAP, retry_after=0.05)
    rtts = []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        began = time.perf_counter()
        assert client.ping()
        rtts.append(time.perf_counter() - began)
        time.sleep(every)
    client.close()
    return rtts


def percentile(values, q):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def test_a_crowd_of_clients_with_cpu_hogs_and_huge_hellos_keeps_the_daemon_answering(tmp_path, daemon):
    d = daemon().start()
    procs, threads, rounds = (16, 8, 30) if FULL else (8, 4, 25)
    fleet = Fleet(tmp_path, d, procs=procs, threads=threads, rounds=rounds, outage_limit=60.0, max_wait=30.0)
    flag = str(tmp_path / "stop-hogs")
    hogs = [_spawn(_hog, flag) for _ in range(os.cpu_count() or 4)]
    heavy = _spawn(_heavy_hello, d.path, flag, 400_000)               # about 5 MB a hello
    rtts: list[float] = []
    try:
        fleet.start()
        end = time.monotonic() + (120 if FULL else 60)
        while fleet.alive() and time.monotonic() < end:
            rtts.extend(pings(d.path, 1.0))
        results = fleet.wait()
    finally:
        Path(flag).write_text("")
        for p in hogs + [heavy]:
            p.join(30)
            if p.is_alive():
                p.kill()
    assert len(rtts) > 20
    assert percentile(rtts, 0.999) < (1.0 if FULL else 3.0), (max(rtts), statistics.median(rtts))
    assert sum(r["lost"] + r["dropped"] for r in results) == 0           # no report was lost
    assert [r["errors"] for r in results] == [[]] * procs
    assert sum(r["violations"] for r in results) == 0
    assert sum(r["ok"] for r in results) + sum(r["busy"] for r in results) == procs * threads * rounds
    audit(fleet.log, slack=GAP / 2)
    stats = d.probe.stats()
    assert stats["largest_frame"] > 4_000_000                            # the huge hellos did arrive


def test_a_slow_sender_does_not_hold_up_the_others(tmp_path, daemon):
    d = daemon().start()
    done = {}

    def drip():
        s = raw_hello(d.path, cap=CAP, gap=GAP, client="slowpoke")
        events = [{"ip": f"{NET}.{i % 250 + 1}", "timeout": False, "http_status": 200, "retry_after": None} for i in range(7000)]
        body = json.dumps({"op": "observe", "events": events}, separators=(",", ":")).encode()
        data = len(body).to_bytes(4, "big") + body
        step = 20_000 if not FULL else 10_000
        for i in range(0, len(data), step):
            s.sendall(data[i:i + step])
            time.sleep(0.2 if not FULL else 0.1)
        done["reply"] = recv_reply(s)
        done["size"] = len(data)
        s.close()
    t = threading.Thread(target=drip)
    t.start()
    try:
        rtts = []
        while t.is_alive():
            rtts.extend(pings(d.path, 0.5, every=0.01))
    finally:
        t.join(120)
    assert done["reply"]["ok"] and done["size"] > 400_000
    assert len(rtts) > 20 and max(rtts) < 3.0, max(rtts)         # a held-up daemon would wait out the whole drip


# --------------------------------------------------------------------------------------------------- split frames

def _session(extra_garbage=False):
    return [{"op": "hello", "protocol": limiterd.PROTOCOL, "cap": 4, "gap": 0.4, "client": "fuzz"},
            {"op": "ping"}, {"op": "claim", "counts": {"198.51.100": 1}}, {"op": "query", "ip": "198.51.100.9"},
            {"op": "release", "counts": {"198.51.100": 1}}, {"op": "query", "ip": "198.51.100.9"},
            {"op": "observe", "events": [{"ip": "198.51.100.9", "timeout": False, "http_status": 200}] * 40},
            {"op": "ping"}, {"op": "goodbye"}]


def _run_session(path, rng, pieces):
    """The session of ``_session`` sent in the pieces ``pieces`` chooses; the replies in order."""
    data = b"".join(limiterd.pack_frame(m) for m in _session())
    cuts, at = [], 0
    while at < len(data):
        at += pieces(rng)
        cuts.append(min(at, len(data)))
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(path)
    last = 0
    for cut in cuts:
        s.sendall(data[last:cut])
        last = cut
        if rng.random() < 0.05:
            time.sleep(0.002)
    replies = []
    try:
        while True:
            replies.append(recv_reply(s))
    except (ConnectionError, OSError):
        pass
    s.close()
    return replies


def test_frames_split_anywhere_give_the_same_replies(tmp_path, daemon):
    d = daemon(cap=4, gap=0.4).start()
    rng = random.Random(11)
    whole = _run_session(d.path, rng, lambda r: 1 << 30)
    assert len(whole) == len(_session()) and whole[-1].get("close") and whole[2]["granted"]
    plans = [lambda r: 1, lambda r: 2, lambda r: 3, lambda r: r.choice((1, 4, 5, 9)), lambda r: r.randint(1, 60), lambda r: r.randint(1, 5000)]
    for case in range(60 if not FULL else 400):
        replies = _run_session(d.path, rng, plans[case % len(plans)])
        assert replies == whole, (case, replies)
    stats = d.probe.stats()
    assert stats["dropped_connections"] == 0 and stats["in_flight_addresses"] == 0


def test_bad_frames_cost_one_connection_and_nothing_else(tmp_path, daemon):
    d = daemon(cap=4, gap=0.4).start()
    rng = random.Random(5)
    for case in range(60):
        s = raw_hello(d.path, cap=4, gap=0.4)
        kind = case % 5
        if kind == 0:                                          # not JSON: told so, the connection stays
            s.sendall((9).to_bytes(4, "big") + b"not json!")
            assert recv_reply(s)["ok"] is False
            s.sendall(limiterd.pack_frame({"op": "ping"}))
            assert recv_reply(s)["ok"]
        elif kind == 1:                                        # JSON but not an object
            s.sendall((3).to_bytes(4, "big") + b"[1]")
            assert recv_reply(s)["ok"] is False
        elif kind == 2:                                        # an absurd length: the connection ends
            s.sendall(rng.randint(limiterd.MAX_FRAME + 1, 2 ** 32 - 1).to_bytes(4, "big"))
            assert s.recv(1) == b""
        elif kind == 3:                                        # a frame cut short, then silence and a close
            s.sendall((1000).to_bytes(4, "big") + b"{" * rng.randint(0, 900))
        else:                                                  # an unknown operation and a claim of the wrong type
            s.sendall(limiterd.pack_frame({"op": "nonsense"}))
            assert recv_reply(s)["ok"] is False
            s.sendall(limiterd.pack_frame({"op": "claim", "ips": "192.0.2.1"}))
            assert recv_reply(s)["ok"] is False
        s.close()
    probe = d.probe
    assert probe.ping() and probe.try_acquire({NET: 1}, ips=[f"{NET}.1"])
    probe.release({NET: 1}, ips=[f"{NET}.1"])
    d.quiet()


# --------------------------------------------------------------------------------------------------------- invariants

def test_nothing_is_sent_without_a_grant_while_the_daemon_is_out(tmp_path):
    sent = []
    for kind in ("absent", "hung"):
        path = tmp_path / f"{kind}.sock"
        close = _hung_server(path) if kind == "hung" else (lambda: None)
        client = make_client(path, io_timeout=0.1, retry_after=0.02, outage_limit=60.0)
        stop_event = threading.Event()
        threading.Timer(1.2, stop_event.set).start()
        verdicts = []

        def lookup(k):
            pacer = pacing.IpPacer(0.0, limiter=client, max_wait=0.3, poll=0.05, stop_event=stop_event)
            verdicts.append(pacer.admit(f"{NETS[k % 3]}.{k + 1}"))
            if verdicts[-1] == pacing.WAIT_OK:
                sent.append(k)
        pool = [threading.Thread(target=lookup, args=(k,)) for k in range(8)]
        for t in pool:
            t.start()
        for t in pool:
            t.join(30)
        close()
        client.close()
        assert verdicts == [pacing.WAIT_STOPPED] * 8
    assert sent == []


def test_state_errors_only_lean_toward_over_counting(tmp_path):
    s = Server(tmp_path / "lossy.sock", cap=3, gap=0.0).start()
    rng = random.Random(8)
    s.lose_reply = lambda op, req: op in ("claim", "release") and rng.random() < 0.2
    client = make_client(s.path, cap=3, gap=0.0, retry_after=0.01)
    nets = NETS[:2]
    held = {n: [] for n in nets}
    serial = iter(range(1, 10 ** 6))
    try:
        for _ in range(500):
            net = rng.choice(nets)
            if held[net] and rng.random() < 0.5:
                ip = held[net].pop()
                client.release({net: 1}, ips=[ip])
            else:
                ip = f"{net}.{next(serial) % 250 + 1}"
                if client.try_acquire({net: 1}, ips=[ip]):
                    held[net].append(ip)
            for n in nets:
                with s.lock:
                    daemon_side = s.core.limiter.in_flight(f"{n}.1")
                assert daemon_side >= client._held_counts.get(n, 0), (n, daemon_side, client._held_counts)
            time.sleep(0.005)
        s.lose_reply = None
        until(client.ping, "the client to reconnect", timeout=20, poll=0.02)
        for n in nets:
            client.release({n: len(held[n])}, ips=held[n])
        for n in nets:
            with s.lock:
                assert s.core.limiter.in_flight(f"{n}.1") == 0
        with s.lock:
            assert s.core.snapshot()["in_flight_addresses"] == 0
    finally:
        client.close()
        s.stop()


def test_the_outage_budget_stays_below_the_stall_rule_and_the_watchdog():
    budget = coordinator.LIMITER_START_WAIT + limiterclient.OUTAGE_LIMIT + max(coordinator.LIMITER_COOLDOWNS)
    assert coordinator.limiter_budget_seconds() == budget
    from scanner.internet.config import ScanConfig
    assert budget < ScanConfig.__dataclass_fields__["stall_minutes"].default * 60
    watchdog = (ROOT / "run" / "watchdog.sh").read_text()
    default = int(re.search(r'stale_min="\$\{STALE_MIN:-(\d+)\}"', watchdog).group(1))
    assert budget < default * 60


@pytest.mark.parametrize("clock_goes_back", [False, True])
def test_the_ledger_never_shortens_a_pause_and_never_lengthens_it_by_more_than_a_bucket(clock_goes_back):
    rng = random.Random(12)
    gap, width = 2.0, 0.5
    ledger = ContactBuckets(gap, width)
    last: dict[str, float] = {}
    now = high = 5000.0
    for step in range(20000):
        if clock_goes_back and rng.random() < 0.02:
            now -= rng.uniform(0, 0.4)
        else:
            now += rng.choice((0.0, 0.01, 0.2, 0.7))
        high = max(high, now)
        ip = rng.choice(ADDRESSES)
        if rng.random() < 0.4:
            ledger.add(ip, now)
            last[ip] = max(last.get(ip, now), now)
        if step % 7 == 0:
            ledger.prune(now)
        probe = rng.choice(ADDRESSES)
        due = ledger.due_in(probe, now)
        if probe in last:
            exact = max(0.0, last[probe] + gap - now)
            assert due >= exact - 1e-9, (probe, due, exact)             # never shorter, whatever the clock does
            if not clock_goes_back and exact > 0.0:
                assert due <= exact + width + 1e-9, (probe, due, exact)  # longer by less than a bucket


def test_a_grant_never_takes_a_network_over_its_current_limit():
    rng = random.Random(21)
    clock = Clock()
    core = LimiterCore(3, 0.0, now=clock, grace=0, bucket=0.1)
    conns = []
    for i in range(4):
        c = core.open()
        assert core.handle(c, {"op": "hello", "protocol": limiterd.PROTOCOL, "cap": 3, "gap": 0.0, "client": f"c{i}"})["ok"]
        conns.append(c)
    held = [{n: 0 for n in NETS} for _ in conns]
    for step in range(30000):
        clock.t += rng.choice((0.0, 0.05, 1.0, 40.0))
        who, net = rng.randrange(4), rng.choice(NETS)
        roll = rng.random()
        if roll < 0.45:
            reply = core.handle(conns[who], {"op": "claim", "counts": {net: 1}})
            if reply["granted"]:
                held[who][net] += 1
                assert core.limiter.in_flight(f"{net}.1") <= core.limiter.limit_for(f"{net}.1")
        elif roll < 0.8 and held[who][net]:
            core.handle(conns[who], {"op": "release", "counts": {net: 1}})
            held[who][net] -= 1
        elif roll < 0.9:
            core.handle(conns[who], {"op": "observe", "events": [{"ip": f"{net}.1", "timeout": True}] * rng.choice((1, 3))})
        else:
            core.handle(conns[who], {"op": "observe", "events": [{"ip": f"{net}.1", "http_status": rng.choice((200, 429, 503)), "retry_after": 2}]})
        assert core.limiter.in_flight(f"{net}.1") == sum(h[net] for h in held)
        assert core.limiter.in_flight(f"{net}.1") <= 3


# ------------------------------------------------------------------------------------- the reference implementation

class Side:
    """One core with its own clock and its connections, driven by a transcript."""

    def __init__(self, module, params):
        self.clock = Clock()
        self.core = module.LimiterCore(params["cap"], params["gap"], now=self.clock, bucket=params["bucket"], grace=params["grace"],
                                       lease_ttl=params["ttl"], startup_hold=0.0, max_hold=params["hold"])
        self.conns: dict[int, object] = {}
        self.params = params

    def connect(self, slot, client, held=None, busy=None, recent=None):
        conn = self.core.open()
        reply = self.core.handle(conn, {"op": "hello", "protocol": limiterd.PROTOCOL, "cap": self.params["cap"], "gap": self.params["gap"],
                                        "client": client, "held": held or {}, "busy": busy or [], "recent": recent or {}})
        self.conns[slot] = conn
        return reply

    def state(self):
        c = self.core
        nets = {n: (c.limiter.in_flight(f"{n}.1"), c.limiter.limit_for(f"{n}.1")) for n in NETS}
        conns = sorted((k, dict(v.counts), sorted(v.ips), sorted(v.tickets), v.closed, v.expired) for k, v in
                       ((conn.id, conn) for conn in c._conns.values()))
        due = [round(c.contacts.due_in(ip, self.clock.t), 9) for ip in ADDRESSES]
        return nets, dict(c._busy), conns, due


def random_request(rng):
    kind = rng.random()
    ips = rng.sample(ADDRESSES, rng.randint(1, 6))
    ticket = rng.choice((None, None, 1, 2, 3))
    if kind < 0.28:
        return {"op": "claim", "ips": ips, "partial": rng.random() < 0.5, "exclusive": rng.random() < 0.5, "ticket": ticket}
    if kind < 0.38:
        return {"op": "claim", "counts": {rng.choice(NETS): rng.randint(1, 2)}, "ticket": ticket}
    if kind < 0.58:
        return {"op": "release", "counts": {rng.choice(NETS): rng.randint(0, 2)}, "ips": ips if rng.random() < 0.7 else []}
    if kind < 0.63:
        return {"op": "withdraw", "ticket": rng.choice((1, 2, 3))}
    if kind < 0.80:
        events = [{"ip": rng.choice(ADDRESSES), "timeout": rng.random() < 0.3, "http_status": rng.choice((None, None, 200, 429, 503)),
                   "retry_after": rng.choice((None, 1.0, 5.0))} for _ in range(rng.randint(1, 5))]
        if rng.random() < 0.04:
            events.insert(rng.randrange(len(events) + 1), rng.choice(({"timeout": True}, "x", {"ip": "192.0.2.1", "retry_after": "soon"})))
        return {"op": "observe", "events": events}
    if kind < 0.90:
        return {"op": "query", "ip": rng.choice(ADDRESSES)}
    if kind < 0.95:
        return {"op": "ping"}
    if kind < 0.98:
        return {"op": "stats"}
    return {"op": "goodbye"}


def same_reply(a, b, op):
    if op == "stats":
        drop = {"ledger_addresses"}
        keys = set(a) - drop
        return keys <= set(b) and all(a[k] == b[k] for k in keys)
    return a == b


def differential(ref_module, new_module, operations, seed):
    rng = random.Random(seed)
    params = {"cap": 3, "gap": 2.0, "bucket": 0.5, "grace": 5.0, "ttl": 30.0, "hold": 20.0}
    ref, new = Side(ref_module, params), Side(new_module, params)
    slots = 5
    for s in range(slots):
        assert ref.connect(s, f"k{s}") == new.connect(s, f"k{s}")
    serial = 0
    for step in range(operations):
        roll = rng.random()
        if roll < 0.30:
            dt = rng.choice((0.0, 0.05, 0.4, 1.1, 2.5)) if rng.random() > 0.05 else rng.choice((-0.4, 45.0))
            ref.clock.t += dt
            new.clock.t += dt
            if rng.random() < 0.5:
                ref.core.sweep()
                new.core.sweep()
            continue
        slot = rng.randrange(slots)
        if roll < 0.34:                                           # the connection breaks and the client comes back, maybe with a state
            serial += 1
            held = {rng.choice(NETS): rng.randint(1, 2)} if rng.random() < 0.3 else {}
            busy = rng.sample(ADDRESSES, rng.randint(0, 3)) if rng.random() < 0.3 else []
            recent = {rng.choice(ADDRESSES): rng.uniform(0, 2.5)} if rng.random() < 0.4 else {}
            for side in (ref, new):
                side.core.close(side.conns[slot])
            client = f"k{slot}" if rng.random() < 0.7 else f"n{serial}"
            assert ref.connect(slot, client, held, busy, recent) == new.connect(slot, client, held, busy, recent), step
            continue
        req = random_request(rng)
        a, b = ref.core.handle(ref.conns[slot], req), new.core.handle(new.conns[slot], req)
        assert same_reply(a, b, req["op"]), (step, req, a, b)
        if req["op"] == "goodbye":
            for side in (ref, new):
                side.core.close(side.conns[slot])
            assert ref.connect(slot, f"k{slot}") == new.connect(slot, f"k{slot}")
        if step % 25 == 0:
            assert ref.state() == new.state(), step
    assert ref.state() == new.state()


def test_the_daemon_core_answers_like_the_reference_over_a_long_transcript(reference):
    began = time.monotonic()
    differential(reference, limiterd, 1_000_000 if FULL else 120_000, seed=17)
    print("differential run:", round(time.monotonic() - began, 1), "s")


def test_observe_with_and_without_a_back_off_record_matches_the_reference(reference):
    params = {"cap": 4, "gap": 0.0, "bucket": 1.0, "grace": 5.0, "ttl": 30.0, "hold": 20.0}
    ref, new = Side(reference, params), Side(limiterd, params)
    for side in (ref, new):
        side.connect(0, "a")
    ok = [{"ip": f"{NET}.{i}", "timeout": False, "http_status": 200, "retry_after": None} for i in range(1, 30)]
    steps = [("observe", ok), ("observe", ok),                               # no record: successes change nothing
             ("observe", [{"ip": f"{NET}.1", "timeout": True}] * 2), ("observe", ok),     # a streak of two, then answered: cleared
             ("observe", [{"ip": f"{NET}.1", "timeout": True}] * 3),                      # a back-off record appears
             ("observe", ok), ("observe", [{"ip": f"{NET}.1", "timeout": True}]),
             ("observe", [{"ip": f"{NET}.2", "timeout": True}, {"timeout": True}, {"ip": f"{NET}.3", "http_status": 429, "retry_after": 3}]),
             ("observe", [{"ip": f"{NET}.5", "http_status": 503, "retry_after": 2}]), ("observe", ok)]
    for i, (op, events) in enumerate(steps):
        a = ref.core.handle(ref.conns[0], {"op": op, "events": events})
        b = new.core.handle(new.conns[0], {"op": op, "events": events})
        assert a == b, (i, a, b)
        assert ref.state() == new.state(), i
        for side in (ref, new):
            side.clock.t += 7
        assert ref.state() == new.state(), i
        assert ref.core.limiter.tracked() == new.core.limiter.tracked()
    assert ref.core.limiter.limit_for(f"{NET}.1") == new.core.limiter.limit_for(f"{NET}.1")


# --------------------------------------------------------------------------------------------- a whole campaign

@full_only
def test_a_scaled_freeze_parks_a_stage_and_the_campaign_resumes(request):
    """A campaign whose limiter stops answering for longer than a worker waits: the stage is parked, not counted, and the
    campaign still finishes with every shard complete."""
    from tests.test_decoupled_e2e import PATIENCE, assert_complete, assert_polite, contacts, make_host, wait_for
    host = make_host("freeze", request)
    host.env.update(SCANNER_LIMITER_OUTAGE_LIMIT="3", SCANNER_LIMITER_START_WAIT="2")
    host.start_campaign()
    wait_for(lambda: any(c["stage"] == "network" for c in contacts(host.events())), PATIENCE, "a network contact")
    os.kill(host.limiter.pid, signal.SIGSTOP)
    time.sleep(12)
    os.kill(host.limiter.pid, signal.SIGCONT)
    rc = host.finish(1500)
    assert_complete(host, rc)
    stages = [s for e in host.state()["shard_states"].values() for s in e["stages"].values()]
    assert any(s.get("limiter_parks", 0) >= 1 for s in stages), "no stage was parked"
    assert all(s["attempts"] == 0 for s in stages)
    assert_polite(host.events())
