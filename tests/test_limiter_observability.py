"""The limiter daemon says what it is doing: a heartbeat, late wake-ups of its loop with the stacks behind them, slow
requests, dropped connections as counters, and a log that cannot stop the loop. Also the small command line that starts it."""
import asyncio
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from scanner.internet import limiterd
from scanner.internet.limiterclient import LimiterClient
from scanner.internet.limiterd import LimiterCore, LimiterServer
from tests.limiter_support import (deadline, make_client, old_env, old_tree, raw_hello, recv_exact, recv_reply, run_old,  # noqa: F401
                                   start_lean, stop)
from tests.test_limiterd import NET, ROOT, SLOW, unix_only, until
OTHER = "198.51.100"

pytestmark = unix_only
LOG = "scanner.internet.limiterd"


# ---------------------------------------------------------------------------------------------------- helpers

class Running:
    """A ``LimiterServer`` on an event loop of its own thread, so a test can block that loop and still talk to it."""

    def __init__(self, tmp_path, cap=4, gap=0.4, core_kw=None, name="run.sock", **server_kw):
        self.path = str(tmp_path / name)
        self.core = LimiterCore(cap, gap, **(core_kw or {}))
        server_kw.setdefault("heartbeat_every", 0)
        server_kw.setdefault("stall_dump_after", 0)
        server_kw.setdefault("stall_file", tmp_path / "run.stall")
        self.server = LimiterServer(self.core, self.path, **server_kw)
        self.loop = asyncio.new_event_loop()
        self._stop: asyncio.Event | None = None
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        asyncio.set_event_loop(self.loop)

        async def main():
            self._stop = asyncio.Event()
            try:
                await self.server.run(self._stop)
            except BaseException as exc:
                self.error = exc
        self.loop.run_until_complete(main())

    def __enter__(self):
        self.thread.start()
        until(lambda: os.path.exists(self.path) or self.error, "the server to listen", timeout=20)
        assert self.error is None, self.error
        return self

    def __exit__(self, *exc):
        if self._stop is not None:
            self.loop.call_soon_threadsafe(self._stop.set)
        self.thread.join(15)


def block_on(core, op, seconds, spin=False, mark=None, entered=None):
    """Make ``core.handle`` hold the loop for ``seconds`` when it sees a request of ``op`` that carries ``hold``."""
    real = core.handle

    def handle(conn, req):
        if req.get("op") == op and req.get("hold"):
            started = time.time()
            if entered is not None:
                entered.set()
            if spin:
                end = time.perf_counter() + seconds
                while time.perf_counter() < end:
                    pass
            else:
                time.sleep(seconds)
            if mark is not None:
                mark.append((started, time.time()))
        return real(conn, req)
    core.handle = handle


def records(caplog, text):
    return [r for r in caplog.records if r.name == LOG and text in r.getMessage()]


# ------------------------------------------------------------------------------------------------------ heartbeat

def test_heartbeat_line_is_logged_and_contains_the_counters(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger=LOG)
    with Running(tmp_path, heartbeat_every=0.3) as run:
        client = make_client(run.path)
        assert client.try_acquire({NET: 1}, ips=[f"{NET}.1"], exclusive=True)
        client.release({NET: 1}, ips=[f"{NET}.1"])
        for i in range(30):
            client.observe(f"{NET}.{i + 2}", timeout=False, http_status=200)
        client.flush(5)
        until(lambda: any("claim=1" in r.getMessage() for r in records(caplog, "heartbeat")), "a heartbeat that counts the claim", timeout=15)
        client.close()
    line = next(r.getMessage() for r in records(caplog, "heartbeat") if "claim=1" in r.getMessage())
    for field in ("up ", "connections ", "lingering ", "in_flight ", "waiting ", "requests ", "ops ", "claim=1", "release=1", "observe=",
                  "bytes_in ", "largest_frame ", "p99 ", "lag_max ", "reconnects ", "dropped ", "truncated ", "rss ", "cpu ", "log_dropped "):
        assert field in line, (field, line)


def test_stats_carry_the_additive_keys_and_old_ones_stay(tmp_path):
    with Running(tmp_path) as run:
        client = make_client(run.path)
        assert client.try_acquire({NET: 1}, ips=[f"{NET}.1"])
        stats = client.stats()
        client.close()
    assert "ok" not in stats
    for key in ("connections", "lingering", "networks_active", "networks_backoff", "in_flight_addresses", "ledger_addresses", "ledger_buckets",
                "waiting", "grants", "refused_full", "refused_gap", "expired", "stale_releases", "refused_startup", "adopted"):
        assert key in stats, key
    for key in ("uptime", "loop_lag_max_ms", "largest_frame", "rss_kb", "ops", "reconnects", "dropped_connections", "truncated_connections",
                "log_dropped"):
        assert key in stats, key
    assert stats["ops"]["hello"] >= 1 and stats["ops"]["claim"] == 1 and stats["largest_frame"] > 0 and stats["uptime"] >= 0


def test_a_hello_of_a_known_client_counts_as_a_reconnect(tmp_path):
    with Running(tmp_path) as run:
        client = make_client(run.path)
        assert client.ping()
        assert client.stats()["reconnects"] == 0
        client._sock.close()                                      # the connection breaks; the next call says hello again
        client._sock = None
        assert client.ping() and client.stats()["reconnects"] == 1
        client.close()


def test_the_heartbeat_is_the_loops_own_so_a_blocked_loop_leaves_a_gap(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger=LOG)
    seen = {}
    with Running(tmp_path, heartbeat_every=0.1, lag_tick=0.05, lag_warn=60.0) as run:
        real = run.core.handle

        def handle(conn, req):
            if req.get("hold"):
                seen["before"] = len(records(caplog, "heartbeat"))
                time.sleep(1.5)                                       # the loop is blocked: no task of it can write a line
                seen["during"] = len(records(caplog, "heartbeat"))
            return real(conn, req)
        run.core.handle = handle
        client = make_client(run.path, io_timeout=30.0)
        until(lambda: len(records(caplog, "heartbeat")) >= 3, "the heartbeat to run", timeout=15)
        assert client._call({"op": "ping", "hold": True}) is not None
        until(lambda: len(records(caplog, "heartbeat")) > seen["during"], "the heartbeat to resume", timeout=15)
        client.close()
    assert seen["during"] == seen["before"], "a heartbeat was written while the loop was blocked"


# ---------------------------------------------------------------------------------------------- the loop-lag probe

@pytest.mark.parametrize("spin, reading", [(False, None), (True, "computing")])
def test_loop_lag_is_detected_and_classified(spin, reading, tmp_path, caplog):
    caplog.set_level(logging.INFO, logger=LOG)
    stall = tmp_path / "stall.out"
    with Running(tmp_path, lag_tick=0.05, lag_warn=0.4, stall_dump_after=0.5, stall_file=stall, heartbeat_every=0.1) as run:
        block_on(run.core, "ping", 1.3, spin=spin)
        client = make_client(run.path, io_timeout=30.0)
        assert client.ping()
        until(lambda: records(caplog, "heartbeat"), "the loop's own tasks to be running", timeout=15)
        assert client._call({"op": "ping", "hold": True}) is not None
        until(lambda: records(caplog, "after a stall"), "the lag warning and the heartbeat that follows it", timeout=15)
        client.close()
    warnings = records(caplog, "event loop late")
    assert len(warnings) == 1
    text = warnings[0].getMessage()
    assert warnings[0].levelno == logging.WARNING
    for field in ("late by", "cpu ", "run-queue wait ", "page faults "):
        assert field in text, text
    lag = float(text.split("late by ")[1].split(" s")[0])
    assert 1.0 < lag < 30.0
    if reading:
        assert reading in text, text
    else:
        assert "the loop was computing" not in text, text
    dump = stall.read_text(errors="replace")
    assert "most recent call first" in dump and "handle" in dump       # the stack of the blocked thread
    assert str(stall) in text


def test_a_stall_file_that_has_grown_is_set_aside_at_the_start(tmp_path):
    stall = tmp_path / "stall.out"
    stall.write_bytes(b"x" * (limiterd.STALL_FILE_MAX + 10))
    with Running(tmp_path, stall_dump_after=0.5, stall_file=stall):
        until(lambda: stall.exists() and stall.stat().st_size < limiterd.STALL_FILE_MAX, "a fresh stall file")
    assert (tmp_path / "stall.out.1").stat().st_size > limiterd.STALL_FILE_MAX


# ----------------------------------------------------------------------------------------------- a stuck log stream

class Stuck(logging.Handler):
    """A log stream that has stopped taking writes."""

    def __init__(self):
        super().__init__()
        self.unblock = threading.Event()               # not ``release``: that is the name of the handler's own lock method
        self.entered = threading.Event()

    def emit(self, record):
        self.entered.set()
        self.unblock.wait(60)


def test_logging_does_not_block_the_loop_when_the_log_stream_blocks(tmp_path, monkeypatch):
    stuck = Stuck()
    logger = logging.getLogger("limiter.test.stuck")
    logger.propagate, logger.handlers = False, [stuck]
    logger.setLevel(logging.DEBUG)
    queued = limiterd.QueuedLogging(root=logger, size=40)
    monkeypatch.setattr(limiterd, "log", logger)
    monkeypatch.setattr(limiterd, "_queued", queued)
    worst = 0.0
    try:
        with Running(tmp_path, heartbeat_every=0.01, lag_tick=0.02, lag_warn=60.0) as run:
            client = make_client(run.path)
            assert stuck.entered.wait(10)                                # the writer is now stuck inside a write
            end = time.monotonic() + 1.5
            while time.monotonic() < end:
                began = time.monotonic()
                assert client.ping()
                worst = max(worst, time.monotonic() - began)
                time.sleep(0.01)
            stats = client.stats()
            client.close()
        assert worst < 0.25
        assert 0 < stats["log_dropped"] <= queued.dropped
    finally:
        stuck.unblock.set()                                     # the stuck write returns, so the writer thread can end
        until(queued.handler.queue.empty, "the writer to empty the queue", timeout=30)    # a full queue has no room for the stop marker
        queued.stop(timeout=10)
        queued.handler.close()
        logger.handlers = []
        stuck.close()


def test_queued_logging_hands_the_handlers_back(tmp_path):
    logger = logging.getLogger("limiter.test.handback")
    logger.propagate = False
    seen = []

    class Collect(logging.Handler):
        def emit(self, record):
            seen.append(record.getMessage())
    h = Collect()
    logger.handlers = [h]
    logger.setLevel(logging.INFO)
    q = limiterd.QueuedLogging(root=logger)
    try:
        logger.info("one")
        until(lambda: seen == ["one"], "the writer thread")
        q.stop()
        assert logger.handlers == [h]
        logger.info("two")
        assert seen == ["one", "two"]
    finally:
        q.handler.close()
        logger.handlers = []
        h.close()


# ------------------------------------------------------------------------- dropped connections and slow requests

def test_dropped_connections_are_summarised_not_logged_each(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger=LOG)
    with Running(tmp_path) as run:
        for _ in range(40):
            s = raw_hello(run.path)
            s.sendall((100).to_bytes(4, "big") + b"x" * 10)          # a frame that never finishes
            s.close()
        for _ in range(5):
            raw_hello(run.path).close()                                # a clean end is not a drop
        client = make_client(run.path)
        until(lambda: client.stats()["truncated_connections"] == 40, "the truncated frames to be counted")
        stats = client.stats()
        client.close()
    assert stats["dropped_connections"] == 40 and stats["truncated_connections"] == 40
    lines = records(caplog, "dropped")
    assert 1 <= len(lines) <= 2 and "dropped since the last example" in lines[0].getMessage()


def test_a_frame_over_the_limit_is_dropped_and_the_daemon_goes_on(tmp_path):
    with Running(tmp_path) as run:
        s = raw_hello(run.path)
        s.sendall((limiterd.MAX_FRAME + 1).to_bytes(4, "big"))
        assert s.recv(1) == b""
        s.close()
        client = make_client(run.path)
        assert client.ping() and client.stats()["dropped_connections"] == 1
        client.close()


def test_slow_request_is_logged_with_operation_and_size(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger=LOG)
    with Running(tmp_path, slow_request=0.05) as run:
        real = run.core.handle

        def slow(conn, req):
            if req.get("op") == "observe":
                time.sleep(0.08)
            return real(conn, req)
        run.core.handle = slow
        client = make_client(run.path)
        events = [{"ip": f"{NET}.{i + 1}", "timeout": False, "http_status": 200, "retry_after": None} for i in range(50)]
        began = time.monotonic()
        for _ in range(60):
            assert client._call({"op": "observe", "events": events})
        span = time.monotonic() - began
        time.sleep(1.1)                                                               # a new second: the line limit starts over
        assert client._call({"op": "ping", "pad": "x" * 300_000})                  # fast, but a big frame
        client.close()
    lines = [r.getMessage() for r in records(caplog, "slow request")]
    first = next(l for l in lines if "op=observe" in l)
    assert "items=50" in first and "bytes=" in first and "ms" in first
    assert 1 <= len([l for l in lines if "op=observe" in l]) < 60                # rate limited
    assert len([l for l in lines if "op=observe" in l]) <= 5 * (int(span) + 2)
    big = next(l for l in lines if "op=ping" in l)
    assert int(big.split("bytes=")[1].split()[0]) > 300_000


def test_frames_over_4_mib_that_are_not_a_hello_are_counted(tmp_path):
    with Running(tmp_path) as run:
        client = make_client(run.path, io_timeout=60.0)
        assert client._call({"op": "ping", "pad": "x" * (4 * 1024 * 1024 + 100)})
        assert client._call({"op": "ping"})
        assert run.core.metrics.big_frames == 1
        client.close()


# ---------------------------------------------------------------------------------------------------- the backlog

def test_a_daemon_with_a_backlog_of_300_unaccepted_connections_refuses_none(tmp_path):
    somaxconn = Path("/proc/sys/net/core/somaxconn")
    if somaxconn.exists() and int(somaxconn.read_text()) < 400:
        pytest.skip("the kernel limits the accept backlog below 400")
    with Running(tmp_path, lag_tick=0.5) as run:
        gate = threading.Event()
        block_on(run.core, "ping", 2.5, entered=gate)
        slow = make_client(run.path, io_timeout=30.0)
        assert slow.ping()
        holder = threading.Thread(target=lambda: slow._call({"op": "ping", "hold": True}), daemon=True)
        holder.start()
        assert gate.wait(30)                                            # the loop is now blocked inside the handler
        socks, refused = [], 0
        for _ in range(300):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(1.0)
            try:
                s.connect(run.path)
                s.sendall(limiterd.pack_frame({"op": "hello", "protocol": limiterd.PROTOCOL, "cap": 4, "gap": 0.4}))
                socks.append(s)
            except OSError:
                refused += 1
                s.close()
        holder.join(30)
        answered = 0
        for s in socks:
            try:
                s.settimeout(30)
                answered += bool(recv_reply(s)["ok"])
            except OSError:
                pass
            s.close()
        slow.close()
    assert refused == 0 and answered == 300


# --------------------------------------------------------------------------------- the small command line and parity

def test_lean_entry_imports_no_third_party_package(tmp_path):
    script = textwrap.dedent("""
        import json, runpy, sys
        sys.path.insert(0, sys.argv[1])
        sys.argv = ["limiterd", "--help"]
        try:
            runpy.run_module("scanner.internet.limiterd", run_name="__main__")
        except SystemExit:
            pass
        outside = []
        for name, mod in sorted(sys.modules.items()):
            path = getattr(mod, "__file__", None) or ""
            if "site-packages" in path or "dist-packages" in path:
                outside.append(name)
        print(json.dumps({"third": outside, "pipeline": "scanner.internet.pipeline" in sys.modules,
                          "yaml": "yaml" in sys.modules, "config": "scanner.internet.config" in sys.modules,
                          "count": len(sys.modules)}))
    """)
    out = subprocess.run([sys.executable, "-I", "-c", script, str(ROOT)], capture_output=True, text=True, timeout=SLOW, cwd=tmp_path)
    assert out.returncode == 0, out.stderr
    seen = json.loads(out.stdout.strip().splitlines()[-1])
    assert seen["third"] == [] and not seen["pipeline"] and not seen["yaml"] and not seen["config"], seen
    assert seen["count"] < 400


def test_lean_entry_starts_and_answers_ping(tmp_path):
    proc, path, probe = start_lean(tmp_path)
    try:
        assert probe.ping()
        assert oct(os.stat(path).st_mode & 0o777) == "0o660"
        stats = probe.stats()
        assert {"uptime", "ops", "largest_frame"} <= set(stats)
        assert probe.try_acquire({NET: 1}, ips=[f"{NET}.1"]) and probe.limit_for(f"{NET}.1") == 4
        again = subprocess.run([sys.executable, "-m", "scanner.internet.limiterd", "--socket", path], cwd=ROOT, capture_output=True,
                               text=True, timeout=SLOW)
        assert again.returncode == 2 and "already listening" in again.stderr
    finally:
        assert stop(proc, probe) == 0
    assert not os.path.exists(path)
    err = (tmp_path / "lean.sock.err").read_text()
    assert "limiter listening on" in err and "accept backlog" in err


def test_lean_entry_without_a_socket_is_refused(tmp_path):
    out = subprocess.run([sys.executable, "-m", "scanner.internet.limiterd"], cwd=ROOT, capture_output=True, text=True, timeout=SLOW)
    assert out.returncode == 2 and "--socket" in out.stderr


def test_the_probe_command_logs_round_trips_and_failures(tmp_path):
    proc, path, probe = start_lean(tmp_path)
    try:
        out = subprocess.run([sys.executable, "-m", "scanner.internet.limiterd", "probe", "--socket", path, "--interval", "0.05",
                              "--count", "3"], cwd=ROOT, capture_output=True, text=True, timeout=SLOW)
        assert out.returncode == 0
        assert out.stderr.count("probe ping") == 3 and "probe connected" in out.stderr
        assert probe.stats()["connections"] == 1                        # the probe's own connection is gone again
    finally:
        stop(proc, probe)
    gone = subprocess.run([sys.executable, "-m", "scanner.internet.limiterd", "probe", "--socket", path, "--interval", "0.05",
                           "--count", "2"], cwd=ROOT, capture_output=True, text=True, timeout=SLOW)
    assert gone.returncode == 0 and gone.stderr.count("probe failed") == 2


FLAGS = ["--max-connections-per-subnet", "3", "--retry-after-max-hold-seconds", "5", "--lease-ttl-seconds", "100",
         "--grace-seconds", "1", "--bucket-seconds", "0.1"]


def test_both_entry_points_accept_the_same_flags(tmp_path):
    helps = {}
    for label, entry in (("lean", ("-m", "scanner.internet.limiterd")), ("main", ("-m", "scanner.internet", "limiterd"))):
        out = subprocess.run([sys.executable, *entry, "--help"], cwd=ROOT, capture_output=True, text=True, timeout=SLOW)
        assert out.returncode == 0, out.stderr
        helps[label] = out.stdout
    lean_flags = {a for a in limiterd._daemon_parser()._option_string_actions if a.startswith("--") and a != "--help"}
    assert lean_flags >= {"--socket", "--config", "--max-connections-per-subnet", "--min-seconds-between-probes", "--lease-ttl-seconds",
                          "--grace-seconds", "--startup-hold-seconds", "--bucket-seconds", "--retry-after-max-hold-seconds"}
    for flag in lean_flags:
        assert flag in helps["main"], f"{flag} is not accepted by python -m scanner.internet limiterd"
    behaviour = {}
    for label, entry in (("lean", ("-m", "scanner.internet.limiterd")), ("main", ("-m", "scanner.internet", "limiterd"))):
        proc, path, probe = start_lean(tmp_path, *FLAGS, entry=entry, name=f"{label}.sock")
        try:
            loose = LimiterClient(path, 2, 0.4, retry_after=0.05)           # asks for a cap below the daemon's 3
            ok = LimiterClient(path, 3, 0.4, retry_after=0.05)
            try:
                loose.ping()
                refused = False
            except Exception as exc:
                refused = type(exc).__name__
            granted = [ok.try_acquire({NET: 1}, ips=[f"{NET}.{i}"]) for i in (1, 2, 3, 4)]
            behaviour[label] = (refused, granted, ok.limit_for(f"{NET}.1"), ok.stats()["refused_startup"])
            ok.close()
        finally:
            stop(proc, probe)
    assert behaviour["lean"] == behaviour["main"] == ("LimiterRefused", [True, True, True, False], 3, 0)


# ----------------------------------------------------------------------------------------- old clients, new numbers

def test_old_client_ignores_new_stats_keys(tmp_path, old_tree):
    proc, path, probe = start_lean(tmp_path)
    try:
        script = textwrap.dedent("""
            import sys
            from scanner.internet.limiterclient import LimiterClient
            c = LimiterClient(sys.argv[1], 4, 0.4)
            assert c.try_acquire({"192.0.2": 1}, ips=["192.0.2.5"], exclusive=True)
            st = c.stats()
            assert isinstance(st, dict) and "ok" not in st and st["connections"] >= 1 and st["ops"]["claim"] >= 1, st
            assert c.tracked() == (1, 0)
            c.release({"192.0.2": 1}, ips=["192.0.2.5"])
            assert c.in_flight("192.0.2.5") == 0 and c.limit_for("192.0.2.5") == 4
            c.close()
            print("fine")
        """)
        assert run_old(old_tree, script, path).strip() == "fine"
    finally:
        stop(proc, probe)


# ------------------------------------------------------------------------------------------- the client's own report

def test_client_episode_is_logged_with_duration_and_attempts(tmp_path, caplog):
    from tests.limiter_support import Server
    caplog.set_level(logging.INFO, logger="scanner.internet.limiterclient")
    path = tmp_path / "late.sock"
    late = Server(path)
    timer = threading.Timer(1.2, late.start)
    timer.start()
    client = make_client(path, retry_after=0.1)
    try:
        began = time.monotonic()
        until(client.ping, "the daemon to appear", timeout=30, poll=0.05)
        away = time.monotonic() - began
    finally:
        timer.cancel()
    lines = [r.getMessage() for r in caplog.records if "reachable again" in r.getMessage()]
    assert len(lines) == 1
    text = lines[0]
    seconds = float(text.split("after ")[1].split(" s")[0])
    attempts = int(text.split("and ")[1].split(" failed")[0])
    assert 1.0 <= seconds <= away + 0.1 and attempts >= 3
    assert "FileNotFoundError" in text or "No such file" in text
    episodes = client.episodes()
    assert len(episodes) == 1 and abs(episodes[0] - seconds) < 0.2
    client.close()
    late.stop()


def test_the_client_keeps_only_the_last_hundred_episodes(tmp_path):
    from tests.limiter_support import Jitter, Server
    from tests.test_limiterd import Clock
    clock = Clock()
    path = tmp_path / "flap.sock"
    client = make_client(path, now=clock, rng=Jitter(fixed=0.5), retry_after=0.01)
    s = Server(path).start()
    try:
        for i in range(130):
            clock.t += 100
            s.stop()
            assert not client.ping()                                  # down
            clock.t += 1 + i * 0.01
            s.start()
            assert client.ping()                                      # reachable again
        eps = client.episodes()
        assert len(eps) == 100 and eps[-1] > eps[0]
    finally:
        client.close()
        s.stop()


def test_the_client_prints_one_line_of_numbers_per_period(tmp_path, capsys, monkeypatch):
    from scanner.internet import limiterclient
    from tests.limiter_support import Server
    monkeypatch.setattr(limiterclient, "REPORT_EVERY", 0.2)
    s = Server(tmp_path / "r.sock").start()
    client = make_client(s.path)
    try:
        for _ in range(5):
            assert client.ping()
            time.sleep(0.12)
    finally:
        client.close()
        s.stop()
    err = capsys.readouterr().err
    lines = [l for l in err.splitlines() if l.startswith("limiter client ")]
    assert lines and all(f in lines[0] for f in ("calls=", "lock_wait=", "connect=", "send=", "recv=", "bytes_out=", "bytes_in=", "failures="))
