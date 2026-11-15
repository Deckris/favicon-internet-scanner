"""The progress heartbeat: ``_thread_activity``, ``_Stages.working``, ``begin_tail`` and the stall rule they feed."""
import ast
import builtins
import inspect
import io
import json
import os
import pathlib
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from scanner.internet import pipeline
from scanner.internet.config import load_config
from tests.test_scale import _cfg

HEARTBEAT = "work-heartbeat"
on_linux = pytest.mark.skipif(not sys.platform.startswith("linux") or not os.path.isdir("/proc/self/task"), reason="needs /proc")


# ---------------------------------------------------------------- helpers

def heartbeat_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == HEARTBEAT and t.is_alive()]


def wait_until(predicate, timeout=15.0, step=0.002) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(step)
    return predicate()


@pytest.fixture(autouse=True)
def no_leaked_helpers():
    """Every test ends with no heartbeat thread left running."""
    yield
    assert wait_until(lambda: not heartbeat_threads(), timeout=10), f"leaked helpers: {heartbeat_threads()}"


def make_stages(tmp_path, stall_seconds=None, executor=None):
    cfg = load_config(_cfg(tmp_path))
    st = pipeline._Stages(cfg, tmp_path, guards=False)
    if stall_seconds is not None:
        st.stall_seconds = stall_seconds
    st.executor = executor if executor is not None else SimpleNamespace(active_tools=0)
    return cfg, st


@pytest.fixture
def stages(tmp_path):
    return make_stages(tmp_path, stall_seconds=1800.0)[1]


class Probe:
    """A scripted stand-in for ``_thread_activity``: the reading of each thread id is whatever the test set."""

    def __init__(self):
        self.values: dict[int, tuple[int, int]] = {}
        self.calls: list[int] = []
        self.fail: BaseException | None = None
        self.gate: threading.Event | None = None

    def __call__(self, tid):
        self.calls.append(tid)
        if self.gate is not None and len(self.calls) > 1:
            self.gate.wait(30)
        if self.fail is not None:
            raise self.fail
        return self.values.get(tid, (0, 0))

    def bump(self, tid=None, cpu=1, moved=0):
        tid = threading.get_native_id() if tid is None else tid
        c, m = self.values.get(tid, (0, 0))
        self.values[tid] = (c + cpu, m + moved)


@pytest.fixture
def probe(monkeypatch):
    p = Probe()
    monkeypatch.setattr(pipeline, "_thread_activity", p)
    return p


class FakeClock:
    """Replaces the ``time`` module of the pipeline; unknown attributes fall through to the real one."""

    def __init__(self, now=1000.0, cpu=0.0):
        self.now = now
        self.cpu = cpu

    def monotonic(self):
        return self.now

    def process_time(self):
        return self.cpu

    def __getattr__(self, name):
        return getattr(time, name)


@pytest.fixture
def clock(monkeypatch):
    c = FakeClock()
    monkeypatch.setattr(pipeline, "time", c)
    return c


def counting_progress(st):
    """Count the progress calls per calling thread name."""
    seen: list[str] = []
    real = st.progress

    def progress():
        seen.append(threading.current_thread().name)
        real()
    st.progress = progress
    return seen


class FakeProc:
    """Serves files under /proc/self/task from a dict; everything else opens normally."""

    def __init__(self, monkeypatch, files):
        self.files = files
        self.opened: list[tuple[str, str]] = []
        real = builtins.open

        def fake(path, mode="r", *a, **k):
            p = str(path).replace("\\", "/")
            if p.startswith("/proc/self/task/"):
                self.opened.append((p, mode))
                if p not in self.files:
                    raise FileNotFoundError(p)
                content = self.files[p]
                if isinstance(content, BaseException):
                    raise content
                return io.BytesIO(content)
            return real(path, mode, *a, **k)
        monkeypatch.setattr(builtins, "open", fake)


def stat_line(tid, comm, utime, stime, state="S"):
    return (f"{tid} ({comm}) {state} 1 {tid} {tid} 0 -1 4194560 120 0 3 0 {utime} {stime} 0 0 20 0 4 0 91234 "
            f"123456789 5000 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 2 0 0 0 0 0").encode()


def io_text(rchar=0, wchar=0, **extra):
    fields = {"rchar": rchar, "wchar": wchar, "syscr": 7, "syscw": 9, "read_bytes": 4096, "write_bytes": 8192,
              "cancelled_write_bytes": 0}
    fields.update(extra)
    return "".join(f"{k}: {v}\n" for k, v in fields.items()).encode()


def proc_files(tid, stat=None, io_=None):
    return {f"/proc/self/task/{tid}/stat": stat if stat is not None else stat_line(tid, "python", 10, 5),
            f"/proc/self/task/{tid}/io": io_ if io_ is not None else io_text(100, 50)}


# ---------------------------------------------------------------- _thread_activity: parsing

@pytest.mark.parametrize("comm", ["python", "a b", "a b) c", "x)y)", "(weird)", "tab\tname", "((", "))", "é-name", ""])
def test_activity_parses_stat_whatever_the_thread_name_holds(monkeypatch, comm):
    proc = FakeProc(monkeypatch, proc_files(77, stat=stat_line(77, comm, 123, 456), io_=io_text(1000, 234)))
    assert pipeline._thread_activity(77) == (123 + 456, 1234)
    assert [p for p, _ in proc.opened] == ["/proc/self/task/77/stat", "/proc/self/task/77/io"]


def test_activity_reads_the_files_of_the_asked_thread_in_binary_mode(monkeypatch):
    proc = FakeProc(monkeypatch, proc_files(4242))
    pipeline._thread_activity(4242)
    assert proc.opened == [("/proc/self/task/4242/stat", "rb"), ("/proc/self/task/4242/io", "rb")]


def test_activity_of_a_thread_name_with_parentheses_and_spaces(monkeypatch):
    raw = b"123 (a b) c) S 1 123 123 0 -1 4194560 120 0 3 0 40 2 0 0 20 0 1 0 5 6 7"
    FakeProc(monkeypatch, proc_files(123, stat=raw, io_=io_text(10, 20)))
    assert pipeline._thread_activity(123) == (42, 30)


def test_activity_adds_user_and_system_time(monkeypatch):
    FakeProc(monkeypatch, proc_files(5, stat=stat_line(5, "t", 0, 9)))
    assert pipeline._thread_activity(5)[0] == 9
    FakeProc(monkeypatch, proc_files(5, stat=stat_line(5, "t", 9, 0)))
    assert pipeline._thread_activity(5)[0] == 9


def test_activity_counts_only_rchar_and_wchar(monkeypatch):
    text = io_text(rchar=10, wchar=5, read_bytes=999999, write_bytes=888888, syscr=77777, syscw=66666)
    FakeProc(monkeypatch, proc_files(5, io_=text))
    assert pipeline._thread_activity(5)[1] == 15


@pytest.mark.parametrize("text, expected", [
    (b"", 0),
    (b"syscr: 5\nsyscw: 6\n", 0),
    (b"rchar: 7\n", 7),
    (b"wchar: 9\n", 9),
    (b"wchar: 9\nrchar: 7\n", 16),
    (b"rchar:5\nwchar:6\n", 11),
    (b"rchar:   5   \nwchar:\t6\n", 11),
    (b"rchar: 0\nwchar: 0\n", 0),
    (b"rchar: 18446744073709551615\nwchar: 1\n", 18446744073709551616),
    (b"RCHAR: 5\n", 0),
    (b"xrchar: 5\nrcharx: 6\n", 0),
    (b"rchar: 5\nrchar: 5\n", 10),
    (b"no colon here\nrchar: 3\n", 3),
])
def test_activity_io_parsing_cases(monkeypatch, text, expected):
    FakeProc(monkeypatch, proc_files(5, io_=text))
    assert pipeline._thread_activity(5) == (15, expected)


def test_activity_returns_a_tuple_of_two_ints(monkeypatch):
    FakeProc(monkeypatch, proc_files(5))
    got = pipeline._thread_activity(5)
    assert isinstance(got, tuple) and len(got) == 2 and all(type(v) is int for v in got)


def test_activity_of_an_idle_thread_is_stable_between_reads(monkeypatch):
    FakeProc(monkeypatch, proc_files(5))
    assert pipeline._thread_activity(5) == pipeline._thread_activity(5)


def test_activity_changes_when_cpu_changes(monkeypatch):
    FakeProc(monkeypatch, proc_files(5, stat=stat_line(5, "t", 1, 1)))
    first = pipeline._thread_activity(5)
    FakeProc(monkeypatch, proc_files(5, stat=stat_line(5, "t", 2, 1)))
    assert pipeline._thread_activity(5) != first


def test_activity_changes_when_bytes_change(monkeypatch):
    FakeProc(monkeypatch, proc_files(5, io_=io_text(1, 1)))
    first = pipeline._thread_activity(5)
    FakeProc(monkeypatch, proc_files(5, io_=io_text(1, 2)))
    assert pipeline._thread_activity(5) != first


# ---------------------------------------------------------------- _thread_activity: fallback

def fallback_value(clock_cpu):
    return (int(clock_cpu * 1000), 0)


@pytest.mark.parametrize("files", [
    {},                                                                                 # neither file
    {"/proc/self/task/5/io": io_text(1, 1)},                                            # stat missing
    {"/proc/self/task/5/stat": PermissionError(13, "denied"), "/proc/self/task/5/io": io_text(1, 1)},
    {"/proc/self/task/5/stat": ProcessLookupError(3, "gone"), "/proc/self/task/5/io": io_text(1, 1)},
    {"/proc/self/task/5/stat": OSError(5, "I/O error"), "/proc/self/task/5/io": io_text(1, 1)},
], ids=["no-files", "no-stat", "stat-denied", "thread-gone", "stat-eio"])
def test_activity_falls_back_when_the_stat_file_cannot_be_read(monkeypatch, clock, files):
    clock.cpu = 3.5
    FakeProc(monkeypatch, files)
    assert pipeline._thread_activity(5) == fallback_value(3.5)


@pytest.mark.parametrize("files", [
    {"/proc/self/task/5/stat": stat_line(5, "t", 1, 1)},                                # io missing
    {"/proc/self/task/5/stat": stat_line(5, "t", 1, 1), "/proc/self/task/5/io": PermissionError(13, "denied")},
    {"/proc/self/task/5/stat": stat_line(5, "t", 1, 1), "/proc/self/task/5/io": IsADirectoryError(21, "dir")},
], ids=["no-io", "io-denied", "io-is-dir"])
def test_activity_keeps_the_thread_cpu_when_only_the_io_file_cannot_be_read(monkeypatch, clock, files):
    clock.cpu = 3.5
    FakeProc(monkeypatch, files)
    assert pipeline._thread_activity(5) == (2, 0)                  # the ticks of the thread, not the clock of the process


@pytest.mark.parametrize("stat", [
    b"",                                                            # nothing at all
    b"no closing parenthesis S 1 2 3",                              # no ')'
    b"5 (t) S 1 5 5 0 -1 4194560 120 0 3 0 40",                     # stops before stime
    b"5 (t)",                                                       # nothing after the name
    b"5 (t) S 1",                                                   # far too short
    b"5 (t) " + b"S " + b"0 " * 10,                                 # one field short
], ids=["empty", "no-paren", "no-stime", "name-only", "short", "off-by-one"])
def test_activity_falls_back_on_truncated_stat(monkeypatch, clock, stat):
    clock.cpu = 1.0
    FakeProc(monkeypatch, proc_files(5, stat=stat))
    assert pipeline._thread_activity(5) == fallback_value(1.0)


@pytest.mark.parametrize("bad", [b"abc", b"1.5", b"-", b"0x10", b"", b"\xff\xfe", b"1e3"])
def test_activity_falls_back_on_malformed_cpu_numbers(monkeypatch, clock, bad):
    clock.cpu = 2.0
    stat = b"5 (t) S 1 5 5 0 -1 4194560 120 0 3 0 " + bad + b" 7 0 0 20 0"
    FakeProc(monkeypatch, proc_files(5, stat=stat))
    got = pipeline._thread_activity(5)
    if bad == b"":                                                  # the empty field simply shifts the later ones
        assert got == (7, 150)
    else:
        assert got == fallback_value(2.0)


@pytest.mark.parametrize("line", [b"rchar: abc\n", b"wchar: \n", b"rchar: 1.5\n", b"wchar: 0x5\n", b"rchar: 12 13\n", b"wchar: --4\n"])
def test_activity_keeps_the_thread_cpu_on_malformed_io_numbers(monkeypatch, clock, line):
    clock.cpu = 4.0
    FakeProc(monkeypatch, proc_files(5, io_=line))
    assert pipeline._thread_activity(5) == (15, 0)


def test_activity_is_not_the_process_clock_while_stat_is_readable(monkeypatch, clock):
    clock.cpu = 9.0
    FakeProc(monkeypatch, proc_files(5, stat=stat_line(5, "t", 1000, 1000), io_=b"rchar: nope\n"))
    assert pipeline._thread_activity(5) == (2000, 0)               # the ticks read from stat, not the 9000 of the clock


@pytest.mark.parametrize("cpu, expected", [(0.0, 0), (0.0004, 0), (0.001, 1), (1.2349, 1234), (86400.0, 86_400_000), (2.5, 2500)])
def test_activity_fallback_is_whole_milliseconds(monkeypatch, clock, cpu, expected):
    clock.cpu = cpu
    FakeProc(monkeypatch, {})
    got = pipeline._thread_activity(5)
    assert type(got[0]) is int and got[1] == 0
    assert abs(got[0] - expected) <= 1


def test_activity_fallback_never_goes_backwards(monkeypatch):
    FakeProc(monkeypatch, {})
    seen = []
    end = time.monotonic() + 0.3
    while time.monotonic() < end:
        seen.append(pipeline._thread_activity(1))
    assert seen == sorted(seen)
    assert all(m == 0 for _, m in seen)


def test_activity_fallback_detects_cpu_work(monkeypatch):
    FakeProc(monkeypatch, {})
    first = pipeline._thread_activity(1)
    end = time.monotonic() + 15
    changed = False
    while time.monotonic() < end and not changed:
        sum(i * i for i in range(200_000))
        changed = pipeline._thread_activity(1) != first
    assert changed


def test_activity_follows_the_clock_only_in_the_fallback(monkeypatch, clock):
    FakeProc(monkeypatch, proc_files(5))
    clock.cpu = 100.0
    assert pipeline._thread_activity(5) == (15, 150)               # /proc wins, the clock is not consulted


# ---------------------------------------------------------------- _thread_activity: the real /proc

@on_linux
def test_real_activity_of_the_current_thread():
    cpu, moved = pipeline._thread_activity(threading.get_native_id())
    assert cpu >= 0 and moved >= 0 and type(cpu) is int and type(moved) is int


@on_linux
def test_real_activity_cpu_grows_with_computation():
    tid = threading.get_native_id()
    first = pipeline._thread_activity(tid)
    end = time.monotonic() + 15
    now = first
    while now[0] == first[0] and time.monotonic() < end:
        sum(i * i for i in range(300_000))
        now = pipeline._thread_activity(tid)
    assert now[0] > first[0]


@on_linux
def test_real_activity_io_grows_with_writes_and_reads(tmp_path):
    tid = threading.get_native_id()
    if not pathlib.Path(f"/proc/self/task/{tid}/io").exists():
        pytest.skip("no per-thread io accounting")
    path = tmp_path / "blob"
    before = pipeline._thread_activity(tid)
    path.write_bytes(b"x" * 200_000)
    mid = pipeline._thread_activity(tid)
    assert mid[1] - before[1] >= 200_000
    assert len(path.read_bytes()) == 200_000
    after = pipeline._thread_activity(tid)
    assert after[1] - mid[1] >= 200_000


@on_linux
def test_real_activity_of_a_blocked_thread_stays_put():
    ready, release = threading.Event(), threading.Event()
    tids = []

    def blocked():
        tids.append(threading.get_native_id())
        ready.set()
        release.wait(30)
    t = threading.Thread(target=blocked)
    t.start()
    try:
        assert ready.wait(10)
        first = pipeline._thread_activity(tids[0])
        time.sleep(0.3)
        assert pipeline._thread_activity(tids[0]) == first
    finally:
        release.set()
        t.join(10)


@on_linux
def test_real_activity_of_a_thread_that_has_ended_falls_back():
    tids = []
    t = threading.Thread(target=lambda: tids.append(threading.get_native_id()))
    t.start()
    t.join(10)
    got = pipeline._thread_activity(tids[0])
    assert type(got[0]) is int and got[1] == 0


@on_linux
def test_real_activity_of_one_thread_ignores_another_threads_work():
    stop = threading.Event()
    tids = []
    ready = threading.Event()

    def idle():
        tids.append(threading.get_native_id())
        ready.set()
        stop.wait(30)
    t = threading.Thread(target=idle)
    t.start()
    try:
        assert ready.wait(10)
        first = pipeline._thread_activity(tids[0])
        end = time.monotonic() + 0.4
        while time.monotonic() < end:
            sum(i * i for i in range(50_000))                      # busy here, not there
        assert pipeline._thread_activity(tids[0]) == first
    finally:
        stop.set()
        t.join(10)


# ---------------------------------------------------------------- working(): basics

def test_working_ticks_when_the_thread_is_active(stages, probe):
    base = stages._progress
    with stages.working(interval=0.01):
        assert wait_until(lambda: (probe.bump(), stages._progress - base)[1] >= 3)
    assert stages._progress - base >= 3


def test_working_does_not_tick_while_the_reading_is_constant(stages, probe):
    base = stages._progress
    with stages.working(interval=0.01):
        assert wait_until(lambda: len(probe.calls) >= 8)           # eight looks, none of them saw a change
        assert stages._progress == base
    assert stages._progress == base + 1                             # only the final report


def test_working_ticks_from_the_helper_thread_not_the_caller(stages, probe):
    names = counting_progress(stages)
    with stages.working(interval=0.01):
        wait_until(lambda: (probe.bump(), HEARTBEAT in names)[1])
    assert HEARTBEAT in names
    assert names[-1] == threading.current_thread().name            # the exit report comes from the caller


def test_working_ticks_once_per_look_at_most(stages, probe):
    names = counting_progress(stages)
    with stages.working(interval=0.05):
        probe.bump()
        assert wait_until(lambda: len(probe.calls) >= 6)
        ticks = names.count(HEARTBEAT)
    assert ticks <= 1                                              # one change, one tick, however many looks follow


@pytest.mark.parametrize("bumps", [1, 2, 5])
def test_working_ticks_once_per_change(stages, probe, bumps):
    names = counting_progress(stages)
    with stages.working(interval=0.02):
        for _ in range(bumps):
            before = len(probe.calls)
            probe.bump()
            assert wait_until(lambda: len(probe.calls) >= before + 2)
        ticks = names.count(HEARTBEAT)
    assert 1 <= ticks <= bumps


def test_working_ticks_on_io_only_changes(stages, probe):
    base = stages._progress
    with stages.working(interval=0.01):
        assert wait_until(lambda: (probe.bump(cpu=0, moved=4096), stages._progress - base)[1] >= 2)


def test_working_ticks_on_cpu_only_changes(stages, probe):
    base = stages._progress
    with stages.working(interval=0.01):
        assert wait_until(lambda: (probe.bump(cpu=1, moved=0), stages._progress - base)[1] >= 2)


def test_working_stops_ticking_when_the_thread_goes_idle(stages, probe):
    base = stages._progress
    with stages.working(interval=0.01):
        assert wait_until(lambda: (probe.bump(), stages._progress - base)[1] >= 2)
        time.sleep(0.1)                                             # let in-flight looks finish
        quiet = stages._progress
        calls = len(probe.calls)
        assert wait_until(lambda: len(probe.calls) >= calls + 6)
        assert stages._progress == quiet


def test_working_final_report_on_exit(stages, probe):
    base = stages._progress
    with stages.working(interval=0.5):
        pass
    assert stages._progress == base + 1


def test_working_final_report_comes_after_the_helper_has_ended(stages, probe):
    with stages.working(interval=0.01):
        probe.bump()
    after = stages._progress
    for _ in range(20):
        probe.bump()
        time.sleep(0.005)
    assert stages._progress == after


def test_working_helper_is_a_named_daemon(stages, probe):
    with stages.working(interval=0.5):
        found = heartbeat_threads()
        assert len(found) == 1 and found[0].daemon and found[0].name == HEARTBEAT
    assert not heartbeat_threads()


def test_working_probes_the_calling_thread_only(stages, probe):
    me = threading.get_native_id()
    with stages.working(interval=0.01):
        assert wait_until(lambda: len(probe.calls) >= 4)
    assert set(probe.calls) == {me}


def test_working_takes_its_first_reading_at_entry(stages, probe):
    with stages.working(interval=30):
        assert wait_until(lambda: len(probe.calls) >= 1)
        assert len(probe.calls) == 1                                 # then it sleeps for the interval


def test_working_returns_promptly_even_with_a_long_interval(stages, probe):
    t = time.monotonic()
    with stages.working(interval=3600):
        pass
    assert time.monotonic() - t < 60


@pytest.mark.parametrize("exc", [ValueError("x"), RuntimeError("y"), KeyError("z"), KeyboardInterrupt(), SystemExit(3), OSError(5, "io")])
def test_working_propagates_exceptions_and_still_cleans_up(stages, probe, exc):
    base = stages._progress
    with pytest.raises(type(exc)):
        with stages.working(interval=0.02):
            raise exc
    assert not heartbeat_threads()
    assert stages._progress == base + 1


def test_working_does_not_swallow_a_return_value_path(stages, probe):
    def step():
        with stages.working(interval=0.02):
            return 42
    assert step() == 42
    assert not heartbeat_threads()


def test_working_in_a_generator_closed_early(stages, probe):
    def gen():
        with stages.working(interval=0.02):
            yield 1
            yield 2
    g = gen()
    assert next(g) == 1
    assert len(heartbeat_threads()) == 1
    g.close()
    assert not heartbeat_threads()


# ---------------------------------------------------------------- working(): interval selection

@pytest.fixture
def waits(monkeypatch):
    """Record the timeouts that heartbeat helpers wait with."""
    seen: list[float] = []
    real = threading.Event

    class Recording(real):
        def wait(self, timeout=None):
            if threading.current_thread().name == HEARTBEAT and timeout is not None:
                seen.append(timeout)
            return super().wait(timeout)
    monkeypatch.setattr(threading, "Event", Recording)
    return seen


@pytest.mark.parametrize("stall, expected", [
    (1800.0, 30.0),             # the default limit: capped by WORK_TICK
    (120.0, 30.0),              # a quarter is exactly the cap
    (40.0, 10.0),               # a quarter of the limit
    (4.0, 1.0),
    (1.0, 0.25),
    (0.4, 0.1),
    (0.2, 0.05),                # exactly the floor
    (0.1, 0.05),                # below the floor
    (1e-9, 0.05),               # absurdly small limit
    (1e12, 30.0),               # absurdly large limit
    (0, 30.0),                  # switched off
    (-1, 30.0),
    (-1e9, 30.0),
])
def test_working_default_interval(tmp_path, probe, waits, stall, expected):
    _, st = make_stages(tmp_path, stall_seconds=stall)
    with st.working():
        assert wait_until(lambda: bool(waits))
    assert waits[0] == pytest.approx(expected)


@pytest.mark.parametrize("interval", [0.01, 0.2, 7, 123.5])
def test_working_explicit_interval_wins(tmp_path, probe, waits, interval):
    _, st = make_stages(tmp_path, stall_seconds=1.0)
    with st.working(interval=interval):
        assert wait_until(lambda: bool(waits))
    assert waits[0] == interval


def test_working_follows_the_module_constant(tmp_path, probe, waits, monkeypatch):
    monkeypatch.setattr(pipeline, "WORK_TICK", 7.0)
    _, st = make_stages(tmp_path, stall_seconds=1e6)
    with st.working():
        assert wait_until(lambda: bool(waits))
    assert waits[0] == 7.0


def test_working_reads_the_stall_limit_when_the_block_starts(tmp_path, probe, waits):
    _, st = make_stages(tmp_path, stall_seconds=1e6)
    st.stall_seconds = 2.0
    with st.working():
        assert wait_until(lambda: bool(waits))
    assert waits[0] == pytest.approx(0.5)


# ---------------------------------------------------------------- working(): nesting, threads, probes

def test_nested_blocks_each_run_a_helper_and_both_end(stages, probe):
    base = stages._progress
    with stages.working(interval=0.5):
        with stages.working(interval=0.5):
            assert len(heartbeat_threads()) == 2
        assert len(heartbeat_threads()) == 1
        assert stages._progress == base + 1                         # the inner exit
    assert not heartbeat_threads()
    assert stages._progress == base + 2


def test_nested_blocks_inner_exception_closes_both(stages, probe):
    with pytest.raises(RuntimeError):
        with stages.working(interval=0.5):
            with stages.working(interval=0.5):
                raise RuntimeError("inner")
    assert not heartbeat_threads()


def test_nested_blocks_tick_independently_of_each_other(stages, probe):
    base = stages._progress
    with stages.working(interval=0.01):
        with stages.working(interval=0.01):
            assert wait_until(lambda: (probe.bump(), stages._progress - base)[1] >= 4)


def test_many_sequential_blocks_reuse_nothing(stages, probe):
    for _ in range(25):
        with stages.working(interval=0.5):
            assert len(heartbeat_threads()) == 1
    assert not heartbeat_threads()


def test_each_thread_watches_its_own_thread_id(stages, probe):
    ids, barrier = {}, threading.Barrier(4)

    def worker(n):
        ids[n] = threading.get_native_id()
        with stages.working(interval=0.01):
            barrier.wait(15)
            assert wait_until(lambda: len(set(probe.calls) & set(ids.values())) >= 3)
            barrier.wait(15)
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(3)]
    for t in threads:
        t.start()
    me = threading.get_native_id()
    ids["main"] = me
    with stages.working(interval=0.01):
        barrier.wait(15)
        assert len(heartbeat_threads()) == 4
        barrier.wait(15)
    for t in threads:
        t.join(15)
    assert set(probe.calls) >= set(ids.values())
    assert len(set(ids.values())) == 4


def test_only_the_busy_thread_makes_the_run_tick(stages, probe):
    busy, idle = threading.Event(), threading.Event()
    release = threading.Event()
    tids = {}

    def worker(name, ev):
        tids[name] = threading.get_native_id()
        with stages.working(interval=0.01):
            ev.set()
            release.wait(30)
    ts = [threading.Thread(target=worker, args=("busy", busy)), threading.Thread(target=worker, args=("idle", idle))]
    for t in ts:
        t.start()
    assert busy.wait(10) and idle.wait(10)
    try:
        base = stages._progress
        time.sleep(0.15)
        assert stages._progress == base                              # nobody is active: nobody ticks
        assert wait_until(lambda: (probe.bump(tids["busy"]), stages._progress - base)[1] >= 2)
    finally:
        release.set()
        for t in ts:
            t.join(15)


def test_working_from_a_non_main_thread(stages, probe):
    result = {}

    def worker():
        tid = threading.get_native_id()
        base = stages._progress
        with stages.working(interval=0.01):
            result["ok"] = wait_until(lambda: (probe.bump(tid), stages._progress - base)[1] >= 2)
        result["tid"] = tid
    t = threading.Thread(target=worker)
    t.start()
    t.join(30)
    assert result["ok"] and set(probe.calls) == {result["tid"]}


def test_working_in_a_thread_pool(stages, probe):
    from concurrent.futures import ThreadPoolExecutor

    def job(n):
        with stages.working(interval=0.01):
            probe.bump()
            return n
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sorted(pool.map(job, range(12))) == list(range(12))
    assert not heartbeat_threads()


@pytest.mark.parametrize("exc", [RuntimeError("r"), OSError(5, "io"), ValueError("v"), KeyError("k"), ZeroDivisionError()])
def test_helper_keeps_going_whatever_a_later_probe_raises(stages, probe, exc):
    with stages.working(interval=0.01):
        assert wait_until(lambda: len(probe.calls) >= 1)
        probe.fail = exc
        n = len(probe.calls)
        assert wait_until(lambda: len(probe.calls) >= n + 3)
        assert len(heartbeat_threads()) == 1


def test_a_probe_that_fails_for_good_does_not_tick_or_break_the_step(stages, probe):
    base = stages._progress
    with stages.working(interval=0.01):
        assert wait_until(lambda: len(probe.calls) >= 1)
        probe.fail = RuntimeError("always")
        n = len(probe.calls)
        assert wait_until(lambda: len(probe.calls) >= n + 5)
    assert stages._progress == base + 1


def test_helper_survives_a_probe_that_raises_at_the_very_start(stages, probe):
    probe.fail = RuntimeError("probe broke at the start")
    base = stages._progress
    with stages.working(interval=0.01):
        assert wait_until(lambda: len(probe.calls) >= 1)
        probe.fail = None
        time.sleep(0.1)
        assert wait_until(lambda: (probe.bump(), stages._progress - base)[1] >= 2, timeout=15)


def test_join_timeout_path(stages, probe, monkeypatch):
    joins = []
    real_join = threading.Thread.join

    def join(self, timeout=None):
        if self.name == HEARTBEAT:
            joins.append(timeout)
            return real_join(self, 0.2)
        return real_join(self, timeout)
    monkeypatch.setattr(threading.Thread, "join", join)
    probe.gate = threading.Event()
    base = stages._progress
    t = time.monotonic()
    with stages.working(interval=0.01):
        assert wait_until(lambda: len(probe.calls) >= 2)             # the helper now hangs inside its probe
    assert time.monotonic() - t < 60                                  # the block did not wait for it
    assert joins == [5]
    assert stages._progress == base + 1                              # the final report is made all the same
    assert len(heartbeat_threads()) == 1                             # still stuck
    probe.gate.set()                                                 # the autouse check sees it end


def test_a_stuck_helper_does_not_hide_a_step_exception(stages, probe, monkeypatch):
    real_join = threading.Thread.join
    monkeypatch.setattr(threading.Thread, "join", lambda self, timeout=None: real_join(self, 0.1))
    probe.gate = threading.Event()
    with pytest.raises(ValueError, match="step failed"):
        with stages.working(interval=0.01):
            assert wait_until(lambda: len(probe.calls) >= 2)
            raise ValueError("step failed")
    probe.gate.set()


def test_rapid_enter_and_exit_leaks_no_threads(stages, probe):
    base = stages._progress
    before = threading.active_count()
    for _ in range(1000):
        with stages.working(interval=0.5):
            pass
    assert stages._progress == base + 1000
    assert not heartbeat_threads()
    assert threading.active_count() <= before


def test_rapid_enter_and_exit_from_several_threads(stages, probe):
    errors = []

    def spin():
        try:
            for _ in range(150):
                with stages.working(interval=0.5):
                    pass
        except BaseException as exc:
            errors.append(exc)
    threads = [threading.Thread(target=spin) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not errors
    assert not heartbeat_threads()


def test_concurrent_progress_calls_only_move_the_counter_forward(stages):
    stages.stall_seconds = 0
    base = stages._progress
    seen_backwards = []

    def hammer():
        last = stages._progress
        for _ in range(20_000):
            stages.progress()
            now = stages._progress
            if now < last - 10_000:
                seen_backwards.append((last, now))
            last = max(last, now)
    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not seen_backwards
    assert base < stages._progress <= base + 8 * 20_000


def test_progress_from_helpers_and_callers_at_once(stages, probe):
    stop = threading.Event()

    def caller():
        while not stop.is_set():
            stages.progress()
    callers = [threading.Thread(target=caller) for _ in range(3)]
    for t in callers:
        t.start()
    try:
        base = stages._progress
        with stages.working(interval=0.005):
            assert wait_until(lambda: (probe.bump(), stages._progress - base)[1] >= 100)
    finally:
        stop.set()
        for t in callers:
            t.join(15)


def test_stop_requested_while_blocks_open_and_close(stages, probe):
    errors, done = [], threading.Event()

    def churn():
        try:
            while not done.is_set():
                with stages.working(interval=0.01):
                    probe.bump()
        except BaseException as exc:
            errors.append(exc)
    t = threading.Thread(target=churn)
    t.start()
    try:
        time.sleep(0.1)
        stages.request_stop("kill_switch")
        time.sleep(0.1)
        stages.request_stop("interrupt")
    finally:
        done.set()
        t.join(30)
    assert not errors
    assert stages.reason == "kill_switch" and stages.stop.is_set()


def test_working_does_not_set_the_stop_event(stages, probe):
    with stages.working(interval=0.01):
        probe.bump()
        time.sleep(0.05)
    assert not stages.stop.is_set() and stages.reason is None


def test_working_exit_does_not_start_a_monitor(stages, probe):
    with stages.working(interval=0.01):
        pass
    assert stages._monitor is None


# ---------------------------------------------------------------- queued() interplay

def test_queued_wait_is_not_a_stall_whatever_the_clock_says(tmp_path, clock):
    _, st = make_stages(tmp_path, stall_seconds=60)
    with st.queued():
        clock.now += 10_000
        assert st._stalled() is None
    clock.now += 59
    assert st._stalled() is None                                    # the wait ended with a tick: the clock restarts here
    clock.now += 59
    assert st._stalled() is None
    clock.now += 2
    assert st._stalled() == "stalled"


def test_queued_exit_reports_progress(stages):
    base = stages._progress
    with stages.queued():
        assert stages._queued == 1
    assert stages._queued == 0 and stages._progress == base + 1


def test_queued_exit_reports_progress_after_an_exception(stages):
    base = stages._progress
    with pytest.raises(RuntimeError):
        with stages.queued():
            raise RuntimeError("x")
    assert stages._queued == 0 and stages._progress == base + 1


def test_working_inside_queued_keeps_both_counters_straight(stages, probe):
    base = stages._progress
    with stages.queued():
        with stages.working(interval=0.5):
            assert stages._queued == 1
    assert stages._queued == 0
    assert stages._progress == base + 2                              # one per exit
    assert not heartbeat_threads()


def test_queued_inside_working_keeps_both_counters_straight(stages, probe):
    base = stages._progress
    with stages.working(interval=0.5):
        with stages.queued():
            pass
        assert stages._progress == base + 1
    assert stages._progress == base + 2 and stages._queued == 0


def test_nested_queued_blocks_count_up_and_down(stages):
    with stages.queued():
        with stages.queued():
            assert stages._queued == 2
        assert stages._queued == 1
    assert stages._queued == 0


# ---------------------------------------------------------------- the stall rule on a fake clock

def test_stalled_is_quiet_before_the_limit_and_fires_at_it(tmp_path, clock):
    _, st = make_stages(tmp_path, stall_seconds=100)
    clock.now += 99.9
    assert st._stalled() is None
    clock.now += 0.1
    assert st._stalled() == "stalled"


def test_stalled_fires_again_on_every_later_check(tmp_path, clock):
    _, st = make_stages(tmp_path, stall_seconds=10)
    clock.now += 50
    assert st._stalled() == "stalled" and st._stalled() == "stalled"


def test_a_progress_tick_restarts_the_clock(tmp_path, clock):
    _, st = make_stages(tmp_path, stall_seconds=100)
    clock.now += 90
    st.progress()
    assert st._stalled() is None
    clock.now += 99
    assert st._stalled() is None
    clock.now += 2
    assert st._stalled() == "stalled"


def test_ticks_from_a_working_block_restart_the_clock(tmp_path, clock, probe):
    _, st = make_stages(tmp_path, stall_seconds=100)
    clock.now += 90
    with st.working(interval=0.5):
        pass                                                         # the exit report is a tick
    clock.now += 50
    assert st._stalled() is None


def test_a_running_tool_is_progress_of_its_own(tmp_path, clock):
    ex = SimpleNamespace(active_tools=1)
    _, st = make_stages(tmp_path, stall_seconds=100, executor=ex)
    for _ in range(10):
        clock.now += 1000
        assert st._stalled() is None
    ex.active_tools = 0
    clock.now += 99
    assert st._stalled() is None                                    # the clock restarted at the last look with a tool
    clock.now += 2
    assert st._stalled() == "stalled"


@pytest.mark.parametrize("tools", [1, 2, 50])
def test_any_number_of_running_tools_blocks_the_stall(tmp_path, clock, tools):
    _, st = make_stages(tmp_path, stall_seconds=10, executor=SimpleNamespace(active_tools=tools))
    clock.now += 10_000
    assert st._stalled() is None


def test_an_executor_without_the_counter_counts_as_no_tool(tmp_path, clock):
    _, st = make_stages(tmp_path, stall_seconds=10, executor=SimpleNamespace())
    clock.now += 11
    assert st._stalled() == "stalled"


def test_no_executor_at_all_counts_as_no_tool(tmp_path, clock):
    _, st = make_stages(tmp_path, stall_seconds=10)
    st.executor = None
    clock.now += 11
    assert st._stalled() == "stalled"


@pytest.mark.parametrize("limit", [0, -1, -3600.0])
def test_a_limit_of_zero_or_less_never_stalls(tmp_path, clock, limit):
    _, st = make_stages(tmp_path, stall_seconds=limit)
    clock.now += 10**9
    assert st._stalled() is None


def test_a_huge_limit_never_fires_in_practice(tmp_path, clock):
    _, st = make_stages(tmp_path, stall_seconds=1e12)
    clock.now += 10**6
    assert st._stalled() is None


def test_a_tiny_limit_fires_on_the_first_idle_check(tmp_path, clock):
    _, st = make_stages(tmp_path, stall_seconds=1e-9)
    clock.now += 1e-6
    assert st._stalled() == "stalled"


def test_progress_exactly_at_the_limit_still_counts(tmp_path, clock):
    _, st = make_stages(tmp_path, stall_seconds=100)
    clock.now += 100
    st.progress()
    assert st._stalled() is None


# ---------------------------------------------------------------- the stall rule end to end

@pytest.fixture
def fast_monitor(monkeypatch):
    monkeypatch.setattr(pipeline, "MONITOR_TICK", 0.02)


def run_step(st, step):
    st.start_monitor()
    try:
        return st.run("step", step, None)
    finally:
        st.stop_monitor()


def busy_for(seconds, st, probe, pause=0.01):
    """A step that does work without reporting any: it only moves its own activity reading."""
    end = time.monotonic() + seconds
    while time.monotonic() < end and not st.stop.is_set():
        probe.bump()
        time.sleep(pause)


def test_a_silent_busy_step_does_not_stall_inside_working(tmp_path, fast_monitor, probe):
    _, st = make_stages(tmp_path, stall_seconds=1.5)

    def step():
        with st.working():
            busy_for(3.5, st, probe)
    run_step(st, step)
    assert st.reason is None and not st.stop.is_set() and not st.errors


def test_the_same_silent_busy_step_stalls_without_working(tmp_path, fast_monitor, probe):
    _, st = make_stages(tmp_path, stall_seconds=0.4)
    t = time.monotonic()
    run_step(st, lambda: busy_for(15, st, probe))
    assert st.reason == "stalled" and time.monotonic() - t < 120


def test_a_blocked_step_stalls_even_inside_working(tmp_path, fast_monitor, probe):
    _, st = make_stages(tmp_path, stall_seconds=0.4)
    t = time.monotonic()

    def step():
        with st.working():
            st.stop.wait(20)
    run_step(st, step)
    assert st.reason == "stalled" and time.monotonic() - t < 120 and st.stop.is_set()


@pytest.mark.parametrize("blocker", ["event", "lock", "sleep"])
def test_every_kind_of_wait_still_stalls(tmp_path, fast_monitor, probe, blocker):
    _, st = make_stages(tmp_path, stall_seconds=0.4)
    lock = threading.Lock()
    lock.acquire()

    def step():
        with st.working():
            if blocker == "event":
                threading.Event().wait(4.0)
            elif blocker == "lock":
                lock.acquire(timeout=4.0)
            else:
                time.sleep(4.0)
    run_step(st, step)
    assert st.reason == "stalled"


def test_a_step_with_a_running_tool_never_stalls(tmp_path, fast_monitor, probe):
    ex = SimpleNamespace(active_tools=1)
    _, st = make_stages(tmp_path, stall_seconds=0.3, executor=ex)

    def step():
        with st.working():
            time.sleep(1.2)                                         # blocked, but a tool is running
    run_step(st, step)
    assert st.reason is None


def test_a_tool_that_ends_lets_the_clock_run_out(tmp_path, fast_monitor, probe):
    ex = SimpleNamespace(active_tools=1)
    _, st = make_stages(tmp_path, stall_seconds=0.3, executor=ex)

    def step():
        time.sleep(0.5)
        ex.active_tools = 0
        st.stop.wait(15)
    run_step(st, step)
    assert st.reason == "stalled"


def test_ticks_keep_resetting_the_clock(tmp_path, fast_monitor, probe):
    _, st = make_stages(tmp_path, stall_seconds=2.0)

    def step():
        for _ in range(30):
            st.progress()
            time.sleep(0.1)                                         # 3 s in all, ticks 0.1 s apart, limit 2 s
    run_step(st, step)
    assert st.reason is None


def test_a_pause_longer_than_the_limit_between_ticks_stalls(tmp_path, fast_monitor, probe):
    _, st = make_stages(tmp_path, stall_seconds=0.3)

    def step():
        st.progress()
        st.stop.wait(15)
    run_step(st, step)
    assert st.reason == "stalled"


def test_work_then_silence_stalls_after_the_work_ends(tmp_path, fast_monitor, probe):
    _, st = make_stages(tmp_path, stall_seconds=0.4)
    marks = {}

    def step():
        with st.working():
            busy_for(0.6, st, probe)
        marks["worked"] = time.monotonic()
        st.stop.wait(15)
    run_step(st, step)
    assert st.reason == "stalled"
    assert time.monotonic() - marks["worked"] < 120


def test_stalled_is_set_once_and_later_requests_do_not_replace_it(tmp_path, fast_monitor, probe):
    cfg, st = make_stages(tmp_path, stall_seconds=0.3)
    st.start_monitor()
    try:
        assert st.stop.wait(15) and st.reason == "stalled"
        st.request_stop("kill_switch")
        st.request_stop("interrupt")
        assert st.reason == "stalled"
        kill = pathlib.Path(cfg.kill_switch_file)
        kill.parent.mkdir(parents=True, exist_ok=True)
        kill.write_text("stop")
        time.sleep(0.2)
        assert st.reason == "stalled" and st.stop.is_set()
    finally:
        st.stop_monitor()


def test_request_stop_is_idempotent(stages):
    stages.request_stop("stalled")
    stages.request_stop("stalled")
    assert stages.reason == "stalled" and stages.stop.is_set()
    stages.request_stop("other")
    assert stages.reason == "stalled"


def test_request_stop_from_many_threads_keeps_the_first_reason(stages):
    barrier = threading.Barrier(8)

    def go(n):
        barrier.wait(15)
        stages.request_stop(f"r{n}")
    threads = [threading.Thread(target=go, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(15)
    assert stages.reason in {f"r{n}" for n in range(8)} and stages.stop.is_set()
    first = stages.reason
    stages.request_stop("late")
    assert stages.reason == first


def test_a_stop_before_the_stall_wins_and_the_stall_never_replaces_it(tmp_path, fast_monitor, probe):
    cfg, st = make_stages(tmp_path, stall_seconds=0.4)
    st.start_monitor()
    try:
        st.request_stop("approval_expired")
        time.sleep(0.8)
        assert st.reason == "approval_expired"
    finally:
        st.stop_monitor()


def test_the_monitor_keeps_the_event_set_after_a_stall(tmp_path, fast_monitor, probe):
    _, st = make_stages(tmp_path, stall_seconds=0.2)
    st.start_monitor()
    try:
        assert st.stop.wait(15)
        time.sleep(0.1)
        assert st.stop.is_set() and st.reason == "stalled"
    finally:
        st.stop_monitor()


def test_a_stalled_step_is_skipped_by_the_stages_after_it(tmp_path, fast_monitor, probe):
    _, st = make_stages(tmp_path, stall_seconds=0.3)
    st.start_monitor()
    try:
        st.run("first", lambda: st.stop.wait(15), None)
        ran = []
        st.run("second", lambda: ran.append(1), None)
    finally:
        st.stop_monitor()
    assert st.reason == "stalled" and "second" in st.skipped and not ran


def test_working_inside_a_stage_run_reports_at_the_end_of_the_stage_too(tmp_path, probe):
    _, st = make_stages(tmp_path, stall_seconds=1800)
    base = st._progress

    def step():
        with st.working(interval=0.5):
            pass
    st.run("step", step, None)
    assert st._progress == base + 3                                 # start of run, exit of working, end of run


def test_real_busy_loop_does_not_stall_inside_working(tmp_path, fast_monitor):
    _, st = make_stages(tmp_path, stall_seconds=2.0)

    def step():
        with st.working():
            end = time.monotonic() + 4.5
            while time.monotonic() < end and not st.stop.is_set():
                sum(i * i for i in range(20_000))                   # computes, reports nothing
    run_step(st, step)
    assert st.reason is None


@on_linux
def test_real_file_io_does_not_stall_inside_working(tmp_path, fast_monitor):
    tid = threading.get_native_id()
    if not pathlib.Path(f"/proc/self/task/{tid}/io").exists():
        pytest.skip("no per-thread io accounting")
    _, st = make_stages(tmp_path, stall_seconds=2.0)
    target = tmp_path / "scratch.bin"

    def step():
        with st.working():
            end = time.monotonic() + 4.5
            while time.monotonic() < end and not st.stop.is_set():
                target.write_bytes(b"y" * 4096)
                target.read_bytes()
                time.sleep(0.02)
    run_step(st, step)
    assert st.reason is None


@on_linux
def test_real_blocked_thread_stalls_inside_working(tmp_path, fast_monitor):
    _, st = make_stages(tmp_path, stall_seconds=0.5)
    t = time.monotonic()

    gate = threading.Event()

    def blocked():
        with st.working():
            gate.wait(20)
    st.start_monitor()
    worker = threading.Thread(target=lambda: st.run("blocked", blocked, None))
    worker.start()
    try:
        assert st.stop.wait(15)
    finally:
        gate.set()
        worker.join(15)
        st.stop_monitor()
    assert st.reason == "stalled" and time.monotonic() - t < 120


@on_linux
def test_real_other_thread_busy_does_not_hide_a_blocked_one(tmp_path, fast_monitor):
    """The helper looks at the calling thread only; work elsewhere in the process does not count for it."""
    _, st = make_stages(tmp_path, stall_seconds=0.5)
    gate, done = threading.Event(), threading.Event()
    worker_done = []

    def spinner():
        while not done.is_set():
            sum(i * i for i in range(20_000))
    spin = threading.Thread(target=spinner)
    spin.start()

    def blocked():
        with st.working():
            gate.wait(20)
        worker_done.append(1)
    st.start_monitor()
    worker = threading.Thread(target=lambda: st.run("blocked", blocked, None))
    worker.start()
    try:
        assert st.stop.wait(15)
    finally:
        gate.set()
        done.set()
        worker.join(15)
        spin.join(15)
        st.stop_monitor()
    assert st.reason == "stalled"


# ---------------------------------------------------------------- no /proc: the fallback inside working()

def test_without_proc_a_busy_step_still_ticks(tmp_path, monkeypatch):
    FakeProc(monkeypatch, {})
    _, st = make_stages(tmp_path, stall_seconds=1.0)
    base = st._progress
    with st.working(interval=0.01):
        end = time.monotonic() + 60
        while st._progress - base < 2 and time.monotonic() < end:
            sum(i * i for i in range(200_000))
    assert st._progress - base >= 2


def test_without_proc_a_busy_step_does_not_stall(tmp_path, monkeypatch, fast_monitor):
    FakeProc(monkeypatch, {})
    _, st = make_stages(tmp_path, stall_seconds=2.0)

    def step():
        with st.working():
            end = time.monotonic() + 4.5
            while time.monotonic() < end and not st.stop.is_set():
                sum(i * i for i in range(50_000))
    run_step(st, step)
    assert st.reason is None


def test_without_proc_the_helper_and_the_exit_report_still_work(tmp_path, monkeypatch):
    FakeProc(monkeypatch, {})
    _, st = make_stages(tmp_path, stall_seconds=1800)
    base = st._progress
    with st.working(interval=0.5):
        assert len(heartbeat_threads()) == 1
    assert st._progress == base + 1 and not heartbeat_threads()


def test_proc_files_that_vanish_mid_block_do_not_end_the_helper(tmp_path, monkeypatch):
    tid = threading.get_native_id()
    files = proc_files(tid)
    proc = FakeProc(monkeypatch, files)
    _, st = make_stages(tmp_path, stall_seconds=1800)
    base = st._progress
    with st.working(interval=0.01):
        assert wait_until(lambda: len(proc.opened) >= 6)
        files.clear()                                                # the thread entry disappears
        n = len(proc.opened)
        assert wait_until(lambda: len(proc.opened) >= n + 6)
        assert len(heartbeat_threads()) == 1
    assert st._progress >= base + 1


def test_a_switch_from_proc_to_fallback_counts_as_a_change_at_most(tmp_path, monkeypatch):
    tid = threading.get_native_id()
    files = proc_files(tid)
    proc = FakeProc(monkeypatch, files)
    _, st = make_stages(tmp_path, stall_seconds=1800)
    names = counting_progress(st)
    with st.working(interval=0.01):
        assert wait_until(lambda: len(proc.opened) >= 4)
        files.clear()
        assert wait_until(lambda: len(proc.opened) >= 20)
    assert names.count(HEARTBEAT) <= 5                               # bounded, no runaway ticking


# ---------------------------------------------------------------- begin_tail / stop_monitor

def test_begin_tail_starts_one_helper(stages, probe):
    stages.begin_tail()
    try:
        assert len(heartbeat_threads()) == 1 and stages._tail_open
    finally:
        stages.stop_monitor()


def test_begin_tail_second_call_makes_no_progress_report_and_no_thread(stages, probe):
    stages.begin_tail()
    try:
        base, threads = stages._progress, threading.active_count()
        stages.begin_tail()
        assert stages._progress == base and threading.active_count() == threads
    finally:
        stages.stop_monitor()


def test_stop_monitor_closes_the_tail_and_reports_once(stages, probe):
    stages.begin_tail()
    base = stages._progress
    stages.stop_monitor()
    assert not heartbeat_threads() and not stages._tail_open
    assert stages._progress == base + 1


def test_stop_monitor_without_a_tail_changes_nothing(stages, probe):
    base = stages._progress
    stages.stop_monitor()
    assert stages._progress == base and not stages._tail_open and not heartbeat_threads()


def test_stop_monitor_twice_is_harmless(stages, probe):
    stages.begin_tail()
    stages.stop_monitor()
    base = stages._progress
    stages.stop_monitor()
    assert stages._progress == base and not heartbeat_threads()


def test_stop_monitor_with_a_running_monitor_closes_both(tmp_path, fast_monitor, probe):
    _, st = make_stages(tmp_path, stall_seconds=1800)
    st.start_monitor()
    st.begin_tail()
    assert len(heartbeat_threads()) == 1
    st.stop_monitor()
    assert not heartbeat_threads() and st._monitor is None


def test_begin_tail_after_stop_monitor_opens_a_fresh_block(stages, probe):
    stages.begin_tail()
    stages.stop_monitor()
    stages.begin_tail()
    try:
        assert len(heartbeat_threads()) == 1 and stages._tail_open
    finally:
        stages.stop_monitor()
    assert not heartbeat_threads()


def test_begin_tail_without_any_monitor(stages, probe):
    assert stages._monitor is None
    stages.begin_tail()
    stages.stop_monitor()
    assert not heartbeat_threads()


def test_tail_stays_alive_across_stop_checks(tmp_path, fast_monitor, probe):
    _, st = make_stages(tmp_path, stall_seconds=1800)
    st.start_monitor()
    st.begin_tail()
    try:
        for _ in range(50):
            assert st.check_now() is False
            assert st.killed() is False
        time.sleep(0.1)
        assert len(heartbeat_threads()) == 1
    finally:
        st.stop_monitor()


def test_tail_stays_alive_after_a_stop_is_requested(tmp_path, probe):
    _, st = make_stages(tmp_path, stall_seconds=1800)
    st.begin_tail()
    try:
        st.request_stop("kill_switch")
        assert st.killed() and len(heartbeat_threads()) == 1         # the write-out goes on after a stop
    finally:
        st.stop_monitor()


def test_tail_is_closed_when_the_run_fails_in_a_finally(stages, probe):
    with pytest.raises(RuntimeError):
        try:
            stages.begin_tail()
            raise RuntimeError("write-out failed")
        finally:
            stages.stop_monitor()
    assert not heartbeat_threads()


def test_tail_closed_by_guard_pattern(stages, probe):
    stages.begin_tail()
    stages.guard("write", lambda: 1 / 0)
    stages.stop_monitor()
    assert not heartbeat_threads() and "write" in stages.errors


def test_tail_ticks_for_a_busy_write_out(tmp_path, fast_monitor, probe):
    _, st = make_stages(tmp_path, stall_seconds=0.5)
    st.start_monitor()
    st.begin_tail()
    try:
        busy_for(1.0, st, probe)
        assert st.reason is None
    finally:
        st.stop_monitor()


def test_tail_does_not_hide_a_hung_write_out(tmp_path, fast_monitor, probe):
    _, st = make_stages(tmp_path, stall_seconds=0.4)
    st.start_monitor()
    st.begin_tail()
    try:
        assert st.stop.wait(15)
        assert st.reason == "stalled"
    finally:
        st.stop_monitor()


def test_tail_helper_watches_the_thread_that_opened_it(stages, probe):
    me = threading.get_native_id()
    stages.begin_tail()
    try:
        assert wait_until(lambda: len(probe.calls) >= 1)
        assert set(probe.calls) == {me}
    finally:
        stages.stop_monitor()


def test_tail_interval_uses_the_stall_limit_at_the_time_of_the_call(tmp_path, probe, waits):
    _, st = make_stages(tmp_path, stall_seconds=2.0)
    st.begin_tail()
    try:
        assert wait_until(lambda: bool(waits))
    finally:
        st.stop_monitor()
    assert waits[0] == pytest.approx(0.5)


def test_tail_with_the_stall_check_switched_off(tmp_path, probe, waits):
    _, st = make_stages(tmp_path, stall_seconds=0)
    st.begin_tail()
    try:
        assert wait_until(lambda: bool(waits))
    finally:
        st.stop_monitor()
    assert waits[0] == pipeline.WORK_TICK


def test_tail_can_be_stopped_from_another_thread(stages, probe):
    stages.begin_tail()
    t = threading.Thread(target=stages.stop_monitor)
    t.start()
    t.join(30)
    assert not t.is_alive() and not heartbeat_threads()


def test_concurrent_begin_tail_calls_open_one_helper(stages, probe):
    barrier = threading.Barrier(6)

    def go():
        barrier.wait(15)
        stages.begin_tail()
    threads = [threading.Thread(target=go) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(15)
    try:
        assert len(heartbeat_threads()) == 1
    finally:
        stages.stop_monitor()


def test_tail_and_working_blocks_can_overlap(stages, probe):
    stages.begin_tail()
    try:
        with stages.working(interval=0.5):
            assert len(heartbeat_threads()) == 2
        assert len(heartbeat_threads()) == 1
    finally:
        stages.stop_monitor()
    assert not heartbeat_threads()


def test_stages_start_without_a_tail(stages):
    assert stages._tail_open is False and not heartbeat_threads()


# ---------------------------------------------------------------- placement of the calls in the stage functions

SOURCE = pathlib.Path(pipeline.__file__).read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def parents_of(tree):
    out = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            out[child] = node
    return out


PARENTS = parents_of(TREE)


def attr_calls(name):
    return [n for n in ast.walk(TREE) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == name]


def plain_calls(name):
    return [n for n in ast.walk(TREE) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == name]


def inside_working(node):
    cur = node
    while cur in PARENTS:
        cur = PARENTS[cur]
        if isinstance(cur, ast.With):
            for item in cur.items:
                ctx = item.context_expr
                if isinstance(ctx, ast.Call) and isinstance(ctx.func, ast.Attribute) and ctx.func.attr == "working":
                    return True
    return False


def enclosing_function(node):
    cur = node
    while cur in PARENTS:
        cur = PARENTS[cur]
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur.name
    return None


@pytest.mark.parametrize("method", ["clear_names", "prune_resolutions", "iter_candidate_names", "fill_missing_ptr", "iter_unsent_ptr_ips"])
def test_slow_store_calls_run_inside_a_working_block(method):
    calls = [c for c in attr_calls(method) if enclosing_function(c) in {"ptr_stage", "cand_stage", "dns_stage"}]
    assert calls, f"{method} not called in a stage"
    assert all(inside_working(c) for c in calls)


def test_favicon_jobs_runs_inside_a_working_block():
    calls = [c for c in plain_calls("favicon_jobs") if enclosing_function(c) == "favicon_stage"]
    assert len(calls) == 1 and inside_working(calls[0])


def test_begin_tail_is_called_before_the_favicon_record_count():
    begins = [c for c in attr_calls("begin_tail") if enclosing_function(c) == "favicon_stage"]
    counts = [c for c in attr_calls("count_favicons") if enclosing_function(c) == "favicon_stage"]
    assert len(begins) == 1 and counts
    assert begins[0].lineno < min(c.lineno for c in counts)


def test_begin_tail_is_called_again_before_the_final_write_out():
    begins = [c for c in attr_calls("begin_tail") if enclosing_function(c) != "favicon_stage"]
    checks = [c for c in attr_calls("check_now") if enclosing_function(c) == "_run_stages_with"]
    assert begins and checks
    last_begin = max(b.lineno for b in begins)
    assert last_begin <= min(c.lineno for c in checks)


def test_begin_tail_is_never_called_inside_a_loop():
    for call in attr_calls("begin_tail"):
        assert not any(isinstance(p, (ast.For, ast.While)) for p in _ancestors(call))


def _ancestors(node):
    while node in PARENTS:
        node = PARENTS[node]
        yield node


@pytest.mark.parametrize("stage", ["cand_stage", "sni_stage"])
def test_the_big_loops_report_every_loop_tick_addresses(stage):
    fn = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef) and n.name == stage)
    loops = [n for n in ast.walk(fn) if isinstance(n, ast.For) and isinstance(n.target, ast.Tuple)
             and isinstance(n.iter, ast.Call) and getattr(n.iter.func, "id", "") == "enumerate"]
    assert loops, "no enumerate loop over the fact store"
    loop = loops[0]
    assert "iter_ips" in ast.unparse(loop.iter)
    first = loop.body[0]
    assert isinstance(first, ast.If) and "LOOP_TICK" in ast.unparse(first.test)
    assert "progress" in ast.unparse(first.body[0])


def test_loop_tick_is_used_only_through_the_module_constant():
    uses = [n for n in ast.walk(TREE) if isinstance(n, ast.Name) and n.id == "LOOP_TICK" and isinstance(n.ctx, ast.Load)]
    assert len(uses) == 2


def test_working_is_a_context_manager_with_an_optional_interval():
    sig = inspect.signature(pipeline._Stages.working)
    assert list(sig.parameters) == ["self", "interval"] and sig.parameters["interval"].default is None


# ---------------------------------------------------------------- behaviour of the stage functions on a real run

def pipeline_run(tmp_path, monkeypatch, loop_tick=None, work_tick=None):
    from tests.helpers import FakeFetcher, write_config
    from tests.test_pipeline import tools
    if loop_tick is not None:
        monkeypatch.setattr(pipeline, "LOOP_TICK", loop_tick)
    if work_tick is not None:
        monkeypatch.setattr(pipeline, "WORK_TICK", work_tick)
    callers: dict[str, int] = {}
    real = pipeline._Stages.progress

    def counting(self):
        if threading.current_thread().name != HEARTBEAT:
            name = sys._getframe(1).f_code.co_name
            callers[name] = callers.get(name, 0) + 1
        real(self)
    monkeypatch.setattr(pipeline._Stages, "progress", counting)
    kinds = {"working": 0, "begin_tail": 0}
    real_working, real_tail = pipeline._Stages.working, pipeline._Stages.begin_tail

    def spy_tail(self):
        kinds["begin_tail"] += 1
        return real_tail(self)
    monkeypatch.setattr(pipeline._Stages, "begin_tail", spy_tail)
    entered = []

    def spy_working(self, interval=None):
        entered.append(sys._getframe(1).f_code.co_name)
        return real_working(self, interval)
    monkeypatch.setattr(pipeline._Stages, "working", spy_working)
    cfg = load_config(write_config(tmp_path))
    run_dir = pipeline.run(cfg, run_id="hb", executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)
    return run_dir, callers, kinds, entered


@pytest.fixture(scope="module")
def baseline_counts(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    try:
        return pipeline_run(tmp_path_factory.mktemp("hb_base"), mp)
    finally:
        mp.undo()


def test_a_real_run_enters_the_working_blocks_and_the_tail(baseline_counts):
    run_dir, callers, kinds, entered = baseline_counts
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["complete"] is True
    assert "cand_stage" in entered and "dns_stage" in entered
    assert kinds["begin_tail"] >= 1


def test_a_real_run_leaves_no_helper_behind(baseline_counts):
    assert not heartbeat_threads()


def test_a_real_run_with_loop_tick_one_reports_per_address(tmp_path, monkeypatch, baseline_counts):
    _, base, _, _ = baseline_counts
    _, every, _, _ = pipeline_run(tmp_path, monkeypatch, loop_tick=1)
    extra_c = every.get("cand_stage", 0) - base.get("cand_stage", 0)
    extra_s = every.get("sni_stage", 0) - base.get("sni_stage", 0)
    assert extra_c >= 2 and extra_s >= 1                              # the fake store holds a few addresses
    assert every.get("cand_stage", 0) >= 3


def test_a_huge_loop_tick_reports_only_for_the_first_address(tmp_path, monkeypatch):
    _, calls, _, _ = pipeline_run(tmp_path, monkeypatch, loop_tick=10**9)
    assert calls.get("cand_stage", 0) == 1
    assert calls.get("sni_stage", 0) <= 1


def test_loop_tick_two_reports_for_every_second_address(tmp_path, monkeypatch):
    base = tmp_path / "a"
    other = tmp_path / "b"
    base.mkdir()
    other.mkdir()
    _, one, _, _ = pipeline_run(base, monkeypatch, loop_tick=1)
    monkeypatch.undo()
    _, two, _, _ = pipeline_run(other, monkeypatch, loop_tick=2)
    assert two["cand_stage"] == (one["cand_stage"] + 1) // 2


def test_a_real_run_with_a_tiny_work_tick_is_unaffected(tmp_path, monkeypatch):
    run_dir, _, _, _ = pipeline_run(tmp_path, monkeypatch, work_tick=0.01, loop_tick=1)
    assert json.loads((run_dir / "manifest.json").read_text())["complete"] is True
    assert not heartbeat_threads()


def test_a_real_run_gives_the_same_rows_whatever_the_ticks(tmp_path, monkeypatch):
    from scanner.internet import outputs
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    run_a, *_ = pipeline_run(a, monkeypatch, loop_tick=1, work_tick=0.01)
    monkeypatch.undo()
    run_b, *_ = pipeline_run(b, monkeypatch, loop_tick=10**9)
    def keyed(run):
        return sorted(json.dumps({k: r.get(k) for k in ("ip", "hostname", "a_answers", "candidate_names_total")}, sort_keys=True,
                                 default=str) for r in outputs.iter_hostname_rows(run))
    rows_a, rows_b = keyed(run_a), keyed(run_b)
    assert rows_a == rows_b and rows_a


def test_a_real_run_aborted_by_the_stop_still_closes_the_tail(tmp_path, monkeypatch):
    from tests.helpers import FakeFetcher, write_config
    from tests.test_pipeline import tools
    cfg = load_config(write_config(tmp_path))
    kill = pathlib.Path(cfg.kill_switch_file)
    kill.parent.mkdir(parents=True, exist_ok=True)
    kill.write_text("stop")
    pipeline.run(cfg, run_id="hb-stop", executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)
    assert not heartbeat_threads()



# ---------------------------------------------------------------- the stat file alone is enough: no mix with the process clock

def deny_io_files(monkeypatch):
    real_open = builtins.open

    def deny_io(path, mode="r", *a, **k):
        if str(path).startswith("/proc/self/task/") and str(path).endswith("/io"):
            raise PermissionError(13, "denied", str(path))
        return real_open(path, mode, *a, **k)
    monkeypatch.setattr(builtins, "open", deny_io)


@on_linux
def test_a_blocked_step_does_not_tick_when_the_io_file_is_unreadable_and_another_thread_computes(tmp_path, monkeypatch, fast_monitor):
    deny_io_files(monkeypatch)
    _, st = make_stages(tmp_path, stall_seconds=0.5)
    gate, done = threading.Event(), threading.Event()

    def spinner():
        while not done.is_set():
            sum(i * i for i in range(20_000))
    spin = threading.Thread(target=spinner)
    spin.start()

    def blocked():
        with st.working():
            gate.wait(20)
    st.start_monitor()
    worker = threading.Thread(target=lambda: st.run("blocked", blocked, None))
    worker.start()
    try:
        assert st.stop.wait(15)
    finally:
        gate.set()
        done.set()
        worker.join(15)
        spin.join(15)
        st.stop_monitor()
    assert st.reason == "stalled"


@on_linux
def test_the_reading_still_changes_when_the_calling_thread_computes_and_the_io_file_is_unreadable(monkeypatch):
    deny_io_files(monkeypatch)
    tid = threading.get_native_id()
    first = pipeline._thread_activity(tid)
    assert first[1] == 0
    end = time.monotonic() + 15
    changed = False
    while time.monotonic() < end and not changed:
        sum(i * i for i in range(300_000))
        changed = pipeline._thread_activity(tid) != first
    assert changed


def test_a_reading_from_stat_is_not_moved_by_the_process_clock(monkeypatch, clock):
    FakeProc(monkeypatch, {"/proc/self/task/5/stat": stat_line(5, "t", 3, 4)})
    first = pipeline._thread_activity(5)
    clock.cpu = 50.0                                                # another thread burns CPU
    assert pipeline._thread_activity(5) == first == (7, 0)


# ---------------------------------------------------------------- the helper thread cannot be started

@pytest.fixture
def no_helper_thread(monkeypatch):
    real_start = threading.Thread.start

    def start(self, *a, **k):
        if self.name == HEARTBEAT:
            raise RuntimeError("cannot start new thread")
        return real_start(self, *a, **k)
    monkeypatch.setattr(threading.Thread, "start", start)


def test_working_goes_on_without_a_helper_when_no_thread_can_be_started(stages, probe, no_helper_thread):
    base = stages._progress
    with stages.working(interval=0.01):
        ran = True
    assert ran and not heartbeat_threads()
    assert stages._progress == base + 1                              # the report at the end still comes


def test_working_still_propagates_the_step_exception_without_a_helper(stages, probe, no_helper_thread):
    with pytest.raises(ValueError):
        with stages.working(interval=0.01):
            raise ValueError("step")


def test_begin_tail_does_not_crash_when_no_thread_can_be_started(stages, probe, no_helper_thread):
    stages.begin_tail()
    assert stages._tail_open and not heartbeat_threads()
    stages.stop_monitor()
    assert not stages._tail_open


def test_a_step_without_a_helper_runs_into_the_stall_limit_as_before(tmp_path, probe, no_helper_thread, fast_monitor):
    _, st = make_stages(tmp_path, stall_seconds=0.3)
    gate = threading.Event()

    def blocked():
        with st.working():
            gate.wait(20)
    st.start_monitor()
    worker = threading.Thread(target=lambda: st.run("blocked", blocked, None))
    worker.start()
    try:
        assert st.stop.wait(15)
    finally:
        gate.set()
        worker.join(15)
        st.stop_monitor()
    assert st.reason == "stalled"


# ---------------------------------------------------------------- stop_monitor always stops the threads

def test_stop_monitor_still_stops_the_threads_when_closing_the_tail_raises(tmp_path, fast_monitor, probe):
    _, st = make_stages(tmp_path, stall_seconds=1800.0)
    st.start_monitor()
    monitor, guard = st._monitor, st._guard_thread
    assert monitor.is_alive() and guard.is_alive()

    class Boom:
        def close(self):
            raise RuntimeError("tail failed")
    st._tail = Boom()
    st._tail_open = True
    with pytest.raises(RuntimeError, match="tail failed"):
        st.stop_monitor()
    assert not monitor.is_alive() and not guard.is_alive()
    assert st._monitor is None and st._guard_thread is None and not st._tail_open
    assert st._monitor_done.is_set()


# ---------------------------------------------------------------- the zmap-only worker covers its write-out

def test_the_zmap_only_run_opens_the_tail_before_the_store_is_closed(tmp_path, monkeypatch):
    from tests.helpers import FakeFetcher, write_config
    from tests.test_pipeline import tools
    events = []
    real_begin = pipeline._Stages.begin_tail

    def begin(self):
        events.append("begin_tail")
        return real_begin(self)
    monkeypatch.setattr(pipeline._Stages, "begin_tail", begin)
    real_guard = pipeline._Stages.guard

    def guard(self, name, fn, default=None):
        if name == "store_close":
            events.append("store_close")
        return real_guard(self, name, fn, default)
    monkeypatch.setattr(pipeline._Stages, "guard", guard)
    cfg = load_config(write_config(tmp_path))
    d = pipeline.run(cfg, run_id="z1", executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True,
                     stop_after_zmap=True)
    assert json.loads((d / "manifest.json").read_text(encoding="utf-8"))["status"] == "zmap_done"
    assert "begin_tail" in events and events.index("begin_tail") < events.index("store_close")
    assert not heartbeat_threads()
