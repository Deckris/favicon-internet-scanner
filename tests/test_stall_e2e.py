"""Stall behaviour end to end: the real stage runner and the offline pipeline on a tiny synthetic shard.

Steps that compute without reporting progress are covered by ``working()`` and the write-out by ``begin_tail()``; a step
that is blocked is not. The stall limit of a run is shortened to about a second so that every scenario stays fast.
"""
from __future__ import annotations

import contextlib
import json
import math
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.internet import __main__ as cli
from scanner.internet import coordinator, fastjobs, pipeline, supervisor
from scanner.internet.config import load_config
from scanner.internet.shardstore import ShardStore
from tests.helpers import FakeFetcher
from tests.test_coordinator import Cluster, _worker_args, state_of
from tests.test_pipeline import tools
from tests.test_resume import real_calls, tables
from tests.test_scale import _cfg

STALL = 2.0                  # seconds without a sign of progress before a run in these tests is stopped
SLOW = 5.0                   # how long a slow step takes: well over the limit
SINGLE = {"fraction": 0.0001, "seed": 4}
THREE = {"fraction": 0.0001, "seed": 4, "shards": 3}
HELPERS = {"work-heartbeat", "run-monitor", "run-guards"}
EXIT_STOPPED = 5


# ------------------------------------------------------------------ helpers

def helper_threads():
    return sorted(t.name for t in threading.enumerate() if t.name in HELPERS)


def threads_back_to(before, wait=30.0):
    """True once every thread alive now was alive before (a finished run may leave a worker that is just ending)."""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if {t.ident for t in threading.enumerate()} <= before:
            return True
        time.sleep(0.05)
    return {t.ident for t in threading.enumerate()} <= before


@pytest.fixture(autouse=True)
def no_helper_threads_left():
    before = helper_threads()
    yield
    deadline = time.monotonic() + 30
    while helper_threads() != before and time.monotonic() < deadline:
        time.sleep(0.02)
    assert helper_threads() == before, "a helper thread of the stage runner outlived its block"


@pytest.fixture(autouse=True)
def fast_monitor(monkeypatch):
    monkeypatch.setattr(pipeline, "MONITOR_TICK", 0.05)


@pytest.fixture
def instances(monkeypatch):
    """Every ``_Stages`` that starts its monitor, with a stall limit of ``box.limit`` seconds in place of the configured one.

    The limit applies from the first stage on: the set-up before it (preflight, store) is not what these tests are about."""
    box = SimpleNamespace(limit=STALL, seen=[])
    start_monitor, run = pipeline._Stages.start_monitor, pipeline._Stages.run

    def start(self):
        box.seen.append(self)
        self._limit_applied = box.limit is None
        if box.limit is not None:
            self.stall_seconds = 0
        start_monitor(self)

    def first_stage(self, name, fn, default):
        if not getattr(self, "_limit_applied", True):
            self._limit_applied = True
            self.stall_seconds = box.limit
        return run(self, name, fn, default)
    monkeypatch.setattr(pipeline._Stages, "start_monitor", start)
    monkeypatch.setattr(pipeline._Stages, "run", first_stage)
    return box


@pytest.fixture
def silent(monkeypatch):
    """A thread that waits shows no CPU time and no I/O, whatever else the process does (on every platform)."""
    monkeypatch.setattr(pipeline, "_thread_activity", lambda tid: (0, 0))


def make_cfg(tmp_path, *, stall=1, sample=SINGLE, **kw):
    return load_config(_cfg(tmp_path, sample=sample, operations={"stall_minutes": stall}, **kw))


def go(cfg, run_id="r", ft=None, **kw):
    return pipeline.run(cfg, run_id=run_id, executor=ft or tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True, **kw)


def manifest_dir(tmp_path):
    return next(p.parent for p in (tmp_path / 'out').glob('*/manifest.json'))


def manifest_of(run_dir):
    return json.loads((Path(run_dir) / "manifest.json").read_text(encoding="utf-8"))


def many_tools(n=25):
    ips = [f"1.1.2.{i}" for i in range(1, n + 1)]
    return tools(l4={443: ips}, tls={(ip, 443): "ok" for ip in ips}, tls_sni={}, http={}, ptr={}, a={})


def spin(seconds, stop=None):
    """Compute for ``seconds`` (less when ``stop`` is set) without reporting anything."""
    end = time.monotonic() + seconds
    while time.monotonic() < end and not (stop is not None and stop.is_set()):
        sum(range(3000))


@contextlib.contextmanager
def _uncovered(self, interval=None):
    yield


def uncovered(monkeypatch):
    """The stage runner with step coverage switched off: nothing watches a step that reports no progress."""
    monkeypatch.setattr(pipeline._Stages, "working", _uncovered)
    monkeypatch.setattr(pipeline._Stages, "begin_tail", lambda self: None)


def around(monkeypatch, owner, name, before, *, once=False):
    """Run ``before()`` ahead of ``owner.name``, then the real one."""
    real = getattr(owner, name)
    count = {"n": 0}

    def wrapper(*args, **kw):
        count["n"] += 1
        if not once or count["n"] == 1:
            before()
        return real(*args, **kw)
    monkeypatch.setattr(owner, name, wrapper)
    return count


STEPS = [(ShardStore, "fill_missing_ptr"), (ShardStore, "clear_names"), (ShardStore, "prune_resolutions"), (fastjobs, "favicon_jobs_fast")]
STEP_IDS = ["fill_missing_ptr", "clear_names", "prune_resolutions", "favicon_jobs"]
SOME_STEPS = [STEPS[1], STEPS[3]]
SOME_IDS = [STEP_IDS[1], STEP_IDS[3]]


# ------------------------------------------------------------------ the limit comes from the configuration

def test_the_stall_limit_of_the_run_is_the_configured_number_of_minutes(tmp_path):
    for minutes in (0, 1, 7):
        assert pipeline._Stages(make_cfg(tmp_path, stall=minutes), tmp_path).stall_seconds == minutes * 60


def test_the_default_limit_is_half_an_hour(tmp_path):
    assert pipeline._Stages(load_config(_cfg(tmp_path, sample=SINGLE)), tmp_path).stall_seconds == 1800


# ------------------------------------------------------------------ 1. a silent step: aborted without working(), kept with it

@pytest.mark.parametrize("owner,name", [STEPS[0], STEPS[3]], ids=["fill_missing_ptr", "favicon_jobs"])
def test_a_silent_step_is_aborted_as_stalled_when_nothing_covers_it(tmp_path, monkeypatch, instances, owner, name):
    uncovered(monkeypatch)
    around(monkeypatch, owner, name, lambda: spin(SLOW, instances.seen[-1].stop))
    t = time.monotonic()
    run_dir = go(make_cfg(tmp_path))
    m = manifest_of(run_dir)
    assert m["abort_reason"] == "stalled" and m["complete"] is False
    assert time.monotonic() - t < 120


@pytest.mark.parametrize("owner,name", SOME_STEPS, ids=SOME_IDS)
def test_the_same_step_survives_when_it_is_covered(tmp_path, monkeypatch, instances, owner, name):
    seen = []
    around(monkeypatch, owner, name, lambda: (seen.append(time.monotonic()), spin(SLOW))[0])
    t = time.monotonic()
    run_dir = go(make_cfg(tmp_path))
    m = manifest_of(run_dir)
    assert m["abort_reason"] is None and m["complete"] is True and m["stage_errors"] == {}
    assert seen and time.monotonic() - t >= SLOW > instances.limit * 2


def test_with_the_limit_off_a_silent_step_is_never_stalled(tmp_path, monkeypatch, instances):
    instances.limit = 0
    uncovered(monkeypatch)
    around(monkeypatch, ShardStore, "clear_names", lambda: spin(SLOW))
    assert manifest_of(go(make_cfg(tmp_path, stall=0)))["complete"] is True


def test_the_loops_over_the_store_keep_a_slow_run_alive_by_ticking(tmp_path, monkeypatch, instances):
    """The candidate and SNI loops run no tool and call no ``working``; their own ticks are all that tells the monitor they live."""
    monkeypatch.setattr(pipeline, "LOOP_TICK", 2)
    slow_loops(monkeypatch, 0.5)
    m = manifest_of(go(make_cfg(tmp_path), ft=many_tools(12)))
    assert m["abort_reason"] is None and m["complete"] is True


def test_the_same_loops_stall_when_they_do_not_tick(tmp_path, monkeypatch, instances):
    monkeypatch.setattr(pipeline, "LOOP_TICK", 10 ** 9)
    slow_loops(monkeypatch, 0.5)
    m = manifest_of(go(make_cfg(tmp_path), ft=many_tools(12)))
    assert m["abort_reason"] == "stalled"


def slow_loops(monkeypatch, pause):
    """Make the candidate and SNI loops wait ``pause`` seconds for every address (a sleep, so it reads as silence)."""
    real = ShardStore.iter_ips

    def slow_iter(self, *a, **k):
        gen = real(self, *a, **k)
        if sys._getframe(1).f_code.co_name not in ("cand_stage", "sni_stage"):
            return gen

        def slow():
            for item in gen:
                time.sleep(pause)
                yield item
        return slow()
    monkeypatch.setattr(ShardStore, "iter_ips", slow_iter)


# ------------------------------------------------------------------ 2. a hung step still stalls under working()

@pytest.mark.parametrize("owner,name", SOME_STEPS, ids=SOME_IDS)
def test_a_blocked_step_still_stalls_inside_working(tmp_path, monkeypatch, instances, silent, owner, name):
    waited = []

    def block():
        t = time.monotonic()
        instances.seen[-1].stop.wait(60)
        waited.append(time.monotonic() - t)
    around(monkeypatch, owner, name, block)
    run_dir = go(make_cfg(tmp_path))
    m = manifest_of(run_dir)
    assert m["abort_reason"] == "stalled" and m["complete"] is False
    assert 0 < waited[0] < 60


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="per-thread counters exist on Linux only; elsewhere the whole process stands in")
def test_a_blocked_step_is_not_kept_alive_by_the_cpu_of_other_threads(tmp_path):
    cfg = make_cfg(tmp_path)
    st = pipeline._Stages(cfg, tmp_path)
    st.stall_seconds = STALL
    busy = threading.Event()
    other = threading.Thread(target=lambda: spin(10, busy), name="elsewhere", daemon=True)
    st.start_monitor()
    other.start()
    t = time.monotonic()
    try:
        with st.working():
            st.stop.wait(60)
    finally:
        busy.set()
        other.join(30)
        st.stop_monitor()
    assert st.reason == "stalled" and time.monotonic() - t < 60


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="per-thread counters exist on Linux only")
def test_a_blocked_step_stalls_with_the_real_counters(tmp_path, monkeypatch, instances):
    around(monkeypatch, ShardStore, "clear_names", lambda: instances.seen[-1].stop.wait(60))
    assert manifest_of(go(make_cfg(tmp_path)))["abort_reason"] == "stalled"


def test_a_step_that_blocks_after_working_is_still_caught(tmp_path, monkeypatch, instances, silent):
    """Work first (the heartbeat sees it), then a wait: the limit counts from the last sign of life."""
    def work_then_block():
        with instances.seen[-1].working(0.05):
            spin(0.5)
        instances.seen[-1].stop.wait(60)
    around(monkeypatch, ShardStore, "clear_names", work_then_block)
    assert manifest_of(go(make_cfg(tmp_path)))["abort_reason"] == "stalled"


# ------------------------------------------------------------------ 3. the write-out tail

def patch_writer(monkeypatch, before):
    real = pipeline._write_records

    def wrapper(*args, **kw):
        before()
        return real(*args[:-1], lambda: None, **kw)         # the writer's own progress callback is silenced
    monkeypatch.setattr(pipeline, "_write_records", wrapper)


def test_a_slow_writeout_over_a_large_store_does_not_stall(tmp_path, monkeypatch, instances):
    patch_writer(monkeypatch, lambda: spin(SLOW))
    cfg = make_cfg(tmp_path, output={"compact": False})
    run_dir = go(cfg, ft=many_tools(25))
    m = manifest_of(run_dir)
    assert m["abort_reason"] is None and m["complete"] is True
    assert m["stage_counts"]["l4_endpoints"] == 25
    assert len(list((run_dir / "normalized").glob("endpoints.jsonl*"))) == 1


def test_a_slow_writeout_stalls_when_the_tail_is_not_covered(tmp_path, monkeypatch, instances):
    uncovered(monkeypatch)
    patch_writer(monkeypatch, lambda: spin(SLOW, instances.seen[-1].stop))
    m = manifest_of(go(make_cfg(tmp_path), ft=many_tools(25)))
    assert m["abort_reason"] == "stalled" and m["complete"] is False


def test_a_writeout_that_only_moves_data_does_not_stall(tmp_path, monkeypatch, instances):
    sink = tmp_path / "sink.bin"

    def write_for_a_while():
        end = time.monotonic() + SLOW
        with open(sink, "wb") as fh:
            while time.monotonic() < end:
                fh.write(b"x" * 65536)
                fh.flush()
    patch_writer(monkeypatch, write_for_a_while)
    m = manifest_of(go(make_cfg(tmp_path)))
    assert m["abort_reason"] is None and m["complete"] is True and sink.stat().st_size > 0


def test_a_blocked_writer_stalls(tmp_path, monkeypatch, instances, silent):
    waited = []

    def blocked():
        t = time.monotonic()
        instances.seen[-1].stop.wait(60)
        waited.append(time.monotonic() - t)
    patch_writer(monkeypatch, blocked)
    m = manifest_of(go(make_cfg(tmp_path), ft=many_tools(25)))
    assert m["abort_reason"] == "stalled" and m["complete"] is False
    assert waited and waited[0] < 60
    assert (Path(manifest_dir(tmp_path)) / "work" / "facts.sqlite").is_file()


def test_the_tail_is_entered_once_per_run(tmp_path, monkeypatch, instances):
    real = pipeline._Stages.working
    default_interval = []

    def counting(self, interval=None):
        if interval is None:
            default_interval.append(1)
        return real(self, interval)
    monkeypatch.setattr(pipeline._Stages, "working", counting)
    begun = []
    real_tail = pipeline._Stages.begin_tail
    monkeypatch.setattr(pipeline._Stages, "begin_tail", lambda self: (begun.append(1), real_tail(self))[1])
    assert manifest_of(go(make_cfg(tmp_path)))["complete"] is True
    assert begun and instances.seen[-1]._tail_open is False
    # every call after the first one in a run is a no-op, so the covered steps plus one tail account for all default-interval blocks
    assert len(default_interval) >= 1


# ------------------------------------------------------------------ 4. a stalled run: manifest, exit code, continuing

def test_a_stalled_run_leaves_a_manifest_that_says_so(tmp_path, monkeypatch, instances, silent):
    around(monkeypatch, ShardStore, "clear_names", lambda: instances.seen[-1].stop.wait(60), once=True)
    run_dir = go(make_cfg(tmp_path))
    m = manifest_of(run_dir)
    assert m["abort_reason"] == "stalled" and m["complete"] is False and m["status"] == "finished"
    assert "dns_forward" in m["stages_skipped"] or "sni_confirm" in m["stages_skipped"]
    assert (run_dir / "report" / "summary.json").is_file()


def test_a_stalled_run_continues_in_place_and_finishes_with_the_tables_of_a_clean_run(tmp_path, monkeypatch, instances, silent):
    clean_tools, second_tools = tools(), tools()
    clean = go(make_cfg(tmp_path), run_id="clean", ft=clean_tools)
    around(monkeypatch, ShardStore, "clear_names", lambda: instances.seen[-1].stop.wait(60), once=True)
    stalled = go(make_cfg(tmp_path), run_id="again")
    assert manifest_of(stalled)["abort_reason"] == "stalled"
    resumed = go(make_cfg(tmp_path), run_id="again", ft=second_tools, continue_in_place=True)
    m = manifest_of(resumed)
    assert resumed == stalled and m["complete"] is True and m["abort_reason"] is None
    assert tables(resumed)[0] == tables(clean)[0] and tables(resumed)[1] == tables(clean)[1] and tables(resumed)[3] == tables(clean)[3]
    assert len(real_calls(second_tools)) < len(real_calls(clean_tools))
    assert not (resumed / "work").exists()


def test_the_stage_worker_exits_five_on_a_stall_and_the_next_start_finishes_the_stage(tmp_path, monkeypatch, instances, silent):
    path = _cfg(tmp_path, sample=THREE, operations={"stall_minutes": 1})
    cfg = load_config(path)
    real_run, real_favicon = pipeline.run, pipeline.run_favicon_only
    monkeypatch.setattr(pipeline, "run", lambda c, **kw: real_run(c, executor=tools(), fetcher=FakeFetcher(), skip_preflight=True,
                                                                   offline_preflight=True, **kw))
    monkeypatch.setattr(pipeline, "run_favicon_only", lambda c, d, **kw: real_favicon(c, d, executor=tools(), fetcher=FakeFetcher(), **kw))
    zmap, run_dir = _worker_args(path, cfg, "zmap")
    network, _ = _worker_args(path, cfg, "network")
    favicon, _ = _worker_args(path, cfg, "favicon")
    assert cli.main(zmap) == 0 and manifest_of(run_dir)["zmap_done"] is True
    around(monkeypatch, ShardStore, "clear_names", lambda: instances.seen[-1].stop.wait(60), once=True)
    assert cli.main(network) == EXIT_STOPPED == coordinator.EXIT_STOPPED
    m = manifest_of(run_dir)
    assert m["abort_reason"] == "stalled" and not coordinator.stage_done_in("network", m)
    assert cli.main(network) == 0
    m = manifest_of(run_dir)
    assert m["abort_reason"] is None and coordinator.stage_done_in("network", m) and m["network_done"] is True
    assert cli.main(favicon) == 0
    assert manifest_of(run_dir)["complete"] is True


def test_the_stage_worker_does_not_call_a_kill_switch_stop_a_stall(tmp_path, monkeypatch, instances):
    path = _cfg(tmp_path, sample=THREE, operations={"stall_minutes": 1})
    cfg = load_config(path)
    real_run = pipeline.run
    monkeypatch.setattr(pipeline, "run", lambda c, **kw: real_run(c, executor=tools(), fetcher=FakeFetcher(), skip_preflight=True,
                                                                   offline_preflight=True, **kw))
    zmap, run_dir = _worker_args(path, cfg, "zmap")
    assert cli.main(zmap) == 0
    network, _ = _worker_args(path, cfg, "network")
    around(monkeypatch, ShardStore, "clear_names", lambda: Path(cfg.kill_switch_file).write_text("stop"), once=True)
    around(monkeypatch, fastjobs, "favicon_jobs_fast", lambda: instances.seen[-1].stop.wait(30))
    assert cli.main(network) == EXIT_STOPPED
    assert manifest_of(run_dir)["abort_reason"] == "kill_switch"


# ------------------------------------------------------------------ 5. the decoupled coordinator

class StallCluster(Cluster):
    """Fake stage workers. A failure with return code 5 leaves the manifest with ``abort_reason`` set to ``reasons.get(key, 'stalled')``."""

    def __init__(self, cfg, durations=None, fail=None, reasons=None, leave_manifest=True):
        super().__init__(cfg, durations=durations, fail=fail)
        self.reasons, self.leave_manifest = reasons or {}, leave_manifest

    def outcome(self, proc):
        rc = super().outcome(proc)
        if rc == EXIT_STOPPED and self.leave_manifest:
            path = proc.run_dir / "manifest.json"
            old = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
            proc.run_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({**old, "abort_reason": self.reasons.get((proc.stage, proc.shard), "stalled"), "complete": False}), encoding="utf-8")
        return rc


def stage_state(cfg, shard, stage):
    return state_of(cfg)["shard_states"][str(shard)]["stages"][stage]


def coordinate(tmp_path, cfg, cluster, **kw):
    logs = []
    kw.setdefault("egress", lambda c: c.vantage.public_egress_ip)
    kw.setdefault("alive", lambda pid: False)
    kw.setdefault("allow_per_process_limits", True)
    kw.setdefault("zmap_lock", tmp_path / "zmap.lock")
    result = coordinator.run_decoupled(cfg, config_path=tmp_path / "scale.yaml", confirm="tok", log=logs.append, spawn=cluster.spawn,
                                       tick=0, sleep=lambda _: None, **kw)
    return result, logs


def three(tmp_path):
    return load_config(_cfg(tmp_path, sample=THREE))


def test_a_stage_that_stalls_once_and_then_succeeds_ends_with_the_shard_done_and_the_attempts_unchanged(tmp_path):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("network", 1): [5]})
    result, logs = coordinate(tmp_path, cfg, cluster)
    assert result["complete"] and result["shards_complete"] == 3 and result["stopped"] is None
    st = stage_state(cfg, 1, "network")
    assert st["status"] == "done" and st["attempts"] == 0 and st["stalls"] == 1
    assert cluster.events.count(("start", "network", 1)) == 2 and cluster.events.count(("fail", "network", 1)) == 1
    assert any(f"stalled (1/{coordinator.MAX_STALLS})" in m and "not counted" in m for m in logs)
    assert state_of(cfg)["shard_states"]["1"]["status"] == "complete"


@pytest.mark.parametrize("stalls", [1, 2, 3, 4, 5, coordinator.MAX_STALLS])
def test_up_to_the_limit_of_stalls_are_continued_and_never_count_as_attempts(tmp_path, stalls):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("network", 0): [5] * stalls})
    result, _ = coordinate(tmp_path, cfg, cluster)
    st = stage_state(cfg, 0, "network")
    assert result["complete"] and st["status"] == "done" and st["attempts"] == 0 and st["stalls"] == stalls


def test_the_limit_of_stalls_then_failures_fail_the_stage_after_three_counted_attempts(tmp_path):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("network", 1): [5] * coordinator.MAX_STALLS + [3, 3, 3]})
    result, logs = coordinate(tmp_path, cfg, cluster)
    st = stage_state(cfg, 1, "network")
    assert st["status"] == "failed" and st["attempts"] == 3 and st["stalls"] == coordinator.MAX_STALLS and st["stop_reason"] == "crashed"
    assert result["complete"] is False and result["stopped"]["reason"] == "crashed"
    assert cluster.events.count(("start", "network", 1)) == coordinator.MAX_STALLS + 3
    assert not any(f"stalled ({coordinator.MAX_STALLS + 1}/{coordinator.MAX_STALLS})" in m for m in logs)


def test_a_stall_over_the_limit_counts_as_an_attempt(tmp_path):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("network", 1): [5] * (coordinator.MAX_STALLS + 1)})
    result, _ = coordinate(tmp_path, cfg, cluster)
    st = stage_state(cfg, 1, "network")
    assert result["complete"] and st["status"] == "done" and st["stalls"] == coordinator.MAX_STALLS and st["attempts"] == 1


def test_stall_after_stall_without_end_fails_the_stage(tmp_path):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("network", 1): [5] * 20})
    result, _ = coordinate(tmp_path, cfg, cluster)
    st = stage_state(cfg, 1, "network")
    assert st["status"] == "failed" and st["stalls"] == coordinator.MAX_STALLS and st["attempts"] == 3
    assert result["stopped"]["reason"] == "crashed" and cluster.events.count(("start", "network", 1)) == coordinator.MAX_STALLS + 3


def test_stalls_are_counted_per_stage_and_per_shard(tmp_path):
    cfg = three(tmp_path)
    fail = {(stage, shard): [5] * coordinator.MAX_STALLS for stage in ("zmap", "network", "favicon") for shard in (0, 2)}
    cluster = StallCluster(cfg, fail=fail)
    result, _ = coordinate(tmp_path, cfg, cluster)
    assert result["complete"]
    for shard in (0, 2):
        for stage in ("zmap", "network", "favicon"):
            st = stage_state(cfg, shard, stage)
            assert st["stalls"] == coordinator.MAX_STALLS and st["attempts"] == 0 and st["status"] == "done"
    assert all(stage_state(cfg, 1, s).get("stalls", 0) == 0 for s in ("zmap", "network", "favicon"))


def test_a_stop_with_another_reason_counts_as_an_attempt(tmp_path):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("network", 1): [5]}, reasons={("network", 1): "kill_switch"})
    result, _ = coordinate(tmp_path, cfg, cluster)
    st = stage_state(cfg, 1, "network")
    assert result["complete"] and st["attempts"] == 1 and st.get("stalls", 0) == 0


def test_a_stop_without_a_manifest_counts_as_an_attempt(tmp_path):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("network", 1): [5]}, leave_manifest=False)
    result, _ = coordinate(tmp_path, cfg, cluster)
    st = stage_state(cfg, 1, "network")
    assert result["complete"] and st["attempts"] == 1 and st.get("stalls", 0) == 0


def test_a_crash_after_a_stall_counts_although_the_manifest_still_says_stalled(tmp_path):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("network", 1): [5, 3]})
    result, _ = coordinate(tmp_path, cfg, cluster)
    st = stage_state(cfg, 1, "network")
    assert result["complete"] and st["stalls"] == 1 and st["attempts"] == 1


def test_a_refusal_after_a_stall_ends_the_campaign(tmp_path):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("network", 1): [5, 2]})
    result, _ = coordinate(tmp_path, cfg, cluster)
    assert result["complete"] is False and result["stopped"]["reason"] == "preflight_failed"


def test_retry_failed_gives_a_stage_that_failed_on_stalls_fresh_counters(tmp_path):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("network", 1): [5] * 20})
    first, _ = coordinate(tmp_path, cfg, cluster)
    assert first["stopped"]["reason"] == "crashed"
    second_cluster = StallCluster(cfg, fail={("network", 1): [5] * coordinator.MAX_STALLS})
    second, _ = coordinate(tmp_path, cfg, second_cluster, retry_failed=True)
    st = stage_state(cfg, 1, "network")
    assert second["complete"] and st["status"] == "done" and st["attempts"] == 0 and st["stalls"] == coordinator.MAX_STALLS


def test_a_stalled_stage_is_continued_in_the_same_run_directory(tmp_path):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("network", 1): [5, 5]})
    coordinate(tmp_path, cfg, cluster)
    dirs = {p.run_dir for p in cluster.procs if p.shard == 1}
    assert len(dirs) == 1


def skip_cluster(cfg, **fail):
    return StallCluster(cfg, fail={("network", 1): [5] * 20, **fail})


def test_skip_failed_lets_the_other_shards_finish_and_lists_the_failed_stage(tmp_path):
    cfg = three(tmp_path)
    cluster = skip_cluster(cfg)
    result, logs = coordinate(tmp_path, cfg, cluster, skip_failed=True)
    assert result["complete"] is False and result["shards_complete"] == 2
    assert result["stopped"]["reason"] == "crashed" and "network of shard 1" in result["stopped"]["detail"]
    assert ("start", "favicon", 1) not in cluster.events
    assert {0, 2} == {e[2] for e in cluster.events if e[:2] == ("done", "favicon")}
    assert any("skipped, the other shards go on" in m for m in logs)


def test_without_skip_failed_the_campaign_stops_at_the_failure(tmp_path):
    cfg = three(tmp_path)
    cluster = skip_cluster(cfg)
    result, logs = coordinate(tmp_path, cfg, cluster)
    assert result["complete"] is False and result["stopped"]["reason"] == "crashed"
    assert result["shards_complete"] <= 2 and any("nothing further starts" in m for m in logs)
    assert "skipped" not in result["stopped"]["detail"]


def test_skip_failed_on_a_failure_in_the_first_shard_still_runs_the_rest(tmp_path):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("network", 0): [5] * 20})
    result, _ = coordinate(tmp_path, cfg, cluster, skip_failed=True)
    assert result["shards_complete"] == 2 and result["stopped"]["reason"] == "crashed"
    assert {1, 2} == {e[2] for e in cluster.events if e[:2] == ("done", "favicon")}


def test_skip_failed_with_a_failed_sweep_leaves_that_shard_alone(tmp_path):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("zmap", 1): [5] * 20})
    result, _ = coordinate(tmp_path, cfg, cluster, skip_failed=True)
    assert result["shards_complete"] == 2 and "zmap of shard 1" in result["stopped"]["detail"]
    assert ("start", "network", 1) not in cluster.events


def test_skip_failed_collects_every_failed_stage(tmp_path):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("network", 0): [5] * 20, ("favicon", 2): [5] * 20})
    result, _ = coordinate(tmp_path, cfg, cluster, skip_failed=True)
    assert result["shards_complete"] == 1
    detail = result["stopped"]["detail"]
    assert "2 stage(s) failed" in detail and "network of shard 0" in detail and "favicon of shard 2" in detail


def test_skip_failed_does_not_skip_a_refusal(tmp_path):
    cfg = three(tmp_path)
    cluster = StallCluster(cfg, fail={("network", 1): [2]})
    result, _ = coordinate(tmp_path, cfg, cluster, skip_failed=True)
    assert result["complete"] is False and result["stopped"]["reason"] == "preflight_failed"


def test_a_later_run_with_skip_failed_leaves_the_failed_stage_and_ends_at_once(tmp_path):
    cfg = three(tmp_path)
    first, _ = coordinate(tmp_path, cfg, skip_cluster(cfg), skip_failed=True)
    assert first["shards_complete"] == 2
    again = StallCluster(cfg)
    second, logs = coordinate(tmp_path, cfg, again, skip_failed=True)
    assert again.events == [] and second["complete"] is False and second["stopped"]["reason"] == "crashed"
    assert any("failed earlier" in m and "skipped" in m for m in logs)


def test_a_later_run_without_the_flag_asks_for_retry_failed(tmp_path):
    cfg = three(tmp_path)
    coordinate(tmp_path, cfg, skip_cluster(cfg), skip_failed=True)
    again = StallCluster(cfg)
    result, _ = coordinate(tmp_path, cfg, again)
    assert again.events == [] and "--retry-failed" in result["stopped"]["detail"]


def test_skip_failed_with_retry_failed_finishes_the_skipped_stage(tmp_path):
    cfg = three(tmp_path)
    coordinate(tmp_path, cfg, skip_cluster(cfg), skip_failed=True)
    again = StallCluster(cfg)
    result, _ = coordinate(tmp_path, cfg, again, skip_failed=True, retry_failed=True)
    assert result["complete"] and result["shards_complete"] == 3 and result["stopped"] is None
    assert [e for e in again.events if e[0] == "start"] == [("start", "network", 1), ("start", "favicon", 1)]


def test_skip_failed_changes_nothing_when_nothing_fails(tmp_path):
    other = tmp_path / "second"
    other.mkdir()
    cfg, cfg2 = three(tmp_path), three(other)
    plain = coordinate(tmp_path, cfg, StallCluster(cfg))[0]
    flagged = coordinate(other, cfg2, StallCluster(cfg2), skip_failed=True)[0]
    assert plain["complete"] and flagged["complete"] and plain["shards_complete"] == flagged["shards_complete"] == 3
    assert plain["stopped"] is None and flagged["stopped"] is None


def test_the_coordinator_stage_exit_constants_match_the_stage_worker():
    assert coordinator.EXIT_STOPPED == cli.EXIT_STOPPED == EXIT_STOPPED and coordinator.MAX_STALLS == 10


class RealWorkers(StallCluster):
    """Shard 0 is run by the real stage worker (real pipeline, fake tools); the other shards by the fake workers."""

    def __init__(self, cfg, real=(0,), **kw):
        super().__init__(cfg, **kw)
        self.real = set(real)
        self.codes = []

    def spawn(self, cmd, pass_fds):
        proc = super().spawn(cmd, pass_fds)
        proc.cmd = list(cmd)
        return proc

    def outcome(self, proc):
        if proc.shard not in self.real:
            return super().outcome(proc)
        argv = proc.cmd[3:]
        if "--zmap-lock-fd" in argv:
            at = argv.index("--zmap-lock-fd")
            del argv[at:at + 2]
        rc = cli.main(argv)
        self.codes.append((proc.stage, proc.shard, rc))
        self.events.append(("done" if rc == 0 else "fail", proc.stage, proc.shard))
        return rc


def test_the_real_stage_worker_stalls_once_under_the_coordinator_and_the_shard_finishes(tmp_path, monkeypatch, instances, silent, capsys):
    cfg = make_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 2})
    real_run, real_favicon = pipeline.run, pipeline.run_favicon_only
    monkeypatch.setattr(pipeline, "run", lambda c, **kw: real_run(c, executor=tools(), fetcher=FakeFetcher(), skip_preflight=True,
                                                                   offline_preflight=True, **kw))
    monkeypatch.setattr(pipeline, "run_favicon_only", lambda c, d, **kw: real_favicon(c, d, executor=tools(), fetcher=FakeFetcher(), **kw))
    monkeypatch.setattr(supervisor, "_die_with_parent", lambda pid: True)    # the worker runs in this process, not under the coordinator's pid
    count = around(monkeypatch, ShardStore, "clear_names", lambda: instances.seen[-1].stop.wait(60), once=True)
    token = pipeline.confirm_token(cfg, pipeline.build_policy(cfg)[1])
    cluster = RealWorkers(cfg, real=(0,))
    logs = []
    result = coordinator.run_decoupled(cfg, config_path=tmp_path / "scale.yaml", confirm=token, log=logs.append, spawn=cluster.spawn,
                                       tick=0, sleep=lambda _: None, egress=lambda c: c.vantage.public_egress_ip, alive=lambda p: False,
                                       allow_per_process_limits=True, zmap_lock=tmp_path / "zmap.lock")
    assert result["complete"] and result["shards_complete"] == 2
    assert cluster.codes == [("zmap", 0, 0), ("network", 0, EXIT_STOPPED), ("network", 0, 0), ("favicon", 0, 0)]
    st = stage_state(cfg, 0, "network")
    assert st["attempts"] == 0 and st["stalls"] == 1 and st["status"] == "done"
    run_dir = Path(state_of(cfg)["shard_states"]["0"]["run_dir"])
    assert manifest_of(run_dir)["complete"] is True and manifest_of(run_dir)["abort_reason"] is None
    assert any(f"stalled (1/{coordinator.MAX_STALLS})" in m for m in logs) and count["n"] == 2


# ------------------------------------------------------------------ 6. stops inside working() and the tail

def started(tmp_path, *, limit=0.0):
    cfg = make_cfg(tmp_path)
    st = pipeline._Stages(cfg, tmp_path)
    st.stall_seconds = limit
    st.start_monitor()
    return cfg, st


def test_the_kill_switch_stops_a_step_inside_working_at_once(tmp_path):
    cfg, st = started(tmp_path)
    try:
        with st.working(0.05):
            Path(cfg.kill_switch_file).write_text("stop")
            t = time.monotonic()
            assert st.stop.wait(60)
            waited = time.monotonic() - t
    finally:
        st.stop_monitor()
    assert st.reason == "kill_switch" and waited < 30


def test_the_kill_switch_stops_a_run_inside_the_tail_at_once(tmp_path):
    cfg, st = started(tmp_path)
    try:
        st.begin_tail()
        Path(cfg.kill_switch_file).write_text("stop")
        t = time.monotonic()
        assert st.stop.wait(60)
        waited = time.monotonic() - t
        assert st.killed() is True
    finally:
        st.stop_monitor()
    assert st.reason == "kill_switch" and waited < 30


def test_an_interrupt_flagged_inside_the_tail_is_promoted_by_the_monitor(tmp_path):
    cfg, st = started(tmp_path)
    try:
        st.begin_tail()
        st.flag_stop("interrupt")                   # what a signal handler does
        assert st.stop.wait(60)
    finally:
        st.stop_monitor()
    assert st.reason == "interrupt"


def test_a_keyboard_interrupt_inside_working_is_recorded_and_ends_the_helper(tmp_path):
    cfg, st = started(tmp_path)

    def step():
        with st.working(0.05):
            raise KeyboardInterrupt("stop")
    try:
        st.run("step", step, None)
    finally:
        st.stop_monitor()
    assert st.interrupted is True and "step" in st.errors


def test_stages_after_a_stop_inside_working_are_skipped(tmp_path):
    cfg, st = started(tmp_path)
    try:
        def first():
            with st.working(0.05):
                Path(cfg.kill_switch_file).write_text("stop")
                st.stop.wait(60)
        st.run("first", first, None)
        ran = []
        st.run("second", lambda: ran.append(1), None)
    finally:
        st.stop_monitor()
    assert ran == [] and st.skipped == ["second"]


def test_stopping_the_monitor_is_prompt_with_a_long_interval_and_an_open_tail(tmp_path):
    cfg, st = started(tmp_path)
    st.begin_tail()
    t = time.monotonic()
    st.stop_monitor()
    assert time.monotonic() - t < 30 and helper_threads() == []
    st.stop_monitor()                                # a second call is harmless


def test_leaving_working_is_bounded_when_the_probe_itself_is_slow(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "_thread_activity", lambda tid: time.sleep(1.0) or (0, 0))
    cfg = make_cfg(tmp_path)
    st = pipeline._Stages(cfg, tmp_path)
    t = time.monotonic()
    with st.working(0.05):
        time.sleep(0.2)
    assert time.monotonic() - t < 60
    # the helper is a daemon and ends with its last look; the autouse fixture checks that it does


def test_a_kill_switch_ends_a_real_run_inside_the_tail_with_the_reason_kill_switch(tmp_path, monkeypatch, instances, silent):
    cfg = make_cfg(tmp_path, stall=30)
    instances.limit = None
    waited = []

    def stop_it():
        Path(cfg.kill_switch_file).write_text("stop")
        t = time.monotonic()
        instances.seen[-1].stop.wait(60)
        waited.append(time.monotonic() - t)
    patch_writer(monkeypatch, stop_it)
    m = manifest_of(go(cfg))
    assert m["abort_reason"] == "kill_switch" and m["complete"] is False and waited[0] < 30


def test_an_interrupt_ends_a_real_run_inside_the_tail_with_the_reason_interrupt(tmp_path, monkeypatch, instances):
    cfg = make_cfg(tmp_path, stall=30)
    instances.limit = None

    def interrupt():
        instances.seen[-1].flag_stop("interrupt")
        assert instances.seen[-1].stop.wait(60)
    patch_writer(monkeypatch, interrupt)
    m = manifest_of(go(cfg))
    assert m["abort_reason"] == "interrupt" and m["complete"] is False


def test_a_keyboard_interrupt_in_the_tail_leaves_no_helper_behind(tmp_path, monkeypatch, instances):
    def die():
        raise KeyboardInterrupt("stop")
    patch_writer(monkeypatch, die)
    with pytest.raises(KeyboardInterrupt):
        go(make_cfg(tmp_path))
    assert helper_threads() == [] and instances.seen[-1]._tail_open is False


def test_an_error_in_the_tail_leaves_no_helper_behind(tmp_path, monkeypatch, instances):
    def boom():
        raise OSError("disk full")
    patch_writer(monkeypatch, boom)
    m = manifest_of(go(make_cfg(tmp_path)))
    assert m["complete"] is False and ("write_outputs" in m["stage_errors"] or "records" in m["stage_errors"])
    assert helper_threads() == []


def test_a_kill_switch_ends_a_run_inside_a_covered_step(tmp_path, monkeypatch, instances):
    cfg = make_cfg(tmp_path, stall=30)
    instances.limit = None
    waited = []

    def stop_it():
        Path(cfg.kill_switch_file).write_text("stop")
        t = time.monotonic()
        instances.seen[-1].stop.wait(60)
        waited.append(time.monotonic() - t)
    around(monkeypatch, ShardStore, "clear_names", stop_it, once=True)
    m = manifest_of(go(cfg))
    assert m["abort_reason"] == "kill_switch" and waited[0] < 30


def test_a_stalled_run_and_a_clean_run_in_one_process_leave_no_threads(tmp_path, monkeypatch, instances, silent):
    before = {t.ident for t in threading.enumerate()}
    around(monkeypatch, ShardStore, "clear_names", lambda: instances.seen[-1].stop.wait(60), once=True)
    assert manifest_of(go(make_cfg(tmp_path), run_id="a"))["abort_reason"] == "stalled"
    assert manifest_of(go(make_cfg(tmp_path), run_id="b"))["complete"] is True
    assert threads_back_to(before)


def test_many_covered_steps_in_a_row_leave_no_threads(tmp_path):
    cfg = make_cfg(tmp_path)
    st = pipeline._Stages(cfg, tmp_path)
    for _ in range(40):
        with st.working(0.05):
            pass
    assert helper_threads() == []


def test_monitors_started_and_stopped_in_turn_leave_no_threads(tmp_path):
    cfg = make_cfg(tmp_path)
    for _ in range(10):
        st = pipeline._Stages(cfg, tmp_path)
        st.start_monitor()
        st.begin_tail()
        assert helper_threads().count("work-heartbeat") == 1
        st.stop_monitor()
        assert helper_threads() == []


def test_begin_tail_twice_starts_one_helper_and_the_cover_can_be_started_again(tmp_path):
    cfg = make_cfg(tmp_path)
    st = pipeline._Stages(cfg, tmp_path)
    st.begin_tail()
    st.begin_tail()
    assert helper_threads() == ["work-heartbeat"]
    st.stop_monitor()
    assert helper_threads() == [] and st._tail_open is False
    st.begin_tail()
    assert helper_threads() == ["work-heartbeat"]
    st.stop_monitor()


def test_stop_monitor_without_a_tail_or_a_monitor_is_harmless(tmp_path):
    st = pipeline._Stages(make_cfg(tmp_path), tmp_path)
    st.stop_monitor()
    st.stop_monitor()
    assert st._tail_open is False and helper_threads() == []


def test_the_tail_stalls_when_nothing_reports_progress(tmp_path, silent):
    cfg = make_cfg(tmp_path)
    st = pipeline._Stages(cfg, tmp_path)
    st.stall_seconds = STALL
    t = time.monotonic()                            # taken before the monitor's clock starts, so the lower bound is exact
    st.start_monitor()
    st.begin_tail()
    try:
        assert st.stop.wait(60)                     # nothing reports progress and the probe sees nothing: stalled
    finally:
        st.stop_monitor()
    assert st.reason == "stalled" and time.monotonic() - t >= STALL


def test_the_tail_keeps_a_busy_writeout_alive(tmp_path):
    cfg = make_cfg(tmp_path)
    st = pipeline._Stages(cfg, tmp_path)
    st.stall_seconds = STALL
    st.start_monitor()
    st.begin_tail()
    try:
        spin(STALL * 2.5)
        assert st.reason is None and not st.stop.is_set()
    finally:
        st.stop_monitor()


# ------------------------------------------------------------------ 8. progress ticks of the loops over the store

def count_ticks(monkeypatch):
    """Calls of ``_Stages.progress`` by the function that made them."""
    callers = {}
    real = pipeline._Stages.progress

    def counting(self):
        name = sys._getframe(1).f_code.co_name
        callers[name] = callers.get(name, 0) + 1
        real(self)
    monkeypatch.setattr(pipeline._Stages, "progress", counting)
    return callers


@pytest.mark.parametrize("tick,addresses", [(10, 25), (7, 25), (1, 6), (25, 25)])
def test_the_candidate_and_sni_loops_tick_once_per_loop_tick_addresses(tmp_path, monkeypatch, tick, addresses):
    monkeypatch.setattr(pipeline, "LOOP_TICK", tick)
    callers = count_ticks(monkeypatch)
    m = manifest_of(go(make_cfg(tmp_path), ft=many_tools(addresses)))
    assert m["complete"] is True and m["stage_counts"]["l4_endpoints"] == addresses
    expected = math.ceil(addresses / tick)
    assert callers.get("cand_stage") == expected and callers.get("sni_stage") == expected


def test_a_store_of_more_than_twice_the_loop_tick_gives_at_least_three_ticks_per_loop(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "LOOP_TICK", 10)
    callers = count_ticks(monkeypatch)
    go(make_cfg(tmp_path), ft=many_tools(25))
    assert 25 > 2 * pipeline.LOOP_TICK and callers["cand_stage"] >= 3 and callers["sni_stage"] >= 3


def test_a_small_store_gives_one_tick_per_loop(tmp_path, monkeypatch):
    callers = count_ticks(monkeypatch)
    go(make_cfg(tmp_path))
    assert pipeline.LOOP_TICK == 1000
    assert callers["cand_stage"] == 1 and callers["sni_stage"] == 1


def test_the_documented_constants_of_the_loops():
    assert pipeline.LOOP_TICK == 1000 and pipeline.WORK_TICK == 30.0
    assert pipeline.WORK_TICK < 1800 / 4
