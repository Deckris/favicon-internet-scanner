"""Decoupled campaigns: stalled stages continue in place, and --skip-failed lets the other shards finish.

Fake stage workers stand in for the processes; every scenario runs on a tick counter with a bounded number of ticks."""
import inspect
import json
import re
import signal
from pathlib import Path

import pytest

from scanner.internet import __main__ as cli
from scanner.internet import campaign, coordinator, pipeline
from scanner.internet.config import load_config
from tests.test_coordinator import Cluster, FakeProc, SweepCluster, _zmap_done_entry, make_cfg, seed_state, state_of
from tests.test_scale import _cfg

STALL = (coordinator.EXIT_STOPPED, "stalled")
ABSENT = object()                       # the failing worker leaves the manifest as it was
CORRUPT = object()                      # the failing worker leaves an unreadable manifest
MAX_TICKS = 3000
OTHER_EGRESS = "203.0.113.9"


@pytest.fixture(autouse=True)
def direct_state_writes(monkeypatch):
    """Write state files in one step: the write-then-rename of the real helper doubles the file operations of every tick."""
    def write(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str), encoding="utf-8")
    monkeypatch.setattr(campaign, "_write_json", write)


class Runaway(Exception):
    pass


class StallProc(FakeProc):
    def send_signal(self, sig):
        spec = self.cluster.on_term.get((self.stage, self.shard))
        if spec is None:
            super().send_signal(sig)
            return
        self.signals.append(sig)
        self.rc = self.cluster.fail_with(self, *spec)


class Sim(Cluster):
    """Fake workers with a script per (stage, shard): a list is consumed one entry per start (then the worker succeeds), a
    bare entry applies to every start. An entry is a return code or a (return code, abort_reason) pair."""

    def __init__(self, cfg, script=None, durations=None, on_term=None, zero_responsive=()):
        super().__init__(cfg, durations=durations)
        self.script = {k: (list(v) if isinstance(v, list) else v) for k, v in (script or {}).items()}
        self.on_term = on_term or {}
        self.zero_responsive = set(zero_responsive)
        self.peaks = {"zmap": 0, "network": 0, "favicon": 0}

    def duration(self, stage, shard):
        return self.durations.get((stage, shard), 1)

    def spawn(self, cmd, pass_fds):
        stage, shard, run_dir = cmd[cmd.index("--stage") + 1], int(cmd[cmd.index("--shard") + 1]), cmd[cmd.index("--run-dir") + 1]
        assert not (stage == "zmap" and [p for p in self.procs if p.stage == "zmap" and p.rc is None]), "two ZMap stages at once"
        self.next_pid += 1
        proc = StallProc(self, stage, shard, run_dir, self.next_pid)
        self.procs.append(proc)
        self.events.append(("start", stage, shard))
        self.peaks[stage] = max(self.peaks[stage], len([p for p in self.procs if p.stage == stage and p.rc is None]))
        return proc

    def fail_with(self, proc, rc, abort):
        run_dir = proc.run_dir
        run_dir.mkdir(parents=True, exist_ok=True)
        target = run_dir / "manifest.json"
        if abort is CORRUPT:
            target.write_text("{not json")
        elif abort is not ABSENT:
            old = json.loads(target.read_text()) if target.exists() else {}
            target.write_text(json.dumps({**old, "abort_reason": abort}))
        self.events.append(("fail", proc.stage, proc.shard))
        return rc

    def outcome(self, proc):
        key = (proc.stage, proc.shard)
        script = self.script.get(key)
        item = None
        if isinstance(script, list):
            if script:
                item = script.pop(0)
        elif script is not None:
            item = script
        if item is not None:
            rc, abort = item if isinstance(item, tuple) else (item, ABSENT)
            if rc != 0 or isinstance(item, tuple):
                return self.fail_with(proc, rc, abort)
        rc = super().outcome(proc)
        if proc.stage == "network" and proc.shard in self.zero_responsive:
            target = proc.run_dir / "manifest.json"
            target.write_text(json.dumps({**json.loads(target.read_text()), "zero_responsive": True}))
        return rc


class Out:
    def __init__(self, cfg, cluster, result, logs, ticks):
        self.cfg, self.cluster, self.result, self.logs, self.ticks = cfg, cluster, result, logs, ticks

    @property
    def stop(self):
        return self.result["stopped"]

    @property
    def text(self):
        return "\n".join(self.logs)

    def stage(self, shard, name):
        return state_of(self.cfg)["shard_states"][str(shard)]["stages"][name]

    def entry(self, shard):
        return state_of(self.cfg)["shard_states"][str(shard)]

    def starts(self, name, shard):
        return self.cluster.events.count(("start", name, shard))

    def started(self, name):
        return [e[2] for e in self.cluster.events if e[:2] == ("start", name)]


def go(cfg, cluster, tmp_path, on_tick=None, max_ticks=MAX_TICKS, **kw):
    kw.setdefault("egress", lambda c: c.vantage.public_egress_ip)
    kw.setdefault("alive", lambda pid: False)
    kw.setdefault("allow_per_process_limits", True)
    kw.setdefault("zmap_lock", tmp_path / "zmap.lock")
    logs, ticks = [], [0]

    def sleep(_):
        ticks[0] += 1
        if ticks[0] > max_ticks:
            raise Runaway(f"no end after {max_ticks} ticks")
        if on_tick:
            on_tick(ticks[0])
    result = coordinator.run_decoupled(cfg, config_path=tmp_path / "scale.yaml", confirm="tok", log=logs.append,
                                       spawn=cluster.spawn, tick=0, sleep=sleep, **kw)
    return Out(cfg, cluster, result, logs, ticks[0])


def seed_stage(cfg, shard, zmap_done=True, network_done=False, **fields):
    """A state file entry whose zmap (and optionally network) stage is done and whose next stage has ``fields``."""
    entry = coordinator._entry_for(cfg, shard, None)
    names = coordinator.STAGES
    done = names[:2] if network_done else names[:1] if zmap_done else ()
    for n in done:
        entry["stages"][n] = coordinator._done_stage()
    nxt = names[len(done)]
    entry["stages"][nxt].update(fields)
    entry["status"] = coordinator.derive_status(entry["stages"])
    seed_state(cfg, {shard: entry})
    return entry


def crash_all(*keys, rc=1):
    return {k: rc for k in keys}


# ------------------------------------------------------------------ constants and signature

def test_constants():
    assert coordinator.MAX_STALLS == 10 and coordinator.EXIT_STOPPED == 5
    assert coordinator.EXIT_STOPPED == cli.EXIT_STOPPED == cli.CAMPAIGN_EXIT["stalled"]
    assert coordinator.EXIT_STOPPED not in (coordinator.EXIT_REFUSED, coordinator.EXIT_RECYCLE, coordinator.EXIT_ZMAP_MISSING)


def test_skip_failed_defaults_to_false():
    assert inspect.signature(coordinator.run_decoupled).parameters["skip_failed"].default is False
    assert inspect.signature(coordinator._coordinate).parameters["skip_failed"].default is False


# ------------------------------------------------------------------ stall resume

def test_first_stall_continues_in_place_without_counting_an_attempt(tmp_path):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, {("network", 1): [STALL, 0]}), tmp_path)
    assert out.result["complete"] and out.stop is None
    assert out.starts("network", 1) == 2
    st = out.stage(1, "network")
    assert st["status"] == "done" and st["attempts"] == 0 and st["stalls"] == 1


@pytest.mark.parametrize("n", [1, 3, coordinator.MAX_STALLS])
def test_up_to_the_limit_of_stalls_never_costs_an_attempt(tmp_path, n):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {("network", 0): [STALL] * n}), tmp_path)
    assert out.result["complete"]
    assert out.starts("network", 0) == n + 1
    st = out.stage(0, "network")
    assert st["attempts"] == 0 and st["stalls"] == n


def test_the_stall_after_the_limit_counts_as_an_attempt(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {("network", 0): [STALL] * (coordinator.MAX_STALLS + 1)}), tmp_path)
    assert out.result["complete"]
    st = out.stage(0, "network")
    assert st["stalls"] == coordinator.MAX_STALLS == 10 and st["attempts"] == 1
    assert out.starts("network", 0) == coordinator.MAX_STALLS + 2
    assert "attempt 1 failed (exited with code 5); will retry" in out.text


@pytest.mark.parametrize("name", ["zmap", "network", "favicon"])
def test_endless_stalls_use_the_free_continuations_then_three_attempts(tmp_path, name):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {(name, 0): STALL}), tmp_path)
    assert out.stop["reason"] == "crashed" and out.stop["stage"] == name and out.stop["shard"] == 0
    assert out.starts(name, 0) == coordinator.MAX_STALLS + coordinator.MAX_ATTEMPTS
    st = out.stage(0, name)
    assert st["status"] == "failed" and st["attempts"] == 3 and st["stalls"] == coordinator.MAX_STALLS and st["stop_reason"] == "crashed"
    assert "exited with code 5" in st["error"]
    assert f"{name} failed after 3 attempts" in out.text


def test_the_final_error_names_the_stalls_continued_before_it(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {("network", 0): STALL}), tmp_path)
    st = out.stage(0, "network")
    suffix = f"; after {coordinator.MAX_STALLS} stalls continued in place"
    assert st["error"] == "exited with code 5" + suffix and len(st["error"]) <= 500
    assert f"failed after 3 attempts: exited with code 5{suffix}" in out.text
    assert suffix in out.stop["detail"]


@pytest.mark.parametrize("name", ["zmap", "network", "favicon"])
def test_a_stalled_stage_is_started_again_in_a_new_process_at_once(tmp_path, name):
    cfg = make_cfg(tmp_path, shards=2)
    cluster = Sim(cfg, {(name, 0): [STALL]}, durations={(name, 0): 3})
    seen = []

    def tick(_):
        if not seen and ("fail", name, 0) in cluster.events:
            st = state_of(cfg)["shard_states"]["0"]["stages"][name]
            seen.append((st["status"], st["stalls"], st["attempts"], st["owner_pid"]))
    go(cfg, cluster, tmp_path, on_tick=tick)
    first, second = [p for p in cluster.procs if p.stage == name and p.shard == 0]
    assert seen[0] == ("running", 1, 0, second.pid) and first.pid != second.pid


@pytest.mark.parametrize("name,expect", [("zmap", "pending"), ("network", "zmap_done"), ("favicon", "network_done")])
def test_a_stalled_stage_leaves_pending_and_the_shard_status_after_a_halt(tmp_path, name, expect):
    cfg = make_cfg(tmp_path, shards=2)
    refused = ("network", 0) if name == "zmap" else (name, 0)
    cluster = Sim(cfg, {(name, 1): [STALL], refused: coordinator.EXIT_REFUSED}, durations={(name, 1): 40, refused: 20})
    out = go(cfg, cluster, tmp_path)
    assert out.stop["reason"] == "preflight_failed"
    st = out.stage(1, name)
    assert st["status"] == "pending" and st["stalls"] == 1 and st["attempts"] == 0
    assert out.entry(1)["status"] == expect


@pytest.mark.parametrize("n", [1, coordinator.MAX_STALLS])
def test_stall_log_text(tmp_path, n):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {("favicon", 1): [STALL] * n}), tmp_path)
    lines = [l for l in out.logs if "stalled (" in l]
    assert len(lines) == n
    assert lines[-1] == (f"[coordinator] shard 2/2 favicon stalled ({n}/{coordinator.MAX_STALLS}); continuing in place, the attempt is not counted")
    assert not any("attempt" in l and "failed" in l and "favicon" in l for l in out.logs)


@pytest.mark.parametrize("limit", [0, 2, 10])
def test_stall_limit_is_read_at_run_time(tmp_path, monkeypatch, limit):
    monkeypatch.setattr(coordinator, "MAX_STALLS", limit)
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {("network", 0): STALL}), tmp_path)
    assert out.starts("network", 0) == limit + coordinator.MAX_ATTEMPTS
    assert out.stage(0, "network").get("stalls", 0) == limit


def test_stall_counter_persists_across_a_coordinator_restart(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    first = Sim(cfg, {("network", 0): [STALL, STALL]}, durations={("network", 0): 50})
    switch = Path(cfg.kill_switch_file)
    switch.parent.mkdir(parents=True, exist_ok=True)

    def tick(_):
        if first.events.count(("start", "network", 0)) == 3:
            switch.write_text("stop")
    out = go(cfg, first, tmp_path, on_tick=tick)
    assert out.stop["reason"] == "kill_switch"
    assert out.stage(0, "network")["stalls"] == 2 and out.stage(0, "network")["attempts"] == 0
    assert out.stage(0, "network")["status"] == "pending"
    switch.unlink()
    again = go(cfg, Sim(cfg, {("network", 0): [STALL]}), tmp_path)
    assert again.result["complete"]
    assert again.stage(0, "network")["stalls"] == 3 and again.stage(0, "network")["attempts"] == 0
    assert again.starts("zmap", 0) == 0


def test_restart_after_exhausted_stalls_keeps_the_count(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    seed_stage(cfg, 0, status="pending", stalls=coordinator.MAX_STALLS - 1)
    out = go(cfg, Sim(cfg, {("network", 0): STALL}), tmp_path)
    assert out.starts("network", 0) == 1 + coordinator.MAX_ATTEMPTS
    assert out.stage(0, "network")["stalls"] == coordinator.MAX_STALLS


def test_stall_then_success_keeps_the_stall_count_after_done(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {("zmap", 1): [STALL, STALL]}), tmp_path)
    assert out.result["complete"]
    st = out.stage(1, "zmap")
    assert st["status"] == "done" and st["stalls"] == 2 and st["attempts"] == 0 and st["error"] is None


MANIFEST_NOT_STALLED = [ABSENT, CORRUPT, None, "kill_switch", "interrupt", "STALLED", 5, ["stalled"]]


@pytest.mark.parametrize("abort", MANIFEST_NOT_STALLED, ids=lambda a: repr(a)[:20])
def test_exit_five_without_a_stalled_manifest_counts_as_an_attempt(tmp_path, abort):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {("network", 0): (coordinator.EXIT_STOPPED, abort)}), tmp_path)
    assert out.stop["reason"] == "crashed"
    assert out.starts("network", 0) == 3
    st = out.stage(0, "network")
    assert st["attempts"] == 3 and st.get("stalls", 0) == 0
    assert "stalled (" not in out.text


def test_exit_five_with_no_manifest_file_at_all_counts_as_an_attempt(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    cluster = Sim(cfg, {("zmap", 0): (5, ABSENT)})
    out = go(cfg, cluster, tmp_path)
    assert not (Path(out.entry(0)["run_dir"]) / "manifest.json").exists()
    assert out.starts("zmap", 0) == 3 and out.stage(0, "zmap").get("stalls", 0) == 0


@pytest.mark.parametrize("rc", [1, 4, 255, -9, 137, 0])
def test_a_stalled_manifest_without_exit_five_counts_as_an_attempt(tmp_path, rc):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {("network", 0): (rc, "stalled")}), tmp_path)
    assert out.stop["reason"] == "crashed"
    assert out.starts("network", 0) == 3
    st = out.stage(0, "network")
    assert st["attempts"] == 3 and st.get("stalls", 0) == 0


def test_exit_zero_with_a_stalled_manifest_is_not_a_finished_stage(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {("network", 0): [(0, "stalled"), 0]}), tmp_path)
    assert out.result["complete"]
    st = out.stage(0, "network")
    assert st["attempts"] == 1 and st.get("stalls", 0) == 0


def test_refusal_exit_is_never_a_stall(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {("zmap", 0): (coordinator.EXIT_REFUSED, "stalled")}), tmp_path)
    assert out.stop["reason"] == "preflight_failed" and out.starts("zmap", 0) == 1
    assert out.stage(0, "zmap").get("stalls", 0) == 0


def test_recycle_exit_with_a_stalled_manifest_is_a_recycle_not_a_stall(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {("favicon", 0): [(coordinator.EXIT_RECYCLE, "stalled")]}), tmp_path)
    assert out.result["complete"]
    st = out.stage(0, "favicon")
    assert st["attempts"] == 0 and st.get("stalls", 0) == 0
    assert "recycle" in out.text


def test_stale_stalled_value_from_an_earlier_attempt_does_not_hide_a_crash(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    script = {("network", 0): [STALL, (1, ABSENT), (1, ABSENT), (1, ABSENT)]}
    out = go(cfg, Sim(cfg, script), tmp_path)
    assert out.stop["reason"] == "crashed"
    st = out.stage(0, "network")
    assert st["stalls"] == 1 and st["attempts"] == 3
    assert out.starts("network", 0) == 4


def test_a_later_attempt_that_rewrites_the_reason_ends_the_stall_streak(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    script = {("network", 0): [STALL, (coordinator.EXIT_STOPPED, "kill_switch"), 0]}
    out = go(cfg, Sim(cfg, script), tmp_path)
    assert out.result["complete"]
    st = out.stage(0, "network")
    assert st["stalls"] == 1 and st["attempts"] == 1


def test_exit_five_over_a_stale_stalled_manifest_is_read_as_a_stall(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {("network", 0): [STALL, (coordinator.EXIT_STOPPED, ABSENT), 0]}), tmp_path)
    assert out.result["complete"]
    st = out.stage(0, "network")
    assert st["stalls"] == 2 and st["attempts"] == 0


@pytest.mark.parametrize("how", ["switch", "signal"])
def test_exit_during_a_hard_stop_is_neither_a_stall_nor_an_attempt(tmp_path, how):
    cfg = make_cfg(tmp_path, shards=2)
    cluster = Sim(cfg, durations={("network", 0): 60}, on_term={("network", 0): STALL})
    switch = Path(cfg.kill_switch_file)
    switch.parent.mkdir(parents=True, exist_ok=True)

    def tick(_):
        if ("start", "network", 0) in cluster.events and not cluster.procs[-1].signals:
            if how == "switch":
                switch.write_text("stop")
            else:
                signal.raise_signal(signal.SIGTERM)
    out = go(cfg, cluster, tmp_path, on_tick=tick)
    assert out.stop["reason"] == ("kill_switch" if how == "switch" else "interrupt")
    st = out.stage(0, "network")
    assert st["status"] == "pending" and st["attempts"] == 0 and st.get("stalls", 0) == 0
    assert "stalled (" not in out.text and "ends without a result (stopped); not counted" in out.text
    assert any(p.signals and p.rc == coordinator.EXIT_STOPPED for p in cluster.procs)


def test_a_stall_after_another_stage_halted_the_campaign_is_not_restarted(tmp_path):
    cfg = make_cfg(tmp_path)
    cluster = Sim(cfg, {("network", 0): 1, ("network", 1): [STALL]}, durations={("network", 0): 6, ("network", 1): 40})
    out = go(cfg, cluster, tmp_path)
    assert out.stop["reason"] == "crashed" and out.stop["shard"] == 0
    assert out.starts("network", 1) == 1
    st = out.stage(1, "network")
    assert st["status"] == "pending" and st["stalls"] == 1 and st["attempts"] == 0


def test_stalls_are_counted_per_stage(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    script = {("zmap", 0): [STALL] * 2, ("network", 0): [STALL] * 3, ("favicon", 0): [STALL] * 4}
    out = go(cfg, Sim(cfg, script), tmp_path)
    assert out.result["complete"]
    got = {n: out.stage(0, n).get("stalls", 0) for n in coordinator.STAGES}
    assert got == {"zmap": 2, "network": 3, "favicon": 4}
    assert all(out.stage(0, n)["attempts"] == 0 for n in coordinator.STAGES)
    assert out.stage(1, "network").get("stalls", 0) == 0


def test_every_stage_has_its_own_allowance_of_stalls(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    script = {(n, 0): [STALL] * coordinator.MAX_STALLS for n in coordinator.STAGES}
    out = go(cfg, Sim(cfg, script), tmp_path)
    assert out.result["complete"]
    assert all(out.stage(0, n)["stalls"] == coordinator.MAX_STALLS and out.stage(0, n)["attempts"] == 0 for n in coordinator.STAGES)


def test_stalls_of_one_shard_do_not_use_up_those_of_another(tmp_path):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, {("network", i): [STALL] * coordinator.MAX_STALLS for i in range(3)}), tmp_path)
    assert out.result["complete"]
    assert [out.stage(i, "network")["stalls"] for i in range(3)] == [coordinator.MAX_STALLS] * 3


@pytest.mark.parametrize("used", [1, 2])
def test_attempts_already_used_are_kept_when_a_stall_follows(tmp_path, used):
    cfg = make_cfg(tmp_path, shards=2)
    seed_stage(cfg, 0, status="pending", attempts=used)
    out = go(cfg, Sim(cfg, {("network", 0): [STALL, 0]}), tmp_path)
    assert out.result["complete"]
    st = out.stage(0, "network")
    assert st["attempts"] == used and st["stalls"] == 1


def test_endless_stalls_after_two_used_attempts_fail_on_the_next_one(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    seed_stage(cfg, 0, status="pending", attempts=2)
    out = go(cfg, Sim(cfg, {("network", 0): STALL}), tmp_path)
    assert out.stop["reason"] == "crashed"
    assert out.starts("network", 0) == coordinator.MAX_STALLS + 1
    assert out.stage(0, "network")["attempts"] == 3


@pytest.mark.parametrize("cap", [1, 2, 3, 5])
def test_endless_stalls_with_a_custom_attempt_cap(tmp_path, cap):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {("network", 0): STALL}), tmp_path, max_attempts=cap)
    assert out.starts("network", 0) == coordinator.MAX_STALLS + cap
    assert out.stage(0, "network")["attempts"] == cap


@pytest.mark.parametrize("cap", [1, 2, 4])
def test_endless_crashes_with_a_custom_attempt_cap_never_stall(tmp_path, cap):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg, {("network", 0): 1}), tmp_path, max_attempts=cap)
    assert out.starts("network", 0) == cap and out.stage(0, "network").get("stalls", 0) == 0


def test_retry_failed_resets_the_stall_counter(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    seed_stage(cfg, 0, status="failed", attempts=3, stalls=5, error="exited with code 5", stop_reason="crashed")
    out = go(cfg, Sim(cfg, {("network", 0): [STALL, STALL, 0]}), tmp_path, retry_failed=True)
    assert out.result["complete"]
    st = out.stage(0, "network")
    assert st["stalls"] == 2 and st["attempts"] == 0
    assert "failed earlier (exited with code 5); trying again with fresh attempts" in out.text


def test_retry_failed_gives_a_full_stall_allowance_again(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    seed_stage(cfg, 0, status="failed", attempts=3, stalls=coordinator.MAX_STALLS, error="x", stop_reason="crashed")
    out = go(cfg, Sim(cfg, {("network", 0): STALL}), tmp_path, retry_failed=True)
    assert out.starts("network", 0) == coordinator.MAX_STALLS + coordinator.MAX_ATTEMPTS
    assert out.stage(0, "network")["stalls"] == coordinator.MAX_STALLS


def test_retry_failed_leaves_the_stalls_of_pending_stages_alone(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    seed_stage(cfg, 0, status="pending", stalls=3)
    out = go(cfg, Sim(cfg, {("network", 0): [STALL, 0]}), tmp_path, retry_failed=True)
    assert out.stage(0, "network")["stalls"] == 4


def test_without_retry_failed_a_failed_stage_keeps_its_counters(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    seed_stage(cfg, 0, status="failed", attempts=3, stalls=5, error="x", stop_reason="crashed")
    out = go(cfg, Sim(cfg), tmp_path)
    assert out.stop["reason"] == "crashed" and out.cluster.events == []
    assert out.stage(0, "network")["stalls"] == 5


def test_state_keys_after_a_stall(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    cluster = Sim(cfg, {("network", 0): [STALL]}, durations={("network", 0): 30})
    seen = []

    def tick(_):
        if not seen and ("fail", "network", 0) in cluster.events:
            seen.append(dict(state_of(cfg)["shard_states"]["0"]["stages"]["network"]))
    go(cfg, cluster, tmp_path, on_tick=tick)
    st = seen[0]
    assert {"status", "attempts", "stalls", "owner_pid", "started_at", "heartbeat", "finished_at", "error"} <= set(st)
    assert st["stalls"] == 1 and isinstance(st["stalls"], int) and st["attempts"] == 0
    assert st["status"] == "running" and st["owner_pid"] is not None


def test_a_run_without_stalls_writes_no_stall_counters(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    out = go(cfg, Sim(cfg), tmp_path)
    assert out.result["complete"]
    assert all("stalls" not in out.stage(i, n) for i in range(2) for n in coordinator.STAGES)


def test_state_written_by_an_older_version_has_no_stalls_key(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    entry = seed_stage(cfg, 0, status="pending", attempts=1)
    assert "stalls" not in entry["stages"]["network"]
    out = go(cfg, Sim(cfg, {("network", 0): [STALL, 0]}), tmp_path)
    assert out.result["complete"] and out.stage(0, "network")["stalls"] == 1


def test_a_text_stall_value_in_the_state_file_reads_as_none(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    seed_stage(cfg, 0, status="pending", stalls="3")
    out = go(cfg, Sim(cfg, {("network", 0): [STALL, 0]}), tmp_path)
    assert out.result["complete"] and out.stage(0, "network")["stalls"] == 1
    assert not (campaign.campaign_dir(cfg) / "campaign.lock").exists()


def test_a_text_stall_value_is_harmless_while_nothing_stalls(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    seed_stage(cfg, 0, status="pending", stalls="3")
    out = go(cfg, Sim(cfg, {("network", 0): [1, 0]}), tmp_path)
    assert out.result["complete"] and out.stage(0, "network")["stalls"] == "3"


def test_a_text_stall_value_of_a_failed_stage_is_reset_by_retry_failed(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    seed_stage(cfg, 0, status="failed", attempts=3, stalls="x", error="e", stop_reason="crashed")
    out = go(cfg, Sim(cfg, {("network", 0): [STALL, 0]}), tmp_path, retry_failed=True)
    assert out.stage(0, "network")["stalls"] == 1


def test_a_null_stall_value_reads_as_none(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    seed_stage(cfg, 0, status="pending", stalls=None)
    out = go(cfg, Sim(cfg, {("network", 0): [STALL, 0]}), tmp_path)
    assert out.result["complete"] and out.stage(0, "network")["stalls"] == 1


@pytest.mark.parametrize("value", [10 ** 12, coordinator.MAX_STALLS, coordinator.MAX_STALLS + 1, 2 ** 70])
def test_a_stall_value_at_or_over_the_limit_counts_every_failure(tmp_path, value):
    cfg = make_cfg(tmp_path, shards=2)
    seed_stage(cfg, 0, status="pending", stalls=value)
    out = go(cfg, Sim(cfg, {("network", 0): STALL}), tmp_path)
    assert out.stop["reason"] == "crashed" and out.starts("network", 0) == coordinator.MAX_ATTEMPTS
    assert out.stage(0, "network")["stalls"] == value


@pytest.mark.parametrize("value", [-1, -3, -10])
def test_a_negative_stall_value_reads_as_none(tmp_path, value):
    cfg = make_cfg(tmp_path, shards=2)
    seed_stage(cfg, 0, status="pending", stalls=value)
    out = go(cfg, Sim(cfg, {("network", 0): STALL}), tmp_path)
    assert out.starts("network", 0) == coordinator.MAX_STALLS + coordinator.MAX_ATTEMPTS
    assert out.stage(0, "network")["stalls"] == coordinator.MAX_STALLS


@pytest.mark.parametrize("value", [True, False, 2.5, "2"])
def test_a_boolean_fractional_or_text_stall_value_reads_as_none(tmp_path, value):
    cfg = make_cfg(tmp_path, shards=2)
    seed_stage(cfg, 0, status="pending", stalls=value)
    out = go(cfg, Sim(cfg, {("network", 0): [STALL, 0]}), tmp_path)
    assert out.result["complete"] and out.stage(0, "network")["stalls"] == 1


def test_a_stage_that_stalls_then_fails_is_skipped_with_skip_failed(tmp_path):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, {("network", 1): STALL}), tmp_path, skip_failed=True)
    assert out.stop["reason"] == "crashed" and out.stop["stage"] == "network" and out.stop["shard"] == 1
    assert out.starts("network", 1) == coordinator.MAX_STALLS + coordinator.MAX_ATTEMPTS and out.result["shards_complete"] == 2
    assert "network: crashed; skipped, the other shards go on" in out.text


# ------------------------------------------------------------------ skip failed: one failure

def test_a_network_failure_is_skipped_and_the_other_shards_finish(tmp_path):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, crash_all(("network", 1))), tmp_path, skip_failed=True)
    r = out.result
    assert not r["complete"] and r["shards_complete"] == 2
    assert out.stop["reason"] == "crashed" and out.stop["stage"] == "network" and out.stop["shard"] == 1
    assert "network of shard 1" in out.stop["detail"] and "1 stage(s) failed and were skipped" in out.stop["detail"]
    assert [out.entry(i)["status"] for i in (0, 2)] == ["complete", "complete"]
    assert out.entry(1)["status"] == "zmap_done"
    assert out.stage(1, "network")["status"] == "failed" and out.stage(1, "network")["attempts"] == 3
    assert out.stage(1, "favicon")["status"] == "pending" and out.starts("favicon", 1) == 0
    assert out.starts("network", 1) == 3


def test_skip_log_lines(tmp_path):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, crash_all(("network", 1))), tmp_path, skip_failed=True)
    assert "[coordinator] shard 2/3 network: crashed; skipped, the other shards go on" in out.logs
    assert not any("nothing further starts" in l for l in out.logs)
    assert any("network failed after 3 attempts" in l for l in out.logs)


@pytest.mark.parametrize("name", ["zmap", "network", "favicon"])
@pytest.mark.parametrize("shard", [0, 1, 2])
def test_any_failing_stage_of_any_shard_is_skipped(tmp_path, name, shard):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, crash_all((name, shard))), tmp_path, skip_failed=True)
    assert out.stop["reason"] == "crashed" and out.stop["shard"] == shard and out.stop["stage"] == name
    assert out.result["shards_complete"] == 2 and not out.result["complete"]
    for i in range(3):
        if i != shard:
            assert out.entry(i)["status"] == "complete"
    later = coordinator.STAGES[coordinator.STAGES.index(name) + 1:]
    assert all(out.starts(n, shard) == 0 for n in later)
    assert out.stage(shard, name)["status"] == "failed"
    assert sorted(set(out.started("zmap"))) == [0, 1, 2]
    assert out.starts("zmap", shard) == (3 if name == "zmap" else 1)


def test_a_zmap_failure_does_not_stop_later_sweeps(tmp_path):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, crash_all(("zmap", 0))), tmp_path, skip_failed=True)
    assert out.started("zmap") == [0, 0, 0, 1, 2]
    assert out.starts("network", 0) == 0 and out.result["shards_complete"] == 2


def test_two_failures_are_both_listed(tmp_path):
    cfg = make_cfg(tmp_path, shards=4)
    out = go(cfg, Sim(cfg, {("network", 1): 1, ("favicon", 3): 1}), tmp_path, skip_failed=True)
    assert out.stop["reason"] == "crashed"
    detail = out.stop["detail"]
    assert "2 stage(s) failed" in detail and "network of shard 1" in detail and "favicon of shard 3" in detail
    assert out.result["shards_complete"] == 2


def test_two_failures_in_the_same_shard(tmp_path):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, {("network", 1): 1, ("zmap", 2): 1}), tmp_path, skip_failed=True)
    assert "2 stage(s) failed" in out.stop["detail"]
    assert out.result["shards_complete"] == 1 and out.entry(0)["status"] == "complete"


def test_every_shard_failing(tmp_path):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, crash_all(*[("network", i) for i in range(3)])), tmp_path, skip_failed=True)
    assert out.result["shards_complete"] == 0 and not out.result["complete"]
    assert out.stop["reason"] == "crashed" and "3 stage(s) failed" in out.stop["detail"]
    assert out.started("zmap") == [0, 1, 2] and out.cluster.events.count(("fail", "network", 0)) == 3


def test_every_zmap_failing_ends_after_all_attempts(tmp_path):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, crash_all(*[("zmap", i) for i in range(3)])), tmp_path, skip_failed=True)
    assert out.started("zmap").count(0) == 3 and len(out.started("zmap")) == 9
    assert out.starts("network", 0) == 0 and "3 stage(s) failed" in out.stop["detail"]


def test_a_single_shard_campaign_with_a_failure(tmp_path):
    cfg = make_cfg(tmp_path, shards=1)
    out = go(cfg, Sim(cfg, crash_all(("network", 0))), tmp_path, skip_failed=True)
    assert out.stop["reason"] == "crashed" and out.result["shards_complete"] == 0
    assert out.starts("network", 0) == 3


def test_a_single_shard_campaign_that_succeeds_reports_no_failure(tmp_path):
    cfg = make_cfg(tmp_path, shards=1)
    out = go(cfg, Sim(cfg), tmp_path, skip_failed=True)
    assert out.result["complete"] and out.stop is None


def test_the_campaign_waits_for_slow_stages_of_other_shards(tmp_path):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, crash_all(("network", 0)), durations={("network", 2): 80}), tmp_path, skip_failed=True)
    assert ("done", "favicon", 2) in out.cluster.events and out.ticks >= 80
    assert out.entry(2)["status"] == "complete"


@pytest.mark.parametrize("fails_on", [1, 2])
def test_a_failure_is_skipped_only_after_the_last_attempt(tmp_path, fails_on):
    cfg = make_cfg(tmp_path)
    script = {("network", 1): [1] * fails_on + [0]}
    out = go(cfg, Sim(cfg, script), tmp_path, skip_failed=True)
    assert out.result["complete"] and out.stop is None
    assert "skipped" not in out.text


def test_shards_are_started_in_index_order_around_a_failure(tmp_path):
    cfg = make_cfg(tmp_path, shards=5)
    out = go(cfg, Sim(cfg, crash_all(("network", 2))), tmp_path, skip_failed=True, network_workers=1, favicon_workers=1)
    assert out.started("zmap") == [0, 1, 2, 3, 4]
    first_network = [s for i, s in enumerate(out.started("network")) if s not in out.started("network")[:i]]
    assert first_network == [0, 1, 2, 3, 4]
    first_favicon = [s for i, s in enumerate(out.started("favicon")) if s not in out.started("favicon")[:i]]
    assert first_favicon == [0, 1, 3, 4]


# ------------------------------------------------------------------ skip failed: other stop reasons

def test_a_refusal_still_halts_with_skip_failed(tmp_path):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, {("zmap", 0): coordinator.EXIT_REFUSED}), tmp_path, skip_failed=True)
    assert out.stop["reason"] == "preflight_failed" and out.starts("zmap", 0) == 1
    assert out.starts("zmap", 1) == 0
    assert "nothing further starts" in out.text and "skipped" not in out.text


def test_zero_responsive_still_halts_with_skip_failed(tmp_path):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, zero_responsive=[0]), tmp_path, skip_failed=True)
    assert out.stop["reason"] == "zero_responsive" and out.stop["shard"] == 0
    assert out.stage(0, "network")["stop_reason"] == "zero_responsive"
    assert "skipped" not in out.text


def test_a_refusal_after_a_skipped_failure_wins(tmp_path):
    cfg = make_cfg(tmp_path, shards=4)
    script = {("network", 0): 1, ("network", 3): coordinator.EXIT_REFUSED}
    out = go(cfg, Sim(cfg, script), tmp_path, skip_failed=True)
    assert out.stop["reason"] == "preflight_failed" and out.stop["shard"] == 3


def test_a_skipped_failure_then_a_kill_switch_reports_the_kill_switch(tmp_path):
    cfg = make_cfg(tmp_path)
    cluster = Sim(cfg, crash_all(("network", 0)), durations={("zmap", 2): 50})
    switch = Path(cfg.kill_switch_file)
    switch.parent.mkdir(parents=True, exist_ok=True)
    logs_ref = []

    def tick(_):
        if cluster.events.count(("fail", "network", 0)) == 3 and not logs_ref:
            logs_ref.append(1)
            switch.write_text("stop")
    out = go(cfg, cluster, tmp_path, skip_failed=True, on_tick=tick)
    assert out.stop["reason"] == "kill_switch"
    assert out.stage(0, "network")["status"] == "failed"


def test_drain_still_ends_the_campaign_between_shards(tmp_path):
    cfg = make_cfg(tmp_path)
    cluster = Sim(cfg, crash_all(("network", 0)))
    drain = campaign.campaign_dir(cfg) / "DRAIN"

    def tick(_):
        if ("start", "zmap", 0) in cluster.events:
            drain.parent.mkdir(parents=True, exist_ok=True)
            drain.touch()
    out = go(cfg, cluster, tmp_path, skip_failed=True, on_tick=tick)
    assert out.stop["reason"] == "drain"
    assert out.starts("zmap", 1) == 0
    assert cli.CAMPAIGN_EXIT["drain"] == 0


def test_low_disk_still_ends_the_campaign(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    cluster = Sim(cfg, crash_all(("network", 0)))
    monkeypatch.setattr(campaign, "disk_shortfall", lambda c, s: "3.0 GB free" if ("done", "zmap", 0) in cluster.events else None)
    out = go(cfg, cluster, tmp_path, skip_failed=True)
    assert out.stop["reason"] == "disk" and "3.0 GB" in out.stop["detail"]
    assert out.starts("zmap", 1) == 0


def test_egress_change_still_stops_the_campaign(tmp_path):
    cfg = make_cfg(tmp_path)
    cluster = Sim(cfg, crash_all(("network", 0)))
    out = go(cfg, cluster, tmp_path, skip_failed=True,
             egress=lambda c: OTHER_EGRESS if ("done", "zmap", 1) in cluster.events else c.vantage.public_egress_ip)
    assert out.stop["reason"] == "egress_changed"
    assert out.starts("zmap", 2) == 0


def test_unknown_egress_still_stops_the_campaign(tmp_path):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg), tmp_path, skip_failed=True, egress=lambda c: None)
    assert out.stop["reason"] == "egress_unknown" and out.cluster.events == []


def test_a_lock_held_by_another_sweep_keeps_the_campaign_waiting(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    cluster = Sim(cfg, crash_all(("network", 0)))
    real = coordinator._try_zmap_lock
    calls = []

    def lock(path):
        calls.append(1)
        if ("done", "zmap", 0) in cluster.events and len(calls) < 60:
            return False
        return real(path)
    monkeypatch.setattr(coordinator, "_try_zmap_lock", lock)
    out = go(cfg, cluster, tmp_path, skip_failed=True)
    assert out.stop["reason"] == "crashed" and out.result["shards_complete"] == 2
    assert len(calls) >= 60 and out.started("zmap") == [0, 1, 2]


def test_a_lock_that_is_never_released_does_not_end_the_campaign(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    cluster = Sim(cfg, crash_all(("network", 0)))
    real = coordinator._try_zmap_lock
    monkeypatch.setattr(coordinator, "_try_zmap_lock", lambda p: False if ("done", "zmap", 0) in cluster.events else real(p))
    with pytest.raises(Runaway):
        go(cfg, cluster, tmp_path, skip_failed=True, max_ticks=300)
    assert ("start", "zmap", 1) not in cluster.events


# ------------------------------------------------------------------ skip failed: sweeps lost

class ForgetfulFor(SweepCluster):
    def __init__(self, cfg, forget):
        super().__init__(cfg)
        self.forget = set(forget)

    def outcome(self, proc):
        if proc.stage == "zmap" and proc.shard in self.forget:
            self.swept.append((proc.shard, []))
            return Cluster.outcome(self, proc)
        return super().outcome(proc)


@pytest.mark.parametrize("cap", [1, 2, 3])
def test_endless_lost_sweeps_are_skipped(tmp_path, cap):
    cfg = make_cfg(tmp_path, shards=2)
    seed_state(cfg, {0: _zmap_done_entry(cfg, 0)})
    cluster = ForgetfulFor(cfg, [0])
    out = go(cfg, cluster, tmp_path, skip_failed=True, max_attempts=cap)
    assert out.stop["reason"] == "crashed" and out.stop["stage"] == "zmap" and out.stop["shard"] == 0
    assert "zmap of shard 0" in out.stop["detail"]
    assert len([s for s in cluster.swept if s[0] == 0]) == cap
    assert out.entry(1)["status"] == "complete" and out.result["shards_complete"] == 1
    assert out.stage(0, "zmap")["status"] == "failed"


def test_endless_lost_sweeps_halt_without_skip_failed(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    seed_state(cfg, {0: _zmap_done_entry(cfg, 0)})
    out = go(cfg, ForgetfulFor(cfg, [0]), tmp_path)
    assert out.stop["reason"] == "crashed" and "nothing further starts" in out.text


# ------------------------------------------------------------------ skip failed: state at start

def failed_entry(cfg, shard=0, name="network", reason="crashed"):
    fields = {"status": "failed", "attempts": 3, "error": "exited with code 1", "stop_reason": reason}
    return seed_stage(cfg, shard, network_done=(name == "favicon"), zmap_done=(name != "zmap"), **fields)


def test_a_failed_stage_in_the_state_file_is_skipped(tmp_path):
    cfg = make_cfg(tmp_path)
    failed_entry(cfg)
    out = go(cfg, Sim(cfg), tmp_path, skip_failed=True)
    assert out.stop["reason"] == "crashed" and out.stop["shard"] == 0 and out.stop["stage"] == "network"
    assert "network of shard 0" in out.stop["detail"]
    assert out.starts("network", 0) == 0 and out.result["shards_complete"] == 2
    assert "failed earlier (exited with code 1); skipped, the other shards go on" in out.text
    assert "not trying again" not in out.text


def test_a_failed_stage_in_the_state_file_halts_without_skip_failed(tmp_path):
    cfg = make_cfg(tmp_path)
    failed_entry(cfg)
    out = go(cfg, Sim(cfg), tmp_path)
    assert out.stop["reason"] == "crashed" and out.cluster.events == []
    assert "--retry-failed" in out.stop["detail"] and "not trying again without --retry-failed" in out.text


def test_retry_failed_wins_over_skip_failed_at_start(tmp_path):
    cfg = make_cfg(tmp_path)
    failed_entry(cfg)
    out = go(cfg, Sim(cfg), tmp_path, skip_failed=True, retry_failed=True)
    assert out.result["complete"] and out.stop is None
    assert out.starts("network", 0) == 1 and "skipped" not in out.text


def test_a_retried_stage_that_fails_again_is_skipped_with_both_flags(tmp_path):
    cfg = make_cfg(tmp_path)
    failed_entry(cfg)
    out = go(cfg, Sim(cfg, crash_all(("network", 0))), tmp_path, skip_failed=True, retry_failed=True)
    assert out.starts("network", 0) == 3 and out.stop["reason"] == "crashed"
    assert out.result["shards_complete"] == 2


@pytest.mark.parametrize("name", ["zmap", "network", "favicon"])
def test_a_failed_stage_of_every_kind_in_the_state_file_is_skipped(tmp_path, name):
    cfg = make_cfg(tmp_path)
    failed_entry(cfg, 1, name)
    out = go(cfg, Sim(cfg), tmp_path, skip_failed=True)
    assert out.stop["reason"] == "crashed" and out.stop["stage"] == name and out.stop["shard"] == 1
    assert out.starts(name, 1) == 0 and out.result["shards_complete"] == 2


@pytest.mark.parametrize("reason", ["crashed", None])
def test_a_crashed_stage_in_the_state_file_is_skipped(tmp_path, reason):
    cfg = make_cfg(tmp_path)
    failed_entry(cfg, 0, "network", reason)
    out = go(cfg, Sim(cfg), tmp_path, skip_failed=True)
    assert out.stop["reason"] == "crashed" and out.result["shards_complete"] == 2


@pytest.mark.parametrize("reason", ["preflight_failed", "zero_responsive"])
def test_a_refused_or_empty_stage_in_the_state_file_still_stops_the_campaign(tmp_path, reason):
    cfg = make_cfg(tmp_path)
    failed_entry(cfg, 0, "network", reason)
    out = go(cfg, Sim(cfg), tmp_path, skip_failed=True)
    assert out.stop["reason"] == reason


@pytest.mark.parametrize("reason,expected", [("preflight_failed", "preflight_failed"), ("zero_responsive", "zero_responsive"), (None, "crashed")])
def test_the_recorded_stop_reason_is_kept_without_skip_failed(tmp_path, reason, expected):
    cfg = make_cfg(tmp_path)
    failed_entry(cfg, 0, "network", reason)
    assert go(cfg, Sim(cfg), tmp_path).stop["reason"] == expected


def test_failed_stages_in_the_state_file_of_two_shards_are_both_listed(tmp_path):
    cfg = make_cfg(tmp_path, shards=4)
    failed_entry(cfg, 0, "network")
    failed_entry(cfg, 2, "favicon")
    out = go(cfg, Sim(cfg), tmp_path, skip_failed=True)
    assert "2 stage(s) failed" in out.stop["detail"]
    assert "network of shard 0" in out.stop["detail"] and "favicon of shard 2" in out.stop["detail"]
    assert out.result["shards_complete"] == 2


def test_everything_failed_in_the_state_file_ends_at_once(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    for i in range(2):
        failed_entry(cfg, i)
    out = go(cfg, Sim(cfg), tmp_path, skip_failed=True, max_ticks=5)
    assert out.stop["reason"] == "crashed" and out.cluster.events == [] and out.ticks <= 1


def test_a_failure_outside_the_shard_span_is_not_reported(tmp_path):
    cfg = make_cfg(tmp_path, shards=4)
    failed_entry(cfg, 0)
    out = go(cfg, Sim(cfg), tmp_path, skip_failed=True, shards_from=1, shards_to=4)
    assert out.result["complete"] and out.stop is None
    assert out.result["shard_range"] == [1, 4]


def test_a_failure_inside_a_shard_span_is_skipped(tmp_path):
    cfg = make_cfg(tmp_path, shards=4)
    out = go(cfg, Sim(cfg, crash_all(("network", 2))), tmp_path, skip_failed=True, shards_from=1, shards_to=4)
    assert out.stop["shard"] == 2 and out.result["shards_complete"] == 2
    assert out.started("zmap") == [1, 2, 3]


def test_a_span_of_one_shard(tmp_path):
    cfg = make_cfg(tmp_path, shards=4)
    out = go(cfg, Sim(cfg, crash_all(("favicon", 2))), tmp_path, skip_failed=True, shards_from=2, shards_to=3)
    assert out.stop["reason"] == "crashed" and out.started("zmap") == [2]


# ------------------------------------------------------------------ skip failed: resume with --retry-failed

def test_retry_failed_completes_the_shards_a_skipping_run_left_behind(tmp_path):
    cfg = make_cfg(tmp_path)
    first = go(cfg, Sim(cfg, crash_all(("network", 1))), tmp_path, skip_failed=True)
    assert first.stop["reason"] == "crashed"
    second = go(cfg, Sim(cfg), tmp_path, skip_failed=True, retry_failed=True)
    assert second.result["complete"] and second.stop is None
    assert second.started("zmap") == [] and second.started("network") == [1] and second.started("favicon") == [1]
    assert second.stage(1, "network")["attempts"] == 0


def test_a_second_skipping_run_without_retry_starts_nothing(tmp_path):
    cfg = make_cfg(tmp_path)
    go(cfg, Sim(cfg, crash_all(("network", 1))), tmp_path, skip_failed=True)
    again = go(cfg, Sim(cfg), tmp_path, skip_failed=True)
    assert again.cluster.events == [] and again.stop["reason"] == "crashed"
    assert again.result["shards_complete"] == 2


def test_a_plain_run_after_a_skipping_run_halts_until_retry_failed(tmp_path):
    cfg = make_cfg(tmp_path)
    go(cfg, Sim(cfg, crash_all(("favicon", 0))), tmp_path, skip_failed=True)
    plain = go(cfg, Sim(cfg), tmp_path)
    assert plain.stop["reason"] == "crashed" and plain.cluster.events == []
    fixed = go(cfg, Sim(cfg), tmp_path, retry_failed=True)
    assert fixed.result["complete"] and fixed.started("favicon") == [0]


def test_retry_after_a_skipped_zmap_failure_sweeps_and_finishes_the_shard(tmp_path):
    cfg = make_cfg(tmp_path)
    go(cfg, Sim(cfg, crash_all(("zmap", 1))), tmp_path, skip_failed=True)
    second = go(cfg, Sim(cfg), tmp_path, skip_failed=True, retry_failed=True)
    assert second.result["complete"]
    assert second.started("zmap") == [1] and second.started("network") == [1]


def test_two_skipped_shards_are_both_retried(tmp_path):
    cfg = make_cfg(tmp_path, shards=4)
    go(cfg, Sim(cfg, {("network", 1): 1, ("favicon", 2): 1}), tmp_path, skip_failed=True)
    second = go(cfg, Sim(cfg), tmp_path, skip_failed=True, retry_failed=True)
    assert second.result["complete"]
    assert second.started("network") == [1] and sorted(second.started("favicon")) == [1, 2]


# ------------------------------------------------------------------ worker limits and the unchanged old behaviour

@pytest.mark.parametrize("nw,fw", [(1, 1), (2, 1), (1, 3), (3, 2), (3, 3)])
def test_worker_limits_hold_around_a_skipped_failure(tmp_path, nw, fw):
    cfg = make_cfg(tmp_path, shards=4)
    durations = {("network", i): 12 for i in range(4)} | {("favicon", i): 9 for i in range(4)}
    cluster = Sim(cfg, crash_all(("network", 2)), durations=durations)
    out = go(cfg, cluster, tmp_path, skip_failed=True, network_workers=nw, favicon_workers=fw)
    assert out.stop["reason"] == "crashed" and out.result["shards_complete"] == 3
    assert cluster.peaks["network"] <= nw and cluster.peaks["favicon"] <= fw and cluster.peaks["zmap"] == 1
    assert out.ticks < 2000


def _scrub(text, root):
    return re.sub(r"campaign-[0-9a-f]+", "campaign-X", text.replace(str(root), "ROOT").replace(str(root).replace("\\", "\\\\"), "ROOT"))


def _normalised(out, root):
    keep = ("status", "attempts", "owner_pid", "error", "stop_reason")
    stages = {i: {n: {k: s.get(k) for k in keep} for n, s in out.entry(i)["stages"].items()} for i in range(out.cfg.shards)}
    result = {k: v for k, v in out.result.items() if k != "finished_at"}
    return {"logs": [_scrub(l, root) for l in out.logs], "events": out.cluster.events, "stages": stages,
            "result": json.loads(_scrub(json.dumps(result), root))}


@pytest.mark.parametrize("shards", [2, 4])
def test_an_all_success_run_is_identical_with_and_without_the_flag(tmp_path, shards):
    runs = []
    for flag in (False, True):
        root = tmp_path / ("on" if flag else "off")
        root.mkdir()
        cfg = make_cfg(root, shards=shards)
        runs.append(_normalised(go(cfg, Sim(cfg), root, skip_failed=flag), root))
    assert runs[0] == runs[1]
    assert runs[0]["result"]["complete"]


def test_a_run_with_only_stalls_is_identical_with_and_without_the_flag(tmp_path):
    runs = []
    for flag in (False, True):
        root = tmp_path / ("on" if flag else "off")
        root.mkdir()
        cfg = make_cfg(root)
        runs.append(_normalised(go(cfg, Sim(cfg, {("network", 1): [STALL] * 3, ("zmap", 2): [STALL]}), root, skip_failed=flag), root))
    assert runs[0] == runs[1]


def test_without_the_flag_a_failure_halts_and_running_stages_finish(tmp_path):
    cfg = make_cfg(tmp_path)
    cluster = Sim(cfg, {("network", 0): 1}, durations={("network", 0): 6, ("network", 1): 40})
    out = go(cfg, cluster, tmp_path)
    assert out.stop["reason"] == "crashed" and out.stop["shard"] == 0 and out.stop["stage"] == "network"
    assert "stage(s) failed" not in out.stop["detail"]
    marker = next(i for i, l in enumerate(out.logs) if "nothing further starts, running stages finish" in l)
    assert not any(" started " in l for l in out.logs[marker:])
    assert ("done", "network", 1) in cluster.events
    assert out.starts("favicon", 1) == 0 and out.entry(1)["status"] in ("network_done", "zmap_done")
    assert "skipped" not in out.text


# ------------------------------------------------------------------ termination

SCENARIOS = {
    "crash-network": {("network", 1): 1},
    "crash-zmap": {("zmap", 0): 1},
    "crash-favicon": {("favicon", 2): 1},
    "stall-forever": {("network", 0): STALL},
    "all-crash": {("zmap", 0): 1, ("network", 1): 1, ("favicon", 2): 1},
    "stall-and-crash": {("zmap", 1): STALL, ("network", 2): 1},
    "recycle-then-crash": {("network", 0): [coordinator.EXIT_RECYCLE, 1, 1, 1]},
    "refusal": {("network", 1): coordinator.EXIT_REFUSED},
    "signals": {("network", 0): -9, ("network", 1): -15},
}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
@pytest.mark.parametrize("skip", [False, True])
def test_every_scenario_terminates(tmp_path, name, skip):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, SCENARIOS[name]), tmp_path, skip_failed=skip, max_ticks=400)
    assert out.ticks < 400
    assert out.result["stopped"] is not None or out.result["complete"]
    assert not any(p.rc is None for p in out.cluster.procs)


def test_no_state_is_left_running_after_a_skipping_campaign(tmp_path):
    cfg = make_cfg(tmp_path)
    out = go(cfg, Sim(cfg, {("network", 1): 1, ("favicon", 0): STALL}), tmp_path, skip_failed=True)
    for i in range(3):
        assert all(s["status"] != "running" and s["owner_pid"] is None for s in out.entry(i)["stages"].values())
    assert not (campaign.campaign_dir(cfg) / "campaign.lock").exists()


# ------------------------------------------------------------------ command line

def _cli_args(tmp_path, *extra, shards=3):
    path = _cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": shards})
    cfg = load_config(path)
    token = pipeline.confirm_token(cfg, pipeline.build_policy(cfg)[1])
    return ["campaign", "--config", str(path), "--confirm", token, "--skip-pilot-check", *extra], cfg, path


def _capture(monkeypatch, result=None):
    seen = {}

    def fake(cfg, **kw):
        seen.update(kw)
        return result or {"complete": True, "stopped": None, "shards_complete": 3}
    monkeypatch.setattr(coordinator, "run_decoupled", fake)
    return seen


@pytest.mark.parametrize("flags,retry,skip", [
    ([], False, False),
    (["--skip-failed"], False, True),
    (["--retry-failed"], True, False),
    (["--skip-failed", "--retry-failed"], True, True),
    (["--retry-failed", "--skip-failed"], True, True),
])
def test_cli_passes_the_flags_on(tmp_path, monkeypatch, flags, retry, skip):
    argv, _, _ = _cli_args(tmp_path, "--decoupled", *flags)
    seen = _capture(monkeypatch)
    assert cli.main(argv) == 0
    assert seen["skip_failed"] is skip and seen["retry_failed"] is retry


def test_cli_skip_failed_works_with_the_other_decoupled_options(tmp_path, monkeypatch):
    argv, _, _ = _cli_args(tmp_path, "--decoupled", "--skip-failed", "--network-workers", "3", "--favicon-workers", "2",
                           "--shards-from", "1", "--shards-to", "3", "--allow-per-process-limits")
    seen = _capture(monkeypatch)
    assert cli.main(argv) == 0
    assert seen["skip_failed"] is True and seen["network_workers"] == 3 and seen["favicon_workers"] == 2
    assert seen["shards_from"] == 1 and seen["shards_to"] == 3


@pytest.mark.parametrize("stopped,code", [
    ({"reason": "crashed"}, 5), ({"reason": "preflight_failed"}, 2), ({"reason": "zero_responsive"}, 4),
    ({"reason": "disk", "detail": "x"}, 6), ({"reason": "drain"}, 0), ({"reason": "kill_switch"}, 5), ({"reason": "stalled"}, 5),
    ({"reason": "interrupt"}, 5), ({"reason": "egress_changed"}, 5), (None, 5),
])
def test_cli_exit_code_of_an_incomplete_campaign(tmp_path, monkeypatch, stopped, code):
    argv, _, _ = _cli_args(tmp_path, "--decoupled", "--skip-failed")
    _capture(monkeypatch, {"complete": False, "stopped": stopped, "shards_complete": 2})
    assert cli.main(argv) == code


def test_cli_end_to_end_a_skipped_failure_gives_exit_five_and_a_report(tmp_path, monkeypatch, capsys):
    argv, cfg, path = _cli_args(tmp_path, "--decoupled", "--skip-failed", "--allow-per-process-limits",
                                "--zmap-lock-file", str(tmp_path / "zmap.lock"))
    cluster = Sim(cfg, crash_all(("network", 1)))
    real = coordinator.run_decoupled
    monkeypatch.setattr(coordinator, "run_decoupled", lambda c, **kw: real(c, **kw, spawn=cluster.spawn, tick=0, sleep=lambda _: None,
                                                                           egress=lambda x: x.vantage.public_egress_ip, alive=lambda p: False,
                                                                           log=lambda *_: None))
    assert cli.main(argv) == 5
    report = json.loads(capsys.readouterr().out)
    assert report["stopped"]["reason"] == "crashed" and report["shards_complete"] == 2 and report["complete"] is False
    assert "network of shard 1" in report["stopped"]["detail"]
    assert cluster.events.count(("start", "network", 1)) == 3


def test_cli_end_to_end_without_the_flag_halts_with_the_same_exit_code(tmp_path, monkeypatch, capsys):
    argv, cfg, path = _cli_args(tmp_path, "--decoupled", "--allow-per-process-limits", "--zmap-lock-file", str(tmp_path / "zmap.lock"))
    cluster = Sim(cfg, crash_all(("network", 0)))
    real = coordinator.run_decoupled
    monkeypatch.setattr(coordinator, "run_decoupled", lambda c, **kw: real(c, **kw, spawn=cluster.spawn, tick=0, sleep=lambda _: None,
                                                                           egress=lambda x: x.vantage.public_egress_ip, alive=lambda p: False,
                                                                           log=lambda *_: None))
    assert cli.main(argv) == 5
    report = json.loads(capsys.readouterr().out)
    assert report["stopped"]["reason"] == "crashed" and "stage(s) failed" not in report["stopped"]["detail"]


def test_cli_end_to_end_a_complete_run_with_the_flag_exits_zero(tmp_path, monkeypatch, capsys):
    argv, cfg, path = _cli_args(tmp_path, "--decoupled", "--skip-failed", "--allow-per-process-limits", "--zmap-lock-file", str(tmp_path / "zmap.lock"))
    cluster = Sim(cfg)
    real = coordinator.run_decoupled
    monkeypatch.setattr(coordinator, "run_decoupled", lambda c, **kw: real(c, **kw, spawn=cluster.spawn, tick=0, sleep=lambda _: None,
                                                                           egress=lambda x: x.vantage.public_egress_ip, alive=lambda p: False,
                                                                           log=lambda *_: None))
    assert cli.main(argv) == 0
    assert json.loads(capsys.readouterr().out)["complete"] is True


def test_cli_help_lists_the_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--skip-failed" in out and "--retry-failed" in out


def test_cli_rejects_a_value_for_the_flag(tmp_path, capsys):
    argv, _, _ = _cli_args(tmp_path, "--decoupled", "--skip-failed=yes")
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2


def test_cli_skip_failed_without_decoupled_is_ignored_like_retry_failed(tmp_path, monkeypatch):
    calls = {}
    monkeypatch.setattr(coordinator, "run_decoupled", lambda *a, **k: pytest.fail("decoupled run started"))
    monkeypatch.setattr(campaign, "run_campaign", lambda cfg, **kw: calls.setdefault("kw", kw) and {"complete": True, "stopped": None})
    for flag in ("--retry-failed", "--skip-failed"):
        calls.clear()
        argv, _, _ = _cli_args(tmp_path, flag)
        assert cli.main(argv) == 0
        assert "skip_failed" not in calls["kw"] and "retry_failed" not in calls["kw"]


@pytest.mark.parametrize("extra", [["--pipeline", "2"], ["--stop-after-network"], ["--no-resume"]])
def test_cli_refuses_the_decoupled_combinations_also_with_skip_failed(tmp_path, capsys, extra):
    argv, _, _ = _cli_args(tmp_path, "--decoupled", "--skip-failed", *extra)
    assert cli.main(argv) == 2
    assert "--decoupled does not combine" in capsys.readouterr().err


def test_cli_skip_failed_without_decoupled_and_with_pipeline_is_not_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(campaign, "run_campaign", lambda cfg, **kw: {"complete": True, "stopped": None})
    argv, _, _ = _cli_args(tmp_path, "--skip-failed", "--pipeline", "2")
    assert cli.main(argv) == 0
