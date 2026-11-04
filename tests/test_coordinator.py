"""Decoupled campaigns: scheduling, retries, hard stops and resume, with fake stage workers instead of real processes."""
import json
import os
import signal
from pathlib import Path

import pytest

from scanner.internet import __main__ as cli
from scanner.internet import campaign, coordinator, pipeline
from scanner.internet.config import ConfigError, load_config
from tests.test_scale import _cfg

posix = pytest.mark.skipif(not coordinator.available(), reason="needs POSIX file locks")


def make_cfg(tmp_path, shards=3):
    return load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": shards}))


class FakeProc:
    def __init__(self, cluster, stage, shard, run_dir, pid):
        self.cluster, self.stage, self.shard, self.run_dir, self.pid = cluster, stage, shard, Path(run_dir), pid
        self.left = cluster.duration(stage, shard)
        self.rc = None
        self.signals = []

    def send_signal(self, sig):
        self.signals.append(sig)
        self.rc = -int(sig)

    def kill(self):
        self.rc = -9

    def wait(self):
        return self.rc

    def poll(self):
        self.cluster.polls += 1
        assert self.cluster.polls < 20000, "the coordinator does not terminate"
        if self.rc is not None:
            return self.rc
        self.left -= 1
        if self.left > 0:
            return None
        self.rc = self.cluster.outcome(self)
        return self.rc


class Cluster:
    """Stands in for the stage-worker processes: each lives for a number of polls, then writes what the real stage would."""

    def __init__(self, cfg, durations=None, fail=None):
        self.cfg, self.durations, self.fail = cfg, durations or {}, fail or {}
        self.procs, self.polls, self.next_pid = [], 0, 40000
        self.events = []

    def duration(self, stage, shard):
        return self.durations.get((stage, shard), {"zmap": 3, "network": 4, "favicon": 2}[stage])

    def spawn(self, cmd, pass_fds):
        assert "stage-worker" in cmd
        stage, shard, run_dir = cmd[cmd.index("--stage") + 1], int(cmd[cmd.index("--shard") + 1]), cmd[cmd.index("--run-dir") + 1]
        if stage == "zmap":
            assert not [p for p in self.procs if p.stage == "zmap" and p.rc is None], "two ZMap stages at once"
            if "--zmap-lock-fd" in cmd:
                assert pass_fds == (int(cmd[cmd.index("--zmap-lock-fd") + 1]),)
        self.next_pid += 1
        proc = FakeProc(self, stage, shard, run_dir, self.next_pid)
        self.procs.append(proc)
        self.events.append(("start", stage, shard))
        return proc

    def outcome(self, proc):
        queue = self.fail.get((proc.stage, proc.shard))
        if queue:
            rc = queue.pop(0) if isinstance(queue, list) else queue
            if rc != 0:
                self.events.append(("fail", proc.stage, proc.shard))
                return rc
        run_dir = proc.run_dir
        (run_dir / "report").mkdir(parents=True, exist_ok=True)
        manifest = {"config_checksum": self.cfg.checksum, "shard": {"index": proc.shard}, "zero_responsive": False, "elapsed_seconds": 1.0}
        old = json.loads((run_dir / "manifest.json").read_text()) if (run_dir / "manifest.json").exists() else {}
        manifest = {**old, **manifest}
        if proc.stage == "zmap":
            manifest.update(status="zmap_done", zmap_done=True)
        elif proc.stage == "network":
            manifest.update(status="network_done", network_done=True)
        else:
            manifest.update(complete=True, status="complete")
            (run_dir / "report" / "summary.json").write_text(json.dumps({"counts": {}}))
        (run_dir / "manifest.json").write_text(json.dumps(manifest))
        self.events.append(("done", proc.stage, proc.shard))
        return 0


def run(cfg, cluster, tmp_path, **kw):
    kw.setdefault("egress", lambda c: c.vantage.public_egress_ip)
    kw.setdefault("alive", lambda pid: False)
    return coordinator.run_decoupled(cfg, config_path=tmp_path / "scale.yaml", confirm="tok", log=lambda *_: None,
                                     spawn=cluster.spawn, tick=0, sleep=kw.pop("sleep", lambda _: None), **kw)


def state_of(cfg):
    return json.loads((campaign.campaign_dir(cfg) / "campaign.json").read_text())


def seed_state(cfg, entries):
    state = campaign.load_state(cfg)
    state["shard_states"].update({str(i): e for i, e in entries.items()})
    campaign._write_json(campaign.campaign_dir(cfg) / "campaign.json", state)


def test_one_sweep_at_a_time_and_later_shards_overtake(tmp_path):
    cfg = make_cfg(tmp_path)
    cluster = Cluster(cfg, durations={("network", 0): 30})
    result = run(cfg, cluster, tmp_path)
    assert result["complete"] and result["stopped"] is None and result["shards_complete"] == 3
    ev = cluster.events
    assert [e[2] for e in ev if e[:2] == ("start", "zmap")] == [0, 1, 2]
    assert ev.index(("done", "network", 1)) < ev.index(("done", "network", 0))          # shard 1 overtook shard 0
    assert ev.index(("start", "zmap", 1)) < ev.index(("done", "network", 0))             # ZMap never waited for downstream
    st = state_of(cfg)
    for i in range(3):
        e = st["shard_states"][str(i)]
        assert e["status"] == "complete" and e["run_id"].endswith(f"s{i:03d}of003")
        assert all(s["status"] == "done" and s["owner_pid"] is None for s in e["stages"].values())
    assert st["decoupled"]["network_workers"] == 2


def test_worker_limits_hold(tmp_path):
    cfg = make_cfg(tmp_path, shards=5)
    cluster = Cluster(cfg, durations={("network", i): 40 for i in range(5)})
    peaks = {"network": 0, "favicon": 0}
    real = cluster.spawn

    def spawn(cmd, fds):
        proc = real(cmd, fds)
        for name in peaks:
            peaks[name] = max(peaks[name], len([p for p in cluster.procs if p.stage == name and p.rc is None]))
        return proc
    result = coordinator.run_decoupled(cfg, config_path=tmp_path / "scale.yaml", confirm="tok", log=lambda *_: None, spawn=spawn, tick=0,
                                       sleep=lambda _: None, egress=lambda c: c.vantage.public_egress_ip, alive=lambda p: False,
                                       network_workers=2, favicon_workers=1)
    assert result["complete"]
    assert peaks["network"] == 2 and peaks["favicon"] == 1


def test_failed_attempt_is_retried_and_a_killed_child_returns_to_pending(tmp_path):
    cfg = make_cfg(tmp_path)
    cluster = Cluster(cfg, fail={("network", 1): [-9, 1, 0]})
    result = run(cfg, cluster, tmp_path)
    assert result["complete"]
    assert cluster.events.count(("start", "network", 1)) == 3
    st = state_of(cfg)["shard_states"]["1"]["stages"]["network"]
    assert st["status"] == "done" and st["attempts"] == 2


def test_retries_are_capped_and_the_campaign_stops(tmp_path):
    cfg = make_cfg(tmp_path)
    cluster = Cluster(cfg, fail={("network", 0): 1})
    result = run(cfg, cluster, tmp_path)
    assert not result["complete"] and result["stopped"]["reason"] == "crashed"
    assert cluster.events.count(("start", "network", 0)) == coordinator.MAX_ATTEMPTS
    st = state_of(cfg)["shard_states"]["0"]
    assert st["stages"]["network"]["status"] == "failed" and st["stages"]["network"]["attempts"] == 3
    assert "exited with code 1" in st["stages"]["network"]["error"] and st["status"] == "zmap_done"


def test_recycle_exit_restarts_without_counting_an_attempt(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    cluster = Cluster(cfg, fail={("favicon", 0): [coordinator.EXIT_RECYCLE, coordinator.EXIT_RECYCLE, 0]})
    result = run(cfg, cluster, tmp_path)
    assert result["complete"]
    assert cluster.events.count(("start", "favicon", 0)) == 3
    assert state_of(cfg)["shard_states"]["0"]["stages"]["favicon"]["attempts"] == 0


def test_refusal_is_not_retried(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    cluster = Cluster(cfg, fail={("zmap", 0): coordinator.EXIT_REFUSED})
    result = run(cfg, cluster, tmp_path)
    assert result["stopped"]["reason"] == "preflight_failed"
    assert cluster.events.count(("start", "zmap", 0)) == 1


def test_kill_switch_stops_every_child_and_a_restart_resumes(tmp_path):
    cfg = make_cfg(tmp_path)
    cluster = Cluster(cfg, durations={("network", 0): 50, ("network", 1): 50, ("zmap", 1): 50})
    switch = Path(cfg.kill_switch_file)
    switch.parent.mkdir(parents=True, exist_ok=True)

    def sleep(_):
        if ("start", "zmap", 1) in cluster.events and ("start", "network", 0) in cluster.events:
            switch.write_text("stop")
    result = run(cfg, cluster, tmp_path, sleep=sleep)
    assert result["stopped"]["reason"] == "kill_switch" and not result["complete"]
    live = [p for p in cluster.procs if p.signals]
    assert {p.stage for p in live} >= {"zmap", "network"} and all(p.signals == [signal.SIGTERM] for p in live)
    st = state_of(cfg)["shard_states"]
    assert st["0"]["stages"]["zmap"]["status"] == "done"
    assert st["0"]["stages"]["network"]["status"] == "pending" and st["1"]["stages"]["zmap"]["status"] == "pending"
    assert st["0"]["stages"]["network"]["attempts"] == 0 and st["0"]["stages"]["network"]["owner_pid"] is None
    switch.unlink()
    again = Cluster(cfg)
    result = run(cfg, again, tmp_path)
    assert result["complete"]
    assert ("start", "zmap", 0) not in again.events and ("start", "zmap", 1) in again.events


def test_signal_handler_stops_children(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    cluster = Cluster(cfg, durations={("zmap", 0): 50})
    polls = []

    def sleep(_):
        polls.append(1)
        if len(polls) == 3:
            signal.raise_signal(signal.SIGTERM)
    before = signal.getsignal(signal.SIGTERM)
    result = run(cfg, cluster, tmp_path, sleep=sleep)
    assert result["stopped"]["reason"] == "interrupt" and signal.getsignal(signal.SIGTERM) == before
    assert state_of(cfg)["shard_states"]["0"]["stages"]["zmap"]["status"] == "pending"


def test_low_disk_blocks_new_sweeps_only(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    cluster = Cluster(cfg)
    monkeypatch.setattr(campaign, "disk_shortfall", lambda c, s: "3.0 GB free" if ("done", "zmap", 0) in cluster.events else None)
    result = run(cfg, cluster, tmp_path)
    assert result["stopped"]["reason"] == "disk" and "3.0 GB" in result["stopped"]["detail"]
    st = state_of(cfg)["shard_states"]
    assert st["0"]["status"] == "complete"                       # downstream stages kept going
    assert st["1"]["stages"]["zmap"]["status"] == "pending"
    assert cluster.events.count(("start", "zmap", 1)) == 0


def test_egress_is_checked_before_each_sweep(tmp_path):
    cfg = make_cfg(tmp_path)
    cluster = Cluster(cfg)
    result = run(cfg, cluster, tmp_path, egress=lambda c: "203.0.113.9")
    assert result["stopped"]["reason"] == "egress_changed" and cluster.events == []
    cluster = Cluster(cfg)
    calls = []
    result = run(cfg, cluster, tmp_path, egress=lambda c: calls.append(1) or c.vantage.public_egress_ip)
    assert result["complete"] and len(calls) == 3


def test_unknown_egress_gives_up_after_three_lookups(tmp_path):
    cfg = make_cfg(tmp_path)
    cluster = Cluster(cfg)
    result = run(cfg, cluster, tmp_path, egress=lambda c: None)
    assert result["stopped"]["reason"] == "egress_unknown" and cluster.events == []


def test_dead_owner_stage_returns_to_pending_with_the_same_attempt(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    entry = coordinator._entry_for(cfg, 0, None)
    entry["stages"]["zmap"].update(status="running", attempts=1, owner_pid=777)
    entry["status"] = "running"
    seed_state(cfg, {0: entry})
    cluster = Cluster(cfg)
    result = run(cfg, cluster, tmp_path)
    assert result["complete"]
    assert state_of(cfg)["shard_states"]["0"]["stages"]["zmap"]["attempts"] == 1
    assert cluster.events[0] == ("start", "zmap", 0)


def test_dead_owner_whose_manifest_shows_the_stage_done_is_not_repeated(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    entry = coordinator._entry_for(cfg, 0, None)
    entry["stages"]["zmap"].update(status="running", owner_pid=777)
    run_dir = Path(entry["run_dir"])
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(json.dumps({"zmap_done": True, "status": "zmap_done"}))
    seed_state(cfg, {0: entry})
    cluster = Cluster(cfg)
    assert run(cfg, cluster, tmp_path)["complete"]
    assert ("start", "zmap", 0) not in cluster.events


def test_live_owner_from_an_earlier_coordinator_is_refused(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    entry = coordinator._entry_for(cfg, 0, None)
    entry["stages"]["network"].update(status="running", owner_pid=777)
    seed_state(cfg, {0: entry})
    with pytest.raises(campaign.CampaignLocked, match="777"):
        run(cfg, Cluster(cfg), tmp_path, alive=lambda pid: True)
    assert not (campaign.campaign_dir(cfg) / "campaign.lock").exists()


def test_entries_of_other_campaign_modes_are_carried_over(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    done_dir = Path(cfg.output_dir) / "old-a1"
    done_dir.mkdir(parents=True)
    entry = coordinator._entry_for(cfg, 0, {"status": "complete", "attempts": 1, "run_id": "old-a1", "run_dir": str(done_dir)})
    assert entry["run_dir"] == str(done_dir)
    assert all(s["status"] == "done" for s in entry["stages"].values())
    fresh = coordinator._entry_for(cfg, 1, {"status": "crashed", "attempts": 2, "run_id": "x-a2"})
    assert fresh["run_id"] == coordinator.run_id_for(cfg, 1) and fresh["status"] == "pending"
    assert coordinator.derive_status(fresh["stages"]) == "pending"


def test_derived_status_keeps_the_existing_values():
    s = {n: coordinator._fresh_stage() for n in coordinator.STAGES}
    assert coordinator.derive_status(s) == "pending"
    s["zmap"]["status"] = "running"
    assert coordinator.derive_status(s) == "running"
    s["zmap"]["status"] = "done"
    assert coordinator.derive_status(s) == "zmap_done"
    s["network"]["status"] = "done"
    assert coordinator.derive_status(s) == "network_done"
    s["favicon"]["status"] = "done"
    assert coordinator.derive_status(s) == "complete"


@posix
def test_zmap_start_waits_while_an_earlier_sweep_holds_the_lock(tmp_path):
    import fcntl
    cfg = make_cfg(tmp_path, shards=2)
    cdir = campaign.campaign_dir(cfg)
    cdir.mkdir(parents=True, exist_ok=True)
    held = os.open(cdir / coordinator.LOCK_NAME, os.O_CREAT | os.O_RDWR)
    fcntl.flock(held, fcntl.LOCK_EX)
    cluster = Cluster(cfg)
    ticks = []

    def sleep(_):
        ticks.append(1)
        if len(ticks) == 5:
            assert cluster.events == []                          # nothing was started while the lock was held
            os.close(held)
    result = run(cfg, cluster, tmp_path, sleep=sleep)
    assert result["complete"] and len(ticks) >= 5
    assert cluster.events[0] == ("start", "zmap", 0)


@posix
def test_lock_survives_in_a_child_after_the_coordinator_closes_its_descriptor(tmp_path):
    import fcntl
    import subprocess
    import sys
    fd = coordinator._try_zmap_lock(tmp_path)
    assert isinstance(fd, int) and coordinator._try_zmap_lock(tmp_path) is False
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], pass_fds=(fd,))
    try:
        os.close(fd)
        assert coordinator._try_zmap_lock(tmp_path) is False     # the worker still holds the sweep lock
    finally:
        child.kill()
        child.wait()
    again = coordinator._try_zmap_lock(tmp_path)
    assert isinstance(again, int)
    fcntl.flock(again, fcntl.LOCK_UN)
    os.close(again)


# ------------------------------------------------------------------ CLI

def test_stage_command_shape(tmp_path):
    cfg = make_cfg(tmp_path)
    cmd = coordinator.stage_command(cfg, tmp_path / "c.yaml", "zmap", 2, tmp_path / "run", "tok", 9)
    assert cmd[1:4] == ["-m", "scanner.internet", "stage-worker"]
    assert cmd[cmd.index("--stage") + 1] == "zmap" and cmd[cmd.index("--zmap-lock-fd") + 1] == "9" and "--confirm" in cmd and "--skip-pilot-check" in cmd
    assert "--zmap-lock-fd" not in coordinator.stage_command(cfg, tmp_path / "c.yaml", "network", 2, tmp_path / "run", "tok")


def _worker_args(cfg_path, cfg, stage, shard=1, extra=()):
    token = pipeline.confirm_token(cfg, pipeline.build_policy(cfg)[1])
    run_dir = Path(cfg.output_dir) / coordinator.run_id_for(cfg, shard)
    return ["stage-worker", "--config", str(cfg_path), "--confirm", token, "--stage", stage, "--shard", str(shard),
            "--run-dir", str(run_dir), "--skip-pilot-check", *extra], run_dir


def test_stage_worker_calls_the_pipeline_with_the_spec_arguments(tmp_path, monkeypatch):
    path = _cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 3})
    cfg = load_config(path)
    calls = []

    def fake_run(c, **kw):
        calls.append(("run", c.shard, kw))
        run_dir = Path(c.output_dir) / kw["run_id"]
        run_dir.mkdir(parents=True, exist_ok=True)
        flag = "zmap_done" if kw.get("stop_after_zmap") else "network_done"
        (run_dir / "manifest.json").write_text(json.dumps({flag: True}))
        return run_dir

    def fake_favicon(c, run_dir, **kw):
        calls.append(("favicon", c.shard, str(run_dir)))
        (Path(run_dir) / "manifest.json").write_text(json.dumps({"complete": True}))
        return Path(run_dir)
    monkeypatch.setattr(pipeline, "run", fake_run)
    monkeypatch.setattr(pipeline, "run_favicon_only", fake_favicon)
    argv, run_dir = _worker_args(path, cfg, "zmap", extra=("--zmap-lock-fd", "7"))
    assert cli.main(argv) == 0
    assert calls[-1] == ("run", 1, {"run_id": run_dir.name, "stop_after_zmap": True, "continue_in_place": True, "zmap_lock_fd": 7})
    argv, _ = _worker_args(path, cfg, "network")
    assert cli.main(argv) == 0
    assert calls[-1] == ("run", 1, {"run_id": run_dir.name, "from_zmap": True})
    argv, _ = _worker_args(path, cfg, "favicon")
    assert cli.main(argv) == 0
    assert calls[-1] == ("favicon", 1, str(run_dir))


def test_stage_worker_exit_codes(tmp_path, monkeypatch):
    path = _cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 3})
    cfg = load_config(path)
    argv, run_dir = _worker_args(path, cfg, "network")

    def unfinished(c, **kw):
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "manifest.json").write_text(json.dumps({"abort_reason": "stalled"}))
    monkeypatch.setattr(pipeline, "run", unfinished)
    assert cli.main(argv) == 5

    def boom(exc):
        def f(*a, **k):
            raise exc
        return f
    for exc, code in ((ConfigError("zmap results missing"), 2), (MemoryError(), coordinator.EXIT_RECYCLE), (RuntimeError("x"), 3)):
        monkeypatch.setattr(pipeline, "run", boom(exc))
        assert cli.main(argv) == code
    at = argv.index("--run-dir") + 1
    assert cli.main(argv[:at] + [str(tmp_path / "elsewhere" / "r")] + argv[at + 1:]) == 2


def test_decoupled_flags_are_refused_with_other_campaign_modes(tmp_path, capsys):
    path = _cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 3})
    cfg = load_config(path)
    token = pipeline.confirm_token(cfg, pipeline.build_policy(cfg)[1])
    for extra in (["--pipeline", "2"], ["--stop-after-network"]):
        assert cli.main(["campaign", "--decoupled", "--config", str(path), "--confirm", token, "--skip-pilot-check", *extra]) == 2
        assert "--decoupled does not combine" in capsys.readouterr().err
