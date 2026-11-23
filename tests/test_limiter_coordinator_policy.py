"""Details of the coordinator's limiter policy: the environment of a stage worker, what counts as a pure limiter failure,
parked stages against a drain, a long probe failure and a clock that moves backwards."""
import json
import os
from pathlib import Path

import pytest

from scanner.internet import __main__ as cli
from scanner.internet import campaign, coordinator, limiterclient, pipeline
from scanner.internet.config import load_config
from tests.test_coordinator import _worker_args, state_of
from tests.test_limiter_outage_policy import START, Recorder, WallClock, drive, make_cfg, with_socket
from tests.test_scale import _cfg

KEY = "SCANNER_LIMITER_START_WAIT"


@pytest.fixture(autouse=True)
def fresh_failures():
    limiterclient.reset_failures()
    yield
    limiterclient.reset_failures()


# -------------------------------------------------------------------------------- the environment of a stage worker

def _network_worker(tmp_path, monkeypatch, seen):
    path = _cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 3})
    cfg = load_config(path)
    argv, run_dir = _worker_args(path, cfg, "network")

    def run(c, **kw):
        seen.append(os.environ.get(KEY))
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "manifest.json").write_text(json.dumps({"network_done": True}))
        return run_dir
    monkeypatch.setattr(pipeline, "run", run)
    return argv


def test_a_stage_worker_sets_the_start_wait_only_while_it_runs(tmp_path, monkeypatch):
    monkeypatch.delenv(KEY, raising=False)
    seen = []
    argv = _network_worker(tmp_path, monkeypatch, seen)
    assert cli.main(argv) == 0
    assert seen == [f"{coordinator.LIMITER_START_WAIT:g}"]          # what the stage and its children see
    assert KEY not in os.environ                                    # what the next caller in this process sees


def test_a_stage_worker_leaves_a_start_wait_that_was_set_alone(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY, "7")
    seen = []
    argv = _network_worker(tmp_path, monkeypatch, seen)
    assert cli.main(argv) == 0
    assert seen == ["7"] and os.environ[KEY] == "7"


def test_a_stage_worker_that_fails_restores_the_environment_too(tmp_path, monkeypatch):
    monkeypatch.delenv(KEY, raising=False)
    path = _cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 3})
    argv, _ = _worker_args(path, load_config(path), "network")

    def boom(c, **kw):
        raise RuntimeError("x")
    monkeypatch.setattr(pipeline, "run", boom)
    assert cli.main(argv) == 3
    assert KEY not in os.environ


# -------------------------------------------------------------------------------- what is a pure limiter failure

LIMITER_TEXT = "LimiterOutage: limiter at /run/x.sock unreachable for 601 s (limit 600 s)"


def test_workers_that_failed_for_other_reasons_too_are_not_a_limiter_failure():
    pure = {"stage_errors": {"favicon_workers": f"2 favicon worker process(es) failed, 9 of 9 lookups lost; first: {LIMITER_TEXT}"}}
    assert cli._limiter_failure_only(pure)
    mixed = {"stage_errors": {**pure["stage_errors"],
                              "favicon_workers_other": "1 favicon worker failure(s) not caused by the limiter; first: exited with code -9"}}
    assert not cli._limiter_failure_only(mixed)


def test_a_crashed_tool_job_is_not_a_limiter_failure():
    base = {"stage_errors": {"run": LIMITER_TEXT}}
    assert cli._limiter_failure_only(base)
    assert not cli._limiter_failure_only({**base, "tool_job_errors": 1})
    assert not cli._limiter_failure_only({**base, "tool_job_errors": ["zgrab: exited with code 2"]})
    assert cli._limiter_failure_only({**base, "tool_job_errors": 0})
    assert not cli._limiter_failure_only({**base, "abort_reason": "stalled"})
    assert not cli._limiter_failure_only({**base, "stages_skipped": ["favicon"]})


# -------------------------------------------------------------------------------- a drain does not end a parked stage

def test_a_drain_waits_for_a_parked_stage_before_it_ends_the_campaign(tmp_path):
    cfg = make_cfg(tmp_path, shards=3)
    clock = WallClock()
    cluster = Recorder(cfg, clock, fail={("network", 0): [77, 0]}, durations={("network", 0): 1})
    drain = campaign.campaign_dir(cfg) / "DRAIN"
    real = cluster.spawn

    def spawn(cmd, fds):
        if cmd[cmd.index("--stage") + 1] == "zmap" and cmd[cmd.index("--shard") + 1] == "1":
            drain.parent.mkdir(parents=True, exist_ok=True)
            drain.write_text("")                                    # the operator asks for a stop between shards
        return real(cmd, fds)
    cluster.spawn = spawn
    result, _ = drive(cfg, cluster, tmp_path, clock)
    assert result["stopped"]["reason"] == "drain"
    assert ("fail", "network", 0) in cluster.events
    assert ("done", "network", 0) in cluster.events                 # the parked stage was started again and finished
    assert state_of(cfg)["shard_states"]["0"]["stages"]["network"]["status"] == "done"
    assert ("start", "zmap", 2) not in cluster.events               # the drain still holds back the sweeps


# -------------------------------------------------------------------------------- a long probe failure raises an alert

def test_a_probe_that_keeps_failing_with_nothing_running_raises_one_alert(tmp_path, monkeypatch):
    monkeypatch.setattr(coordinator, "LIMITER_PROBE_RETRY", 0.0)
    monkeypatch.setattr(coordinator, "LIMITER_PROBE_ALERT", 0.0)
    cfg = with_socket(make_cfg(tmp_path), tmp_path / "limiter.sock")
    clock = WallClock()
    cluster = Recorder(cfg, clock)
    result, log = drive(cfg, cluster, tmp_path, clock,
                        limiter_probe=lambda c: None if clock.t >= START + 60 else "FileNotFoundError: no socket")
    assert result["complete"]
    alerts = [line for line in log if line.startswith("[coordinator] ALERT")]
    assert len(alerts) == 1 and "limiter" in alerts[0]
    assert "limiter" in (campaign.campaign_dir(cfg) / "ALERT").read_text()
    assert min(t for t, *_ in cluster.starts) >= START + 60


def test_a_short_probe_failure_raises_no_alert(tmp_path, monkeypatch):
    monkeypatch.setattr(coordinator, "LIMITER_PROBE_RETRY", 0.0)
    cfg = with_socket(make_cfg(tmp_path), tmp_path / "limiter.sock")
    clock = WallClock()
    result, log = drive(cfg, Recorder(cfg, clock), tmp_path, clock,
                        limiter_probe=lambda c: None if clock.t >= START + 10 else "down")
    assert result["complete"]
    assert not [line for line in log if "ALERT" in line]
    assert not (campaign.campaign_dir(cfg) / "ALERT").exists()


# -------------------------------------------------------------------------------- a clock set back, and the alert wording

def test_a_cooldown_recorded_far_in_the_future_is_cut_to_the_longest_one(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    clock = WallClock()
    result, _ = drive(cfg, Recorder(cfg, clock), tmp_path, clock)
    assert result["complete"]
    state = state_of(cfg)
    for name in ("network", "favicon"):
        state["shard_states"]["1"]["stages"][name].update(status="pending", not_before=START + 10 ** 7, limiter_parks=3)
    campaign._write_json(campaign.campaign_dir(cfg) / "campaign.json", state)
    clock2 = WallClock()
    second = Recorder(cfg, clock2)
    result, _ = drive(cfg, second, tmp_path, clock2)
    assert result["complete"]
    assert second.starts_of("network", 1)[0] <= START + max(coordinator.LIMITER_COOLDOWNS) + 60


def test_the_alert_at_the_park_cap_says_what_the_count_means(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    clock = WallClock(step=20.0)
    _, log = drive(cfg, Recorder(cfg, clock, fail={("network", 0): 77}), tmp_path, clock)
    alert = [line for line in log if line.startswith("[coordinator] ALERT")][0]
    assert f"{coordinator.MAX_LIMITER_PARKS} earlier runs of this stage" in alert
    assert "in a row" not in alert


def test_a_clock_set_back_during_the_run_cannot_stretch_a_park(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    clock = WallClock()
    cluster = Recorder(cfg, clock, fail={("network", 0): [77, 0]})
    stepped = {}

    def sleep(_):
        clock.sleep(_)
        if not stepped and ("fail", "network", 0) in cluster.events:
            clock.t -= 86400.0                                      # the wall clock jumps back a day while the stage is parked
            stepped["at"] = clock.t
    result = coordinator.run_decoupled(cfg, config_path=tmp_path / "scale.yaml", confirm="tok", log=lambda *_: None, spawn=cluster.spawn,
                                       tick=0, sleep=sleep, egress=lambda c: c.vantage.public_egress_ip, alive=lambda p: False,
                                       allow_per_process_limits=True, zmap_lock=tmp_path / "zmap.lock", clock=clock,
                                       limiter_probe=lambda c: None)
    assert result["complete"] and stepped
    starts = cluster.starts_of("network", 0)
    assert len(starts) == 2 and starts[1] <= stepped["at"] + max(coordinator.LIMITER_COOLDOWNS) + 60


def test_a_park_within_the_longest_cooldown_is_not_shortened_by_the_clamp(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    clock = WallClock()
    cluster = Recorder(cfg, clock, fail={("network", 0): [77, 0]})
    result, _ = drive(cfg, cluster, tmp_path, clock)
    assert result["complete"]
    first, second = cluster.starts_of("network", 0)[:2]
    assert second - first >= coordinator.LIMITER_COOLDOWNS[0]
