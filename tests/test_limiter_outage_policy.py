"""What the coordinator does when the limiter daemon cannot be reached: a distinct exit code, a cooldown, a bounded
number of parks, a probe before a stage starts, and a total wait that stays under the stall rule."""
import dataclasses
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.internet import __main__ as cli
from scanner.internet import campaign, coordinator, limiterclient, pipeline
from scanner.internet.config import load_config
from scanner.internet.limiterclient import LimiterClient, LimiterOutage, LimiterUnavailable
from tests.test_coordinator import Cluster, _worker_args, make_cfg, seed_state, state_of
from tests.limiter_support import Server, deadline  # noqa: F401
from tests.test_limiterd import _hung_server, unix_only, until
from tests.test_scale import _cfg

START = 1_800_000_000.0


class WallClock:
    """The wall clock of a coordinator run, moved by the loop's own sleep so a cooldown costs no real time."""

    def __init__(self, step=5.0):
        self.t, self.step = START, step

    def __call__(self):
        return self.t

    def sleep(self, _):
        self.t += self.step


def with_socket(cfg, path):
    return dataclasses.replace(cfg, measurement=SimpleNamespace(**{**vars(cfg.measurement), "limiter_socket": str(path)}))


def drive(cfg, cluster, tmp_path, clock, log=None, **kw):
    """``run_decoupled`` with the fake workers, the fake wall clock and a log that is kept."""
    lines = [] if log is None else log
    kw.setdefault("limiter_probe", lambda c: None)
    result = coordinator.run_decoupled(cfg, config_path=tmp_path / "scale.yaml", confirm="tok", log=lines.append, spawn=cluster.spawn, tick=0,
                                       sleep=clock.sleep, egress=lambda c: c.vantage.public_egress_ip, alive=lambda p: False,
                                       allow_per_process_limits=True, zmap_lock=tmp_path / "zmap.lock", clock=clock, **kw)
    return result, lines


class Recorder(Cluster):
    """Fake workers that note when each stage was started, by the fake wall clock."""

    def __init__(self, cfg, clock, **kw):
        super().__init__(cfg, **kw)
        self.clock, self.starts = clock, []

    def spawn(self, cmd, pass_fds):
        stage, shard = cmd[cmd.index("--stage") + 1], int(cmd[cmd.index("--shard") + 1])
        self.starts.append((self.clock.t, stage, shard))
        return super().spawn(cmd, pass_fds)

    def starts_of(self, stage, shard):
        return [t for t, s, i in self.starts if (s, i) == (stage, shard)]


# ---------------------------------------------------------------------------------------- the worker's exit code

def _unfinished(monkeypatch, stage_errors, kinds=(), **manifest):
    """A stage that ends without finishing, with the failures it recorded in the manifest and in this process."""
    limiterclient.reset_failures()

    def run(c, **kw):
        run_dir = Path(c.output_dir) / kw["run_id"]
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "manifest.json").write_text(json.dumps({"stage_errors": stage_errors, **manifest}))
        for kind in kinds:
            limiterclient.note_failure(kind)
        return run_dir

    def favicon(c, run_dir, **kw):
        Path(run_dir).mkdir(parents=True, exist_ok=True)
        (Path(run_dir) / "manifest.json").write_text(json.dumps({"stage_errors": stage_errors, **manifest}))
        for kind in kinds:
            limiterclient.note_failure(kind)
        return Path(run_dir)
    monkeypatch.setattr(pipeline, "run", run)
    monkeypatch.setattr(pipeline, "run_favicon_only", favicon)


@pytest.fixture(autouse=True)
def fresh_failures(monkeypatch):
    """A stage worker sets the start wait in the environment of its own process; here that process is the test run."""
    monkeypatch.setenv("SCANNER_LIMITER_START_WAIT", "0")
    limiterclient.reset_failures()
    yield
    limiterclient.reset_failures()


@pytest.fixture
def worker(tmp_path):
    path = _cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 3})
    cfg = load_config(path)
    return lambda stage: _worker_args(path, cfg, stage)[0]


CASES = {
    "network start": ("network", {"run": "LimiterUnavailable: no limiter daemon answers at /run/x.sock: FileNotFoundError"}),
    "network mid-run": ("network", {"run": "LimiterOutage: limiter at /run/x.sock unreachable for 601 s (limit 600 s)"}),
    "favicon start": ("favicon", {"favicon": "LimiterUnavailable: no limiter daemon answers at /run/x.sock"}),
    "favicon mid-run": ("favicon", {"favicon": "LimiterOutage: limiter at /run/x.sock unreachable for 601 s (limit 600 s)"}),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_stage_worker_returns_77_for_a_pure_limiter_failure_and_5_for_a_mixed_one(case, worker, monkeypatch):
    stage, errors = CASES[case]
    _unfinished(monkeypatch, errors, kinds=("limiter",))
    assert cli.main(worker(stage)) == coordinator.EXIT_LIMITER == 77
    _unfinished(monkeypatch, {**errors, "tls": "ValueError: not a limiter"}, kinds=("limiter",))
    assert cli.main(worker(stage)) == 5
    _unfinished(monkeypatch, errors, kinds=("limiter", "other"))
    assert cli.main(worker(stage)) == 5
    _unfinished(monkeypatch, errors, kinds=("limiter",), abort_reason="stalled")
    assert cli.main(worker(stage)) == 5
    _unfinished(monkeypatch, errors, kinds=("limiter",), stages_skipped=["dns"])
    assert cli.main(worker(stage)) == 5


def test_an_unfinished_stage_without_any_limiter_failure_is_still_5(worker, monkeypatch):
    _unfinished(monkeypatch, {}, kinds=())
    assert cli.main(worker("network")) == 5
    _unfinished(monkeypatch, {"run": "RuntimeError: boom"}, kinds=())
    assert cli.main(worker("favicon")) == 5


def test_an_exception_that_leaves_the_stage_is_77_only_when_it_is_a_limiter_one(worker, monkeypatch):
    limiterclient.reset_failures()

    def boom(exc):
        def f(*a, **k):
            limiterclient.note_failure("limiter") if isinstance(exc, (LimiterOutage, LimiterUnavailable)) else None
            raise exc
        return f
    for exc, code in ((LimiterOutage("unreachable"), 77), (LimiterUnavailable("no daemon"), 77), (RuntimeError("x"), 3)):
        limiterclient.reset_failures()
        monkeypatch.setattr(pipeline, "run", boom(exc))
        assert cli.main(worker("network")) == code


def test_the_worker_starts_with_the_start_wait_unless_one_is_set(worker, monkeypatch):
    seen = []

    def run(c, **kw):
        seen.append(os.environ.get("SCANNER_LIMITER_START_WAIT"))
        run_dir = Path(c.output_dir) / kw["run_id"]
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "manifest.json").write_text(json.dumps({"network_done": True}))
        return run_dir
    monkeypatch.setattr(pipeline, "run", run)
    monkeypatch.delenv("SCANNER_LIMITER_START_WAIT", raising=False)
    assert cli.main(worker("network")) == 0
    monkeypatch.delenv("SCANNER_LIMITER_START_WAIT", raising=False)
    monkeypatch.setenv("SCANNER_LIMITER_START_WAIT", "7")
    assert cli.main(worker("network")) == 0
    assert seen == ["120", "7"]


# ------------------------------------------------------------------------- where a limiter failure ends up, per stage

def _manifest_of(run_dir):
    return json.loads((Path(run_dir) / "manifest.json").read_text())


def _network_run(tmp_path, socket_path):
    from tests.helpers import FakeFetcher
    from tests.test_pipeline import tools
    cfg = load_config(_cfg(tmp_path))
    cfg = dataclasses.replace(cfg, measurement=SimpleNamespace(**{**vars(cfg.measurement), "limiter_socket": str(socket_path)}))
    limiterclient.reset_failures()
    return pipeline.run(cfg, executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)


def test_a_network_stage_that_cannot_reach_the_limiter_at_its_start_is_a_limiter_failure(tmp_path):
    run_dir = _network_run(tmp_path, tmp_path / "absent.sock")
    manifest = _manifest_of(run_dir)
    assert "LimiterUnavailable" in manifest["stage_errors"]["run"] and not manifest["complete"]
    assert limiterclient.failure_kinds() == {"limiter": 1}
    assert cli._limiter_failure_only(manifest)
    limiterclient.reset_failures()


@unix_only
def test_a_network_stage_that_loses_the_limiter_during_the_run_is_a_limiter_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("SCANNER_LIMITER_OUTAGE_LIMIT", "1")
    cfg = load_config(_cfg(tmp_path))
    m = cfg.measurement
    s = Server(tmp_path / "live.sock", cap=m.max_connections_per_subnet, gap=m.min_seconds_between_probes_per_ip).start()
    real, seen = s.core.handle, {"claims": 0}

    def handle(conn, req):
        if req.get("op") == "claim":
            seen["claims"] += 1
            if seen["claims"] >= 2:
                s.mute.set()                                           # the daemon stops answering after its first claim
        return real(conn, req)
    s.core.handle = handle
    try:
        manifest = _manifest_of(_network_run(tmp_path, s.path))
    finally:
        s.mute.clear()
        s.stop()
    errors = manifest["stage_errors"]
    assert errors and all("LimiterOutage" in text for text in errors.values()) and not manifest["complete"]
    assert limiterclient.failure_kinds().get("limiter", 0) >= 1
    assert cli._limiter_failure_only(manifest)
    limiterclient.reset_failures()


def test_favicon_workers_that_cannot_reach_the_limiter_at_their_start_report_it_by_name(tmp_path, monkeypatch):
    from scanner.internet import favicon
    from tests.helpers import ProcessFetcherFactory
    from tests.test_favicon_processes import make_jobs
    monkeypatch.setenv("SCANNER_LIMITER_START_WAIT", "0.3")
    failures = []
    records = favicon.run_favicon_stage_processes(ProcessFetcherFactory(), make_jobs(12), processes=2, workers=4, pace=0.0, max_icons=2,
                                                  subnet_cap=4, limiter_socket=str(tmp_path / "absent.sock"),
                                                  on_failure=lambda why, lost: failures.append((why, lost)))
    assert len(records) == len(make_jobs(12)) and failures                   # every lookup still leaves a record
    assert all("LimiterUnavailable" in why for why, _ in failures)
    assert sum(lost for _, lost in failures) == len(records)
    assert cli._limiter_failure_only({"stage_errors": {"favicon_workers": failures[0][0]}})


# --------------------------------------------------------------------------------------------- the coordinator

def test_a_limiter_exit_is_not_counted_and_is_parked(tmp_path):
    cfg = make_cfg(tmp_path)
    clock = WallClock()
    cluster = Recorder(cfg, clock, fail={("network", 1): [77, 77, 77, 77, 77, 77, 0]})
    result, log = drive(cfg, cluster, tmp_path, clock)
    assert result["complete"] and result["stopped"] is None
    st = state_of(cfg)["shard_states"]["1"]["stages"]["network"]
    assert st["status"] == "done" and st["attempts"] == 0 and st["limiter_parks"] == 6
    starts = cluster.starts_of("network", 1)
    assert len(starts) == 7
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    for gap, cooldown in zip(gaps, (30, 60, 120, 300, 600, 600)):
        assert cooldown <= gap <= cooldown + 60                      # nothing starts early, and it starts once the time is up
    assert any("not counted" in line and "unreachable" in line for line in log)


def test_a_parked_stage_does_not_block_the_others(tmp_path):
    cfg = make_cfg(tmp_path)
    clock = WallClock()
    cluster = Recorder(cfg, clock, fail={("network", 0): [77, 0]})
    result, _ = drive(cfg, cluster, tmp_path, clock)
    assert result["complete"]
    ev = cluster.events
    assert ev.index(("done", "network", 1)) < ev.index(("done", "network", 0))
    assert [e for e in ev if e[:2] == ("fail", "network")] == [("fail", "network", 0)]


def test_parks_are_capped_and_the_cap_raises_an_alert(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    clock = WallClock(step=20.0)
    cluster = Recorder(cfg, clock, fail={("network", 0): 77})
    result, log = drive(cfg, cluster, tmp_path, clock)
    assert not result["complete"] and result["stopped"]["reason"] == "crashed"
    st = state_of(cfg)["shard_states"]["0"]["stages"]["network"]
    assert st["status"] == "failed" and st["limiter_parks"] == coordinator.MAX_LIMITER_PARKS == 20
    assert 1 <= st["attempts"] <= coordinator.MAX_ATTEMPTS
    assert len(cluster.starts_of("network", 0)) == 20 + coordinator.MAX_ATTEMPTS
    alerts = [line for line in log if line.startswith("[coordinator] ALERT")]
    assert alerts
    alert_file = campaign.campaign_dir(cfg) / "ALERT"
    assert alert_file.is_file() and "network" in alert_file.read_text()
    waits = [b - a for a, b in zip(cluster.starts_of("network", 0), cluster.starts_of("network", 0)[1:])]
    assert max(waits[:20]) <= 600 + 120                                # the cooldown never grows past its last value


def test_a_limiter_exit_while_stopping_is_not_counted(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    clock = WallClock()
    cluster = Recorder(cfg, clock, fail={("network", 0): [77], ("network", 1): [77]})
    kill = Path(cfg.kill_switch_file)
    real = cluster.spawn

    def spawn(cmd, fds):
        proc = real(cmd, fds)
        if "network" in cmd:
            kill.write_text("stop")                                  # the operator stops the campaign as the stage starts
        return proc
    try:
        result = coordinator.run_decoupled(cfg, config_path=tmp_path / "scale.yaml", confirm="tok", log=lambda *_: None, spawn=spawn, tick=0,
                                           sleep=clock.sleep, egress=lambda c: c.vantage.public_egress_ip, alive=lambda p: False,
                                           allow_per_process_limits=True, zmap_lock=tmp_path / "zmap.lock", clock=clock,
                                           limiter_probe=lambda c: None)
    finally:
        kill.unlink(missing_ok=True)
    assert result["stopped"]["reason"] == "kill_switch"
    for shard in ("0", "1"):
        st = state_of(cfg)["shard_states"][shard]["stages"]["network"]
        assert st["attempts"] == 0 and st.get("limiter_parks", 0) == 0 and st["status"] == "pending"


def test_old_state_loads_and_new_keys_survive_a_reload(tmp_path):
    cfg = make_cfg(tmp_path)
    clock = WallClock()
    first = Recorder(cfg, clock, fail={("network", 1): 77}, durations={("network", 1): 2})
    # one park, then the process that held the campaign ends before the cooldown is over
    stop = {"n": 0}

    def sleep(_):
        stop["n"] += 1
        clock.t += 1.0
        if first.events.count(("fail", "network", 1)) >= 1:
            Path(cfg.kill_switch_file).write_text("stop")
    try:
        coordinator.run_decoupled(cfg, config_path=tmp_path / "scale.yaml", confirm="tok", log=lambda *_: None, spawn=first.spawn, tick=0,
                                  sleep=sleep, egress=lambda c: c.vantage.public_egress_ip, alive=lambda p: False,
                                  allow_per_process_limits=True, zmap_lock=tmp_path / "zmap.lock", clock=clock, limiter_probe=lambda c: None)
    finally:
        Path(cfg.kill_switch_file).unlink(missing_ok=True)
    kept = state_of(cfg)["shard_states"]["1"]["stages"]["network"]
    assert kept["limiter_parks"] == 1 and kept["not_before"] and kept["attempts"] == 0
    second = Recorder(cfg, clock)                                  # the next coordinator reads the keys and honours them
    result, _ = drive(cfg, second, tmp_path, clock)
    assert result["complete"]
    assert all(t >= kept["not_before"] for t in second.starts_of("network", 1))
    assert state_of(cfg)["shard_states"]["1"]["stages"]["network"]["limiter_parks"] == 1


def test_a_state_written_before_parks_existed_is_read_as_it_was(tmp_path):
    cfg = make_cfg(tmp_path)
    clock = WallClock()
    result, _ = drive(cfg, Recorder(cfg, clock), tmp_path, clock)
    assert result["complete"]
    state = state_of(cfg)
    for entry in state["shard_states"].values():
        for st in entry["stages"].values():
            st.pop("limiter_parks", None)
            st.pop("not_before", None)
    campaign._write_json(campaign.campaign_dir(cfg) / "campaign.json", state)
    result, _ = drive(cfg, Recorder(cfg, clock), tmp_path, clock)
    assert result["complete"]


def test_retry_failed_resets_the_parks(tmp_path):
    cfg = make_cfg(tmp_path, shards=2)
    clock = WallClock(step=20.0)
    drive(cfg, Recorder(cfg, clock, fail={("network", 0): 77}), tmp_path, clock)
    assert state_of(cfg)["shard_states"]["0"]["stages"]["network"]["status"] == "failed"
    clock2 = WallClock()
    second = Recorder(cfg, clock2, fail={("network", 0): [77, 0]})
    result, _ = drive(cfg, second, tmp_path, clock2, retry_failed=True)
    assert result["complete"]
    st = state_of(cfg)["shard_states"]["0"]["stages"]["network"]
    assert st["limiter_parks"] == 1 and st["attempts"] == 0


# ------------------------------------------------------------------------------------------------ the probe gate

def test_the_probe_gate_starts_nothing_while_the_socket_fails_and_starts_when_it_answers(tmp_path, monkeypatch):
    monkeypatch.setattr(coordinator, "LIMITER_PROBE_RETRY", 0.0)                    # the loop here runs on a fake clock
    cfg = with_socket(make_cfg(tmp_path), tmp_path / "limiter.sock")
    clock = WallClock()
    cluster = Recorder(cfg, clock)
    opens_at = START + 120.0
    asked = []

    def probe(c):
        asked.append(clock.t)
        return None if clock.t >= opens_at else "FileNotFoundError: no daemon"
    result, log = drive(cfg, cluster, tmp_path, clock, limiter_probe=probe)
    assert result["complete"]
    assert cluster.starts and min(t for t, _, _ in cluster.starts) >= opens_at           # not a single worker before it answers
    assert len([line for line in log if "does not answer" in line]) == 1                 # said once, not on every tick
    assert any(t < opens_at for t in asked)


def test_the_probe_is_not_asked_without_a_limiter_socket(tmp_path):
    cfg = make_cfg(tmp_path)
    clock = WallClock()
    asked = []
    result, _ = drive(cfg, Recorder(cfg, clock), tmp_path, clock, limiter_probe=lambda c: asked.append(1) or "down")
    assert result["complete"] and not asked


@unix_only
def test_the_probe_answers_for_a_live_daemon_and_describes_a_dead_one(tmp_path):
    m_cfg = make_cfg(tmp_path)
    cap, gap = m_cfg.measurement.max_connections_per_subnet, m_cfg.measurement.min_seconds_between_probes_per_ip
    path = tmp_path / "limiter.sock"
    cfg = with_socket(m_cfg, path)
    assert "FileNotFoundError" in coordinator.probe_limiter(cfg)
    s = Server(path, cap=cap, gap=gap).start()
    try:
        assert coordinator.probe_limiter(cfg) is None
        until(lambda: s.core.snapshot()["connections"] == 0 and s.core.snapshot()["lingering"] == 0, "the probe's goodbye")
        assert [op for _, op, _ in s.seen][-3:] == ["hello", "ping", "goodbye"]
        hello = s.ops("hello")[-1][1]
        assert hello["client"].startswith("probe-") and hello["held"] == {} and hello["busy"] == []
    finally:
        s.stop()
    assert coordinator.probe_limiter(cfg) is not None


@unix_only
def test_the_probe_gives_up_on_a_daemon_that_never_answers(tmp_path):
    path = tmp_path / "hung.sock"
    close = _hung_server(path)
    try:
        started = time.monotonic()
        problem = coordinator.probe_limiter(with_socket(make_cfg(tmp_path), path), timeout=0.5)
        assert problem and time.monotonic() - started < 3.0
    finally:
        close()


# ------------------------------------------------------------------------------------------------- the budget

def test_the_outage_budget_stays_below_the_stall_rule():
    assert coordinator.LIMITER_START_WAIT == 120.0
    assert limiterclient.OUTAGE_LIMIT == coordinator.LIMITER_OUTAGE_LIMIT == 600.0
    assert max(coordinator.LIMITER_COOLDOWNS) == 600
    assert coordinator.LIMITER_COOLDOWNS == (30, 60, 120, 300, 600)
    assert coordinator.MAX_LIMITER_PARKS == 20
    assert coordinator.limiter_budget_seconds() == 120 + 600 + 600 == 1320
    assert 120 + 600 + 600 < 1800                                       # the stall rule of 30 minutes and the watchdog's default
    from scanner.internet.config import ScanConfig
    assert ScanConfig.__dataclass_fields__["stall_minutes"].default * 60 > coordinator.limiter_budget_seconds()


def test_a_stall_rule_below_the_budget_is_reported_at_the_start(tmp_path):
    cfg = make_cfg(tmp_path)
    tight = dataclasses.replace(cfg, stall_minutes=20)
    clock = WallClock()
    result, log = drive(with_socket(tight, tmp_path / "x.sock"), Recorder(tight, clock), tmp_path, clock)
    assert any("stall_minutes" in line and "WARNING" in line for line in log)
    clock = WallClock()
    result, log = drive(with_socket(cfg, tmp_path / "x.sock"), Recorder(cfg, clock), tmp_path, clock)
    assert not any("stall_minutes" in line for line in log)
    assert coordinator.limiter_budget_problem(dataclasses.replace(cfg, stall_minutes=0)) is None
    assert coordinator.limiter_budget_problem(tight)


def test_the_outage_limit_comes_from_the_environment_and_the_argument_wins(tmp_path, monkeypatch):
    path = str(tmp_path / "x.sock")
    assert LimiterClient(path, 4, 5.0).outage_limit == 600.0
    monkeypatch.setenv("SCANNER_LIMITER_OUTAGE_LIMIT", "120")
    assert LimiterClient(path, 4, 5.0).outage_limit == 120.0
    assert LimiterClient(path, 4, 5.0, outage_limit=3).outage_limit == 3.0
    monkeypatch.setenv("SCANNER_LIMITER_OUTAGE_LIMIT", "not a number")
    assert LimiterClient(path, 4, 5.0).outage_limit == 600.0
