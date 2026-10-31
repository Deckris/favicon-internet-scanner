"""The run monitor: stop conditions as an event, signals that wake workers, the stall check, drain and stack dumps."""
import os
import pathlib
import signal
import threading
import time
from types import SimpleNamespace

import pytest

from scanner.internet import campaign, pacing, pipeline
from scanner.internet.config import ConfigError, load_config
from tests.test_scale import _cfg, _fake_run

posix_only = pytest.mark.skipif(os.name != "posix" or not hasattr(signal, "SIGUSR1"), reason="POSIX signals")


@pytest.fixture
def fast_monitor(monkeypatch):
    monkeypatch.setattr(pipeline, "MONITOR_TICK", 0.05)


def _stages(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    return cfg, pipeline._Stages(cfg, tmp_path, guards=False)


def test_killed_follows_the_kill_file_without_a_stat_per_call(tmp_path, monkeypatch):
    cfg, st = _stages(tmp_path)
    kill = pathlib.Path(cfg.kill_switch_file)
    real = pathlib.Path.exists
    stats = []

    def counting(self, *a, **k):
        if self == kill:
            stats.append(1)
        return real(self, *a, **k)
    monkeypatch.setattr(pathlib.Path, "exists", counting)
    st.start_monitor()
    try:
        before = len(stats)
        assert not any(st.killed() for _ in range(5000))
        assert len(stats) - before <= 3                    # the monitor's own checks, nothing per call
        kill.parent.mkdir(parents=True, exist_ok=True)
        kill.write_text("stop")
        t = time.monotonic()
        while not st.killed() and time.monotonic() - t < 2:
            time.sleep(0.01)
        assert st.killed() and st.reason == "kill_switch" and st.stop.is_set()
        assert time.monotonic() - t < 0.8
    finally:
        st.stop_monitor()


def test_condition_already_true_at_start_is_seen_before_the_first_stage(tmp_path):
    cfg, st = _stages(tmp_path)
    pathlib.Path(cfg.kill_switch_file).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(cfg.kill_switch_file).write_text("stop")
    st.start_monitor()
    try:
        assert st.killed() and st.reason == "kill_switch"
    finally:
        st.stop_monitor()


def test_without_a_monitor_killed_still_checks_inline(tmp_path):
    cfg, st = _stages(tmp_path)
    assert st.killed() is False
    pathlib.Path(cfg.kill_switch_file).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(cfg.kill_switch_file).write_text("stop")
    assert st.killed() is True and st.reason == "kill_switch"


@posix_only
def test_sigterm_sets_the_event_before_the_stage_returns(tmp_path):
    cfg, st = _stages(tmp_path)
    restore = pipeline._install_signal_handlers(lambda: st.flag_stop("interrupt"))
    seen = {}

    def worker():
        seen["woke"] = st.stop.wait(10)
    t = threading.Thread(target=worker)
    t.start()
    threading.Timer(0.2, os.kill, (os.getpid(), signal.SIGTERM)).start()
    try:
        st.run("long", lambda: time.sleep(10), None)
        was_set = st.stop.is_set()          # ordering, not timestamps: the event is set by the time the stage has returned
    finally:
        restore()
    t.join(5)
    assert was_set and seen["woke"]
    assert st.reason == "interrupt" and st.interrupted and "long" in st.errors


def test_stall_fires_without_progress_and_no_tool(tmp_path, fast_monitor):
    cfg, st = _stages(tmp_path)
    st.stall_seconds = 0.4
    st.executor = SimpleNamespace(active_tools=0)
    st.start_monitor()
    t = time.monotonic()
    try:
        st.run("hung", lambda: st.stop.wait(10), None)
    finally:
        st.stop_monitor()
    assert st.reason == "stalled" and time.monotonic() - t < 5


def test_progress_or_a_running_tool_prevents_the_stall(tmp_path, fast_monitor):
    cfg, st = _stages(tmp_path)
    st.stall_seconds = 0.4
    st.executor = SimpleNamespace(active_tools=0)
    st.start_monitor()
    try:
        for _ in range(15):
            st.progress()
            time.sleep(0.1)
        assert st.reason is None
        st.executor = SimpleNamespace(active_tools=1)
        time.sleep(0.9)
        assert st.reason is None
    finally:
        st.stop_monitor()


def test_stall_can_be_switched_off(tmp_path, fast_monitor):
    cfg, st = _stages(tmp_path)
    st.stall_seconds = 0
    st.start_monitor()
    try:
        time.sleep(0.4)
        assert st.reason is None
    finally:
        st.stop_monitor()


def test_stall_minutes_is_optional_and_validated(tmp_path):
    assert load_config(_cfg(tmp_path)).stall_minutes == 30
    assert load_config(_cfg(tmp_path, operations={"stall_minutes": 0})).stall_minutes == 0
    with pytest.raises(ConfigError):
        load_config(_cfg(tmp_path, operations={"stall_minutes": -1}))


def test_a_stalled_run_leaves_a_manifest_with_the_reason(tmp_path, monkeypatch):
    from tests.helpers import FakeFetcher
    from tests.test_pipeline import tools
    monkeypatch.setattr(pipeline, "MONITOR_TICK", 0.05)
    orig = pipeline._Stages.start_monitor

    def quick(self):
        self.stall_seconds = 0.3
        orig(self)
    monkeypatch.setattr(pipeline._Stages, "start_monitor", quick)
    ft = tools()
    real_call = ft.__class__.__call__

    def hang_on_zmap(self, command, *a, **k):
        if command[0].endswith("zmap") and "--dryrun" not in command:
            time.sleep(1.5)
        return real_call(self, command, *a, **k)
    monkeypatch.setattr(ft.__class__, "__call__", hang_on_zmap)
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4}))
    run_dir = pipeline.run(cfg, run_id="stall", executor=ft, fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)
    import json
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["abort_reason"] == "stalled" and manifest["complete"] is False


def test_event_wakes_a_parked_pacer_at_once():
    stop = threading.Event()
    pacer = pacing.IpPacer(30, killed=stop.is_set, stop_event=stop)
    assert pacer.wait("192.0.2.1")                          # first request: no wait
    threading.Timer(0.2, stop.set).start()
    t = time.monotonic()
    assert pacer.wait("192.0.2.1") is False                 # parked for 30 s, released by the event
    assert time.monotonic() - t < 2


def test_ledger_claim_wakes_on_the_event():
    stop = threading.Event()
    ledger = pacing.ContactLedger(30, killed=stop.is_set, stop_event=stop)
    ledger.release(["192.0.2.2"])
    threading.Timer(0.2, stop.set).start()
    t = time.monotonic()
    assert ledger.claim(["192.0.2.2"]) is False
    assert time.monotonic() - t < 2


def test_drain_file_stops_the_campaign_between_shards(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    run_fn, calls = _fake_run(tmp_path, {})
    inner = run_fn

    def drain_after_first(c, **kw):
        out = inner(c, **kw)
        (campaign.campaign_dir(c) / "DRAIN").write_text("")
        return out
    logs = []
    result = campaign.run_campaign(cfg, run_fn=drain_after_first, log=logs.append)
    assert [c[0] for c in calls] == [0]                      # shard 0 finished, shard 1 never started
    assert result["stopped"]["reason"] == "drain" and result["shards_complete"] == 1 and not result["complete"]
    assert (campaign.campaign_dir(cfg) / "DRAIN").exists() and any("DRAIN" in m for m in logs)
    (campaign.campaign_dir(cfg) / "DRAIN").unlink()
    run_fn2, calls2 = _fake_run(tmp_path, {})
    assert campaign.run_campaign(cfg, run_fn=run_fn2, log=lambda *_: None)["complete"]
    assert [c[0] for c in calls2] == [1, 2]


@posix_only
def test_sigusr1_dumps_every_thread_and_is_unregistered_afterwards(tmp_path):
    (tmp_path / "raw").mkdir()
    release = pipeline._register_stack_dump(tmp_path)
    os.kill(os.getpid(), signal.SIGUSR1)
    time.sleep(0.2)
    text = (tmp_path / "raw" / "stacks.txt").read_text()
    assert "most recent call first" in text
    release()
    assert (tmp_path / "raw" / "stacks.txt").exists()      # kept: it holds a dump


@posix_only
def test_empty_stack_file_is_removed_at_the_end(tmp_path):
    (tmp_path / "raw").mkdir()
    release = pipeline._register_stack_dump(tmp_path)
    release()
    assert not (tmp_path / "raw" / "stacks.txt").exists()
