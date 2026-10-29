"""A killed run must leave nothing sending: inherited phase lock, one sweep per host, stop checks before a due slot, stale attempts."""
import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.internet import campaign, pacing, preflight, supervisor
from scanner.internet.config import load_config
from tests.test_scale import _cfg

posix = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs Linux (fcntl, prctl, /proc)")
ROOT = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------ pacing: stop conditions win over a due slot

def test_a_due_slot_is_not_granted_after_a_stop():
    stopped = [False]
    clock = lambda: 1000.0                                          # noqa: E731
    pacer = pacing.IpPacer(15, killed=lambda: stopped[0], now=clock, sleep=lambda s: None)
    assert pacer.wait("1.1.1.1")
    stopped[0] = True
    assert not pacer.wait("2.2.2.2")                                # a fresh address is due at once, but the run is stopping
    assert not pacer.wait("1.1.1.1")

    gap = pacing.Gap(15, killed=lambda: stopped[0], now=clock, sleep=lambda s: None)
    assert not gap.wait()                                           # nothing marked yet, still no go-ahead
    gap.mark()
    assert not gap.wait()

    ledger = pacing.ContactLedger(15, killed=lambda: stopped[0], now=clock, sleep=lambda s: None)
    assert not ledger.wait(["3.3.3.3"])
    assert not ledger.claim(["3.3.3.3"])


def test_a_set_stop_event_refuses_a_due_slot():
    import threading
    event = threading.Event()
    pacer = pacing.IpPacer(15, stop_event=event)
    assert pacer.wait("1.1.1.1")
    event.set()
    assert not pacer.wait("2.2.2.2")
    assert not pacing.IpPacer(0, stop_event=event).wait("2.2.2.2")


# ------------------------------------------------------------------ preflight: one sweep per host

def _fake_proc(root, entries):
    for pid, comm in entries.items():
        d = root / str(pid)
        d.mkdir(parents=True)
        (d / "comm").write_text(comm + "\n")
    (root / "self").mkdir()


def test_running_zmap_processes_are_found_by_command_name(tmp_path):
    _fake_proc(tmp_path, {41: "zmap", 42: "zgrab2", 43: "python3", 44: "my-zmap-binary-"})
    assert preflight.running_zmap_pids(proc=tmp_path) == [41]
    assert preflight.running_zmap_pids(("zmap", "my-zmap-binary-long"), proc=tmp_path) == [41, 44]
    assert preflight.running_zmap_pids(proc=tmp_path / "missing") is None


def test_preflight_fails_while_another_zmap_runs(tmp_path, monkeypatch):
    from tests.test_pipeline import tools
    from scanner.internet import pipeline
    cfg = load_config(_cfg(tmp_path))
    _, splan, _ = pipeline.build_policy(cfg)
    monkeypatch.setattr(preflight, "running_zmap_pids", lambda *a, **k: [4242])
    rep = preflight.run_preflight(cfg, splan, run_dir=tmp_path, executor=tools(), offline=True)
    check = next(c for c in rep["checks"] if c["name"] == "no_other_zmap")
    assert check["status"] == "fail" and "4242" in check["detail"] and not rep["ok"]
    monkeypatch.setattr(preflight, "running_zmap_pids", lambda *a, **k: [])
    rep = preflight.run_preflight(cfg, splan, run_dir=tmp_path, executor=tools(), offline=True)
    assert next(c for c in rep["checks"] if c["name"] == "no_other_zmap")["status"] == "pass"


# ------------------------------------------------------------------ the sweep tool keeps the phase lock

HOLDER = textwrap.dedent('''
    import fcntl, os, sys
    from pathlib import Path
    from types import SimpleNamespace
    from scanner.internet import runner

    lock, tool, ready = sys.argv[1:4]
    fd = os.open(lock, os.O_CREAT | os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    runner.hold_fd(fd)
    cfg = SimpleNamespace(binaries=SimpleNamespace(zmap=tool, zgrab2="zgrab2", zdns="zdns"))
    runner.ManagedExecutor(cfg, Path(ready).parent, lambda: False)(["zmap"], timeout=60)
''')

STAND_IN = textwrap.dedent('''\
    #!%s
    import ctypes, os, sys, time
    ctypes.CDLL(None).prctl(1, 0, 0, 0, 0)        # what executing a file-capability binary does to the death signal
    open(sys.argv[0] + ".pid", "w").write(str(os.getpid()))
    time.sleep(60)
''')


def _lock_free(path):
    import fcntl
    fd = os.open(path, os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False
    finally:
        os.close(fd)


@posix
def test_the_sweep_tool_keeps_the_phase_lock_when_its_parent_is_killed(tmp_path):
    tool = tmp_path / "zmap-standin"
    tool.write_text(STAND_IN % sys.executable)
    tool.chmod(0o755)
    lock = tmp_path / "phase-a.lock"
    holder = subprocess.Popen([sys.executable, "-c", HOLDER, str(lock), str(tool), str(tmp_path / "ready")], cwd=ROOT,
                              env={**os.environ, "PYTHONPATH": str(ROOT)})
    pid_file = Path(str(tool) + ".pid")
    try:
        for _ in range(200):
            if pid_file.exists() and pid_file.read_text():
                break
            time.sleep(0.05)
        tool_pid = int(pid_file.read_text())
        assert not _lock_free(lock)
        holder.kill()
        holder.wait()
        time.sleep(0.3)
        os.kill(tool_pid, 0)                                         # the stand-in survived, as a capability-bearing zmap would
        assert not _lock_free(lock)                                  # and the lock went on being held
        os.kill(tool_pid, signal.SIGKILL)
        for _ in range(100):
            if _lock_free(lock):
                break
            time.sleep(0.05)
        assert _lock_free(lock)
    finally:
        holder.kill()
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text()), signal.SIGKILL)
            except (OSError, ValueError):
                pass


@posix
def test_phase_gate_registers_its_lock_for_the_tool_only_while_held(tmp_path):
    from scanner.internet import runner
    gate = supervisor.PhaseGate(tmp_path, "r1")
    with gate("a"):
        assert len(runner._INHERITED_FDS) == 1
        with gate("b"):
            assert len(runner._INHERITED_FDS) == 1                  # the favicon-stage lock is not handed to the sweep tool
    assert runner._INHERITED_FDS == {}


# ------------------------------------------------------------------ supervisor child start

@posix
def test_a_child_whose_supervisor_is_already_gone_does_not_start(tmp_path):
    assert supervisor._die_with_parent(os.getppid())
    assert not supervisor._die_with_parent(os.getppid() + 100000)
    rc = supervisor.child_main(["--child", "--config", str(tmp_path / "x.yaml"), "--shard", "0", "--run-id", "r", "--checksum", "c",
                                "--campaign-dir", str(tmp_path), "--supervisor-pid", str(os.getppid() + 100000)])
    assert rc == supervisor.EXIT_INTERRUPTED and not list(tmp_path.iterdir())


# ------------------------------------------------------------------ campaign: stale work, resume source

def _attempt(cfg, shard, n, *, records=True, work=True, complete=False, checksum=None):
    d = Path(cfg.output_dir) / campaign._run_id(cfg, shard, n)
    (d / "raw").mkdir(parents=True)
    (d / "manifest.json").write_text(json.dumps({"complete": complete, "zero_responsive": False, "config_checksum": checksum or cfg.checksum,
                                                 "shard": {"index": shard}}))
    if records:
        (d / "raw" / "favicon_records.jsonl").write_text("{}\n")
    if work:
        (d / "work").mkdir()
        (d / "work" / "facts.sqlite").write_text("x")
        (d / "work" / "facts.sqlite-wal").write_text("x")
    return d


def test_a_new_attempt_clears_the_work_files_of_earlier_unfinished_ones_and_resumes_from_the_latest(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    first, second = _attempt(cfg, 1, 1), _attempt(cfg, 1, 2, records=False)
    other_shard = _attempt(cfg, 0, 1)
    state = {"shard_states": {"1": {"status": "crashed", "attempts": 2}}}
    action, run_id = campaign.begin_shard(cfg, state, 1, lambda *_: None)
    assert action == "run" and run_id.endswith("-a3")
    for d in (first, second):
        assert not (d / "work").exists() and (d / "manifest.json").exists()
    assert (first / "raw" / "favicon_records.jsonl").exists() and (other_shard / "work").exists()
    assert campaign.resume_source(cfg, 1, run_id) == first          # the newest attempt had no records, so the one before


def test_resume_source_ignores_other_configurations_and_finished_runs(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    _attempt(cfg, 0, 1, checksum="0" * 64)
    assert campaign.resume_source(cfg, 0, campaign._run_id(cfg, 0, 2)) is None
    done = _attempt(cfg, 0, 2, complete=True)
    assert campaign.resume_source(cfg, 0, campaign._run_id(cfg, 0, 3)) is None
    assert (done / "work").exists()                                 # a finished run keeps what it wrote


def test_the_campaign_passes_the_earlier_attempt_to_the_next_run(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    seen = {}

    def run_fn(c, *, run_id, resume_from=None, **_kw):
        seen[run_id] = resume_from
        d = Path(c.output_dir) / run_id
        (d / "raw").mkdir(parents=True, exist_ok=True)
        (d / "work").mkdir(exist_ok=True)
        (d / "raw" / "favicon_records.jsonl").write_text("{}\n")
        ok = run_id.endswith("-a2") or c.shard != 1
        (d / "manifest.json").write_text(json.dumps({"complete": ok, "zero_responsive": False, "stage_errors": {}, "abort_reason": None if ok else "stall",
                                                     "config_checksum": c.checksum, "shard": {"index": c.shard}}))
        (d / "report").mkdir(exist_ok=True)
        (d / "report" / "summary.json").write_text("{}")
        return d
    first = campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)
    assert first["stopped"]["shard"] == 1
    second = campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)
    assert second["complete"]
    a1, a2 = (Path(cfg.output_dir) / campaign._run_id(cfg, 1, n) for n in (1, 2))
    assert seen[a2.name] == a1 and seen[a1.name] is None
    assert not (a1 / "work").exists() and (a1 / "raw" / "favicon_records.jsonl").exists()


def test_the_overlapped_launcher_names_the_resume_source_and_its_own_pid(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    cmd = supervisor.child_command(cfg, tmp_path / "c.yaml", 1, "r-a2", None, tmp_path / "earlier")
    assert cmd[cmd.index("--resume-from") + 1] == str(tmp_path / "earlier")
    assert cmd[cmd.index("--supervisor-pid") + 1] == str(os.getpid())
    assert "--resume-from" not in supervisor.child_command(cfg, tmp_path / "c.yaml", 1, "r-a1")
