"""Overlapped campaigns (--pipeline 2): phase locks, child processes, stop handling, and identical outputs."""
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.internet import campaign, pipeline, supervisor
from scanner.internet.config import load_config
from tests.helpers import FakeFetcher
from tests.test_pipeline import tools
from tests.test_scale import _cfg

posix = pytest.mark.skipif(not supervisor.available(), reason="needs POSIX file locks")
ROOT = Path(__file__).resolve().parent.parent

CHILD = r'''
import json, os, signal, sys, time
from pathlib import Path
from scanner.internet.supervisor import PhaseGate

cdir, run_id, shard, out, checksum, log, a_sleep, b_sleep = sys.argv[1:9]
shard, a_sleep, b_sleep = int(shard), float(a_sleep), float(b_sleep)


def ev(kind):
    with open(log, "a") as fh:
        fh.write(f"{kind} {shard} {time.monotonic():.4f}\n")


def finish(complete, abort=None):
    (run_dir / "manifest.json").write_text(json.dumps({
        "complete": complete, "abort_reason": abort, "zero_responsive": False, "stage_errors": {}, "elapsed_seconds": 1.0,
        "config_checksum": checksum, "shard": {"index": shard}}))
    (run_dir / "report" / "summary.json").write_text(json.dumps({"counts": {"l4_endpoints": 1}}))


def term(*_):
    raise KeyboardInterrupt


signal.signal(signal.SIGTERM, term)
run_dir = Path(out) / run_id
(run_dir / "report").mkdir(parents=True)
gate = PhaseGate(cdir, run_id)
ev("begin")
try:
    with gate("a"):
        ev("a-start")
        if os.environ.get("FAKE_DIE") == str(shard) and run_id.endswith("-a1"):
            os.kill(os.getpid(), signal.SIGKILL)
        time.sleep(a_sleep)
        ev("a-end")
    with gate("b"):
        ev("b-start")
        if os.environ.get("FAKE_B_FAIL") == str(shard):         # fail once the other shard is sweeping
            for _ in range(400):
                if "a-start 1" in Path(log).read_text():
                    break
                time.sleep(0.05)
            finish(False, os.environ.get("FAKE_B_REASON", "stall"))
            ev("end")
            sys.exit(0)
        time.sleep(b_sleep)
        ev("b-end")
    finish(True)
except KeyboardInterrupt:
    finish(False, "interrupt")
ev("end")
'''


@pytest.fixture
def fake(tmp_path, monkeypatch):
    """A launcher whose children are small scripts that take the real phase locks and sleep."""
    script = tmp_path / "fake_child.py"
    script.write_text(CHILD, encoding="utf-8")
    log = tmp_path / "events.log"
    monkeypatch.setenv("PYTHONPATH", str(ROOT))

    def make(cfg, a=1.2, b=2.5):
        def launcher(i, run_id):
            return [sys.executable, str(script), str(campaign.campaign_dir(cfg)), run_id, str(i), str(cfg.output_dir),
                    cfg.checksum, str(log), str(a), str(b)]
        return launcher

    def events():
        out = []
        for line in log.read_text().splitlines() if log.exists() else []:
            kind, shard, t = line.split()
            out.append((kind, int(shard), float(t)))
        return out
    return SimpleNamespace(launcher=make, events=events)


def _intervals(events, phase):
    starts = {s: t for k, s, t in events if k == f"{phase}-start"}
    ends = {s: t for k, s, t in events if k == f"{phase}-end"}
    return {s: (starts[s], ends[s]) for s in starts if s in ends}


def _go(cfg, fake, **kw):
    return supervisor.run_overlapped(cfg, log=lambda *_: None, launcher=fake.launcher(cfg, **kw.pop("times", {})), poll=0.05, **kw)


def _after(fake, kind, shard, action):
    """Run ``action`` once the fake child of ``shard`` has logged ``kind`` (child start-up takes a while)."""
    def wait():
        for _ in range(600):
            if any(e[0] == kind and e[1] == shard for e in fake.events()):
                action()
                return
            time.sleep(0.05)
    t = threading.Thread(target=wait, daemon=True)
    t.start()
    return t


def _lock_is_free(cfg, name):
    import fcntl
    fd = os.open(campaign.campaign_dir(cfg) / name, os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False
    finally:
        os.close(fd)


@posix
def test_phase_a_is_exclusive_two_in_flight_and_phase_b_overlaps_the_next_phase_a(tmp_path, fake):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 5}))
    result = _go(cfg, fake)
    assert result["complete"] and result["shards_complete"] == 5
    ev = fake.events()
    a, b = _intervals(ev, "a"), _intervals(ev, "b")
    order = sorted(a, key=lambda s: a[s][0])
    assert order == [0, 1, 2, 3, 4]                                            # shards start in order
    for x, y in zip(order, order[1:]):
        assert a[x][1] <= a[y][0]                                              # never two sweeps at once
        assert b[x][1] <= b[y][0] if y in b else True                          # nor two favicon stages

    assert any(b[s][0] < a[s + 1][1] and a[s + 1][0] < b[s][1] for s in range(4))         # the overlap actually happens
    live = peak = 0
    for kind, _s, _t in sorted(ev, key=lambda e: e[2]):
        live += {"begin": 1, "end": -1}.get(kind, 0)
        peak = max(peak, live)
    assert peak == 2
    state = json.loads(Path(result["state_file"]).read_text())
    assert state["pipeline"] == 2 and all(e["status"] == "complete" for e in state["shard_states"].values())
    assert json.loads((Path(result["summary_file"])).read_text())["merged"]["shards_merged"] == 5


@posix
def test_a_killed_child_frees_its_locks_and_the_shard_is_repeated_as_a_new_attempt(tmp_path, fake, monkeypatch):
    cfg = load_config(_cfg(tmp_path))
    monkeypatch.setenv("FAKE_DIE", "1")
    first = _go(cfg, fake)
    assert not first["complete"] and first["stopped"]["shard"] == 1 and first["stopped"]["reason"] == "crashed"
    assert "signal 9" in first["stopped"]["detail"]
    assert {e[1] for e in fake.events() if e[0] == "begin"} == {0, 1}          # shard 2 was never started
    assert _lock_is_free(cfg, "phase-a.lock") and _lock_is_free(cfg, "phase-b.lock")
    second = _go(cfg, fake)
    assert second["complete"]
    state = json.loads(Path(second["state_file"]).read_text())
    assert state["shard_states"]["0"]["attempts"] == 1 and state["shard_states"]["1"]["attempts"] == 2
    assert state["shard_states"]["1"]["run_id"].endswith("s001of003-a2")


@posix
def test_sigterm_to_the_supervisor_reaches_the_children_and_no_shard_starts_afterwards(tmp_path, fake):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 4}))
    _after(fake, "a-start", 1, lambda: os.kill(os.getpid(), signal.SIGTERM))
    result = _go(cfg, fake)
    assert not result["complete"] and result["stopped"]["reason"] == "interrupt"
    began = {e[1] for e in fake.events() if e[0] == "begin"}
    assert began == {0, 1} and not any(e[0] == "b-end" for e in fake.events())
    state = json.loads(Path(result["state_file"]).read_text())
    assert state["shard_states"]["0"]["status"] == "incomplete" and state["shard_states"]["0"]["abort_reason"] == "interrupt"
    assert _lock_is_free(cfg, "phase-a.lock") and _lock_is_free(cfg, "phase-b.lock")


@posix
def test_kill_switch_stops_the_running_children(tmp_path, fake):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 4}))
    _after(fake, "a-start", 1, lambda: Path(cfg.kill_switch_file).write_text("x"))
    result = _go(cfg, fake)
    assert not result["complete"] and result["stopped"]["reason"] == "interrupt"
    assert {e[1] for e in fake.events() if e[0] == "begin"} == {0, 1}


@posix
def test_drain_lets_the_shard_in_progress_finish_and_starts_no_other(tmp_path, fake):
    cfg = load_config(_cfg(tmp_path))
    drain = campaign.campaign_dir(cfg) / "DRAIN"
    _after(fake, "a-start", 0, lambda: drain.write_text(""))
    result = _go(cfg, fake)
    assert result["stopped"]["reason"] == "drain" and result["shards_complete"] == 1
    assert {e[1] for e in fake.events() if e[0] == "begin"} == {0}


@posix
def test_a_failing_child_stops_new_shards_but_lets_the_other_one_finish(tmp_path, fake, monkeypatch):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 4}))
    monkeypatch.setenv("FAKE_DIE", "1")
    result = _go(cfg, fake)
    state = json.loads(Path(result["state_file"]).read_text())
    assert state["shard_states"]["0"]["status"] == "complete" and state["shard_states"]["1"]["status"] == "crashed"
    assert result["shards_complete"] == 1 and {e[1] for e in fake.events() if e[0] == "begin"} == {0, 1}


@posix
@pytest.mark.parametrize("reason,sibling_finishes", [("stall", False), ("stage_errors", True)])
def test_a_stop_in_one_shard_ends_a_sweep_in_the_other_but_a_plain_failure_does_not(tmp_path, fake, monkeypatch, reason, sibling_finishes):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 4}))
    monkeypatch.setenv("FAKE_B_FAIL", "0")
    monkeypatch.setenv("FAKE_B_REASON", reason)
    result = _go(cfg, fake, times={"a": 4.0, "b": 0.2})
    ev = fake.events()
    assert {e[1] for e in ev if e[0] == "begin"} == {0, 1}
    assert any(e[0] == "a-end" and e[1] == 1 for e in ev) == sibling_finishes
    state = json.loads(Path(result["state_file"]).read_text())
    assert state["shard_states"]["1"]["status"] == ("complete" if sibling_finishes else "incomplete")


def test_off_host_icon_fetching_is_refused_before_anything_starts(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    bad = replace(cfg, favicon=SimpleNamespace(**{**vars(cfg.favicon), "offhost": SimpleNamespace(enabled=True)}))
    with pytest.raises(ValueError, match="offhost_icons"):
        campaign.run_campaign(bad, pipeline_depth=2, config_path=tmp_path / "scale.yaml", log=lambda *_: None)
    assert not (campaign.campaign_dir(bad) / "campaign.lock").exists()
    assert not (campaign.campaign_dir(bad) / "phases").exists()


def test_without_posix_locks_the_campaign_falls_back_to_one_shard_at_a_time(tmp_path, monkeypatch):
    cfg = load_config(_cfg(tmp_path))
    monkeypatch.setattr(supervisor, "available", lambda: False)
    seen = []

    def run_fn(c, *, run_id, **_kw):
        seen.append(c.shard)
        d = Path(c.output_dir) / run_id
        (d / "report").mkdir(parents=True)
        (d / "manifest.json").write_text(json.dumps({"complete": True, "zero_responsive": False, "stage_errors": {}}))
        (d / "report" / "summary.json").write_text("{}")
        return d
    messages = []
    result = campaign.run_campaign(cfg, run_fn=run_fn, log=messages.append, pipeline_depth=2)
    assert result["complete"] and seen == [0, 1, 2] and any("one after another" in m for m in messages)


# ------------------------------------------------------------------ the real pipeline in child processes

def child_kwargs():
    return {"executor": tools(), "fetcher": FakeFetcher(), "skip_preflight": True, "offline_preflight": True}


COMPARED = ("normalized/endpoints.jsonl", "normalized/hostname_resolution.jsonl", "normalized/hostname_resolution.csv",
            "normalized/policy_refusals.jsonl", "ip_results.csv", "scanned_ips.txt", "favicons/index.jsonl")


@posix
def test_overlapped_campaign_writes_the_same_outputs_as_one_shard_after_another(tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", str(ROOT))
    monkeypatch.chdir(ROOT)
    outputs = {}
    for depth in (1, 2):
        work = tmp_path / f"d{depth}"
        work.mkdir()
        path = _cfg(work, sample={"fraction": 0.0001, "seed": 4, "shards": 4})
        cfg = load_config(path)
        if depth == 1:
            def run_fn(c, *, run_id, **_kw):
                return pipeline.run(c, run_id=run_id, **child_kwargs())
            result = campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)
        else:
            result = supervisor.run_overlapped(cfg, log=lambda *_: None, config_path=path, kwargs_factory="tests.test_supervisor:child_kwargs",
                                               poll=0.05)
        assert result["complete"], result
        state = json.loads(Path(result["state_file"]).read_text())
        outputs[depth] = {int(i): Path(e["run_dir"]) for i, e in state["shard_states"].items()}
        if depth == 2:
            manifest = json.loads((outputs[2][0] / "manifest.json").read_text())
            assert manifest["parameters"]["pipeline"] == 2 and state["pipeline"] == 2
        else:
            assert "pipeline" not in json.loads((outputs[1][0] / "manifest.json").read_text())["parameters"]
    for shard in range(4):
        for rel in COMPARED:
            assert (outputs[1][shard] / rel).exists() == (outputs[2][shard] / rel).exists(), (shard, rel)
            if (outputs[1][shard] / rel).exists():
                assert (outputs[1][shard] / rel).read_bytes() == (outputs[2][shard] / rel).read_bytes(), (shard, rel)
        one = json.loads((outputs[1][shard] / "report" / "summary.json").read_text())
        two = json.loads((outputs[2][shard] / "report" / "summary.json").read_text())
        assert one["counts"] == two["counts"]


# ------------------------------------------------------------------ disjoint slices

@pytest.mark.skipif(shutil.which("zmap") is None and not Path("/usr/sbin/zmap").exists(), reason="zmap is not installed")
def test_zmap_dry_run_slices_are_disjoint_and_cover_the_allowlist(tmp_path):
    zmap = shutil.which("zmap") or "/usr/sbin/zmap"
    allow = tmp_path / "allow.txt"
    allow.write_text("10.0.0.0/20\n", encoding="utf-8")
    block = tmp_path / "block.txt"
    block.write_text("", encoding="utf-8")
    slices = []
    for shard in range(4):
        cmd = [zmap, "-C", "/dev/null", "-T", "1", "-p", "80", "-w", str(allow), "-b", str(block), "-i", "lo", "-S", "10.0.0.1",
               "-G", "00:00:00:00:00:00", "-r", "100000", "--cooldown-time", "1", "--max-runtime", "60", "-P", "1", "--seed", "7",
               "--dryrun", "--shards", "4", "--shard", str(shard), "-O", "csv", "-f", "saddr", "-o", str(tmp_path / f"o{shard}.csv")]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        text = proc.stdout + proc.stderr
        if proc.returncode != 0 and "daddr" not in text:
            pytest.skip(f"zmap --dryrun is not usable here: {text[-200:]}")
        import re
        slices.append(re.findall(r"daddr: (\d+\.\d+\.\d+\.\d+)", text))
    sets = [set(s) for s in slices]
    assert all(len(s) == len(sl) for s, sl in zip(sets, slices))             # no address twice within a slice
    for i in range(4):
        for j in range(i + 1, 4):
            assert not sets[i] & sets[j]
    assert set().union(*sets) == {f"10.0.{a}.{b}" for a in range(16) for b in range(256)}
