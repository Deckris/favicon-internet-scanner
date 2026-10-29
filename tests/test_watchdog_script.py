"""The long-campaign watchdog: memory and staleness triggers, run against a fake meminfo and fake tools."""
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "run" / "watchdog.sh"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def meminfo(path, available_mib, swap_mib):
    path.write_text(f"MemTotal:  4000000 kB\nMemAvailable:  {available_mib * 1024} kB\nSwapFree:  {swap_mib * 1024} kB\n")
    return path


def old_file(path, age_min=120):
    path.write_text("x")
    t = path.stat().st_mtime - age_min * 60
    os.utime(path, (t, t))
    return path


def run(tmp_path, *args, mem=None, pgrep_hits=False, env=None):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / "pgrep"
    fake.write_text(f"#!/bin/sh\nexit {0 if pgrep_hits else 1}\n")
    fake.chmod(0o755)
    e = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}", **(env or {}))
    if mem is not None:
        e["WATCHDOG_MEMINFO"] = str(mem)
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=e, timeout=30)


def test_script_parses():
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0


def test_kill_file_is_required():
    assert subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True).returncode == 2


def test_low_memory_touches_the_kill_file(tmp_path):
    kill = tmp_path / "STOP"
    mem = meminfo(tmp_path / "meminfo", 300, 200)
    out = run(tmp_path, "-k", str(kill), "-m", "700", "-i", "1", mem=mem)
    assert out.returncode == 0 and kill.exists()
    assert "below 700 MiB" in out.stdout


def test_swap_counts_towards_available_memory(tmp_path):
    kill = tmp_path / "STOP"
    mem = meminfo(tmp_path / "meminfo", 500, 400)       # 900 MiB together
    out = run(tmp_path, "-k", str(kill), "-m", "700", "-i", "1", "-p", "999999999", mem=mem)
    assert not kill.exists()
    assert "is gone" in out.stdout


def test_stale_paths_touch_the_kill_file(tmp_path):
    kill = tmp_path / "STOP"
    mem = meminfo(tmp_path / "meminfo", 3000, 0)
    old_file(tmp_path / "campaign.log")
    old_file(tmp_path / "favicon_records.jsonl")
    out = run(tmp_path, "-k", str(kill), "-w", str(tmp_path / "*.log"), "-w", str(tmp_path / "favicon_*.jsonl"),
              "-s", "30", "-i", "1", mem=mem)
    assert kill.exists() and "no zmap" in out.stdout


def test_one_fresh_path_is_enough(tmp_path):
    kill = tmp_path / "STOP"
    mem = meminfo(tmp_path / "meminfo", 3000, 0)
    old_file(tmp_path / "campaign.log")
    (tmp_path / "favicon_records.jsonl").write_text("x")
    out = run(tmp_path, "-k", str(kill), "-w", str(tmp_path / "campaign.log"), "-w", str(tmp_path / "favicon_records.jsonl"),
              "-s", "30", "-i", "1", "-p", "999999999", mem=mem)
    assert not kill.exists() and out.returncode == 0


def test_running_scan_tools_defer_the_stale_stop(tmp_path):
    kill = tmp_path / "STOP"
    mem = meminfo(tmp_path / "meminfo", 3000, 0)
    old_file(tmp_path / "campaign.log")
    run(tmp_path, "-k", str(kill), "-w", str(tmp_path / "campaign.log"), "-s", "30", "-i", "1", "-p", "999999999",
        mem=mem, pgrep_hits=True)
    assert not kill.exists()


def test_existing_kill_file_ends_the_watchdog(tmp_path):
    kill = tmp_path / "STOP"
    kill.write_text("")
    out = run(tmp_path, "-k", str(kill), "-i", "1", mem=meminfo(tmp_path / "meminfo", 100, 0))
    assert out.returncode == 0 and "already present" in out.stdout


def test_failed_touch_is_logged_and_retried_instead_of_exiting(tmp_path):
    kill, log = tmp_path / "nodir" / "STOP", tmp_path / "wd.log"
    mem = meminfo(tmp_path / "meminfo", 100, 0)
    e = dict(os.environ, WATCHDOG_MEMINFO=str(mem))
    p = subprocess.Popen(["bash", str(SCRIPT), "-k", str(kill), "-i", "1", "-l", str(log)], env=e,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(3.5)
        assert p.poll() is None                           # still running, not exited as if it had stopped the campaign
        (tmp_path / "nodir").mkdir()
        p.wait(timeout=10)
    finally:
        if p.poll() is None:
            p.kill()
    text = log.read_text()
    assert text.count("could not touch") >= 2 and kill.exists()


def test_missing_pgrep_never_allows_the_stale_stop(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("date", "awk", "stat", "sleep", "touch", "sed", "cat"):
        found = shutil.which(tool)
        if found:
            (bin_dir / tool).symlink_to(found)
    kill, log = tmp_path / "STOP", tmp_path / "wd.log"
    old_file(tmp_path / "campaign.log")
    mem = meminfo(tmp_path / "meminfo", 3000, 0)
    e = dict(os.environ, PATH=str(bin_dir), WATCHDOG_MEMINFO=str(mem))
    p = subprocess.Popen([shutil.which("bash"), str(SCRIPT), "-k", str(kill), "-w", str(tmp_path / "campaign.log"),
                          "-s", "30", "-i", "1", "-l", str(log)], env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(3.5)
        assert p.poll() is None and not kill.exists()
    finally:
        p.kill()
        p.wait()
    assert log.read_text().count("pgrep not found") == 1


def test_missing_memavailable_is_warned_about_once(tmp_path):
    mem = tmp_path / "meminfo"
    mem.write_text("MemTotal:  4000000 kB\n")
    log = tmp_path / "wd.log"
    p = subprocess.Popen(["bash", str(SCRIPT), "-k", str(tmp_path / "STOP"), "-i", "1", "-l", str(log)],
                         env=dict(os.environ, WATCHDOG_MEMINFO=str(mem)), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(3.5)
    finally:
        p.kill()
        p.wait()
    assert log.read_text().count("MemAvailable not found") == 1


def test_leading_zero_numbers_are_decimal_and_paths_may_contain_spaces(tmp_path):
    kill = tmp_path / "STOP"
    mem = meminfo(tmp_path / "meminfo", 3000, 0)
    spaced = tmp_path / "with space"
    spaced.mkdir()
    old_file(spaced / "campaign.log")
    out = run(tmp_path, "-k", str(kill), "-w", str(spaced / "*.log"), "-s", "030", "-i", "01", "-m", "0700", mem=mem)
    assert kill.exists() and "no zmap" in out.stdout


def test_log_file_and_environment_settings(tmp_path):
    kill, log = tmp_path / "STOP", tmp_path / "wd.log"
    mem = meminfo(tmp_path / "meminfo", 100, 0)
    run(tmp_path, mem=mem, env={"KILL_SWITCH": str(kill), "LOG_FILE": str(log), "INTERVAL": "1"})
    assert kill.exists() and "STOP:" in log.read_text()
