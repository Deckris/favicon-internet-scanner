"""The resource measurement script: samples a short-lived dummy process and a fake scan log."""
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "run" / "measure.sh"
pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or not Path("/proc/stat").exists(), reason="needs bash and Linux /proc"
)

DUMMY = """
import threading, time
def spin():
    end = time.time() + 3
    while time.time() < end:
        pass
threading.Thread(target=spin, name="busy").start()
time.sleep(3)
"""


def rows(path):
    lines = path.read_text().splitlines()
    return lines[0], lines[1:]


def test_script_parses_and_helps():
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0
    out = subprocess.run(["bash", str(SCRIPT), "--help"], capture_output=True, text=True)
    assert out.returncode == 0 and "--pyspy" in out.stdout


def test_requires_output_dir_and_process(tmp_path):
    assert subprocess.run(["bash", str(SCRIPT)], capture_output=True).returncode == 2
    assert subprocess.run(["bash", str(SCRIPT), "-o", str(tmp_path / "x")], capture_output=True).returncode == 2


def test_samples_dummy_process_until_it_exits(tmp_path):
    log = tmp_path / "scan.log"
    log.write_text("[scanner run1] discover: start\nnoise\n[scanner run1] discover: 1 s\n")
    out = tmp_path / "out"
    proc = subprocess.Popen([sys.executable, "-c", DUMMY])
    started = time.time()
    try:
        done = subprocess.run(
            ["bash", str(SCRIPT), "-o", str(out), "-p", str(proc.pid), "-i", "1", "-l", str(log)],
            capture_output=True, text=True, timeout=30,
        )
    finally:
        proc.kill()
        proc.wait()
    assert done.returncode == 0, done.stderr
    assert time.time() - started < 20

    head, body = rows(out / "cpu.csv")
    assert head.startswith("time,cpu,user_pct") and any(r.split(",")[1] == "cpu0" for r in body)
    head, body = rows(out / "procs.csv")
    assert head.startswith("time,pid,comm") and any(r.split(",")[1] == str(proc.pid) for r in body)
    head, body = rows(out / "threads.csv")
    assert head.startswith("time,pid,tid") and body
    head, body = rows(out / "mem.csv")
    assert head.startswith("time,mem_available_kb") and body and body[0].split(",")[3] == str(proc.pid)
    assert body[0].split(",")[4]
    head, body = rows(out / "net.csv")
    assert head.startswith("time,iface")
    head, body = rows(out / "disk.csv")
    assert head.startswith("time,free_kb") and body and body[0].split(",")[1]
    head, body = rows(out / "stages.csv")
    assert head == "time,label,stage" and len(body) == 1 and body[0].endswith(",run1,discover")


def test_stop_file_ends_sampling(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "stop").write_text("")
    proc = subprocess.Popen(["sleep", "30"])
    try:
        done = subprocess.run(
            ["bash", str(SCRIPT), "-o", str(out), "-p", str(proc.pid), "-i", "1"], capture_output=True, timeout=20
        )
    finally:
        proc.kill()
        proc.wait()
    assert done.returncode == 0
