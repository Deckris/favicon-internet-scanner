"""Tool stdout goes straight to the raw file; nothing proportional to its size is held in memory."""
import hashlib
import json
import sys
import tracemalloc
from pathlib import Path

import pytest

from scanner.internet import outputs
from scanner.internet.config import load_config
from scanner.internet.runner import ManagedExecutor, capture_stdout, iter_lines
from scanner.zdns_runner import run_zdns
from tests.helpers import write_config

PY = sys.executable

BIG = (
    "import sys\n"
    "line = '{\"ip\": \"10.0.0.1\", \"pad\": \"' + 'x' * 1000 + '\"}\\n'\n"
    "for _ in range(100_000):\n"
    "    sys.stdout.write(line)\n"
)

ODD = (
    "import sys\n"
    "sys.stdout.buffer.write(b'{\"a\": 1}\\r\\n\\xff\\xfe broken\\n\\n{\"b\": \"\\xc3\\xa9\"}\\rlast')\n"
    "sys.stderr.write('warn\\n')\n"
)

ZDNS = (
    "import json, sys\n"
    "for n in sys.stdin.read().split():\n"
    "    print(json.dumps({'name': n, 'results': {'A': {'status': 'NOERROR', 'data': {'resolver': '9.9.9.9:53',"
    " 'answers': [{'type': 'A', 'name': n, 'answer': '10.0.0.1'}]}}}}))\n"
    "print('not json')\n"
)


@pytest.fixture
def cfg(tmp_path):
    return load_config(write_config(tmp_path))


def _executor(cfg, tmp_path, streaming=True):
    (tmp_path / "raw").mkdir(exist_ok=True)
    ex = ManagedExecutor(cfg, tmp_path, lambda: False)
    ex.streams_stdout = streaming
    return ex


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def test_large_output_is_not_held_in_memory(cfg, tmp_path):
    ex = _executor(cfg, tmp_path)
    out = tmp_path / "big.jsonl"
    tracemalloc.start()
    try:
        proc, digest = capture_stdout(ex, [PY, "-c", BIG], out, capture_output=True, text=True, check=False)
        count = sum(1 for line in iter_lines(out) if line.strip())
        _cur, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert proc.returncode == 0 and proc.stdout == ""
    assert out.stat().st_size > 100_000_000
    assert count == 100_000
    assert digest == _sha(out)
    assert peak < 16_000_000


def test_streamed_file_matches_text_path_byte_for_byte(cfg, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    streamed, text = a / "o.jsonl", b / "o.jsonl"
    p1, d1 = capture_stdout(_executor(cfg, a, True), [PY, "-c", ODD], streamed, capture_output=True, text=True, check=False)
    p2, d2 = capture_stdout(_executor(cfg, b, False), [PY, "-c", ODD], text, capture_output=True, text=True, check=False)
    assert streamed.read_bytes() == text.read_bytes()
    assert d1 == d2 == hashlib.sha256(text.read_bytes()).hexdigest()
    assert (p1.returncode, p1.stderr) == (p2.returncode, p2.stderr) and "warn" in p1.stderr
    assert list(iter_lines(streamed)) == text.read_text(encoding="utf-8").split("\n")


def test_nonzero_exit_and_stderr_file_are_kept(cfg, tmp_path):
    ex = _executor(cfg, tmp_path)
    out = tmp_path / "o.txt"
    proc, digest = capture_stdout(
        ex, [PY, "-c", "import sys; print('x'); sys.stderr.write('boom'); sys.exit(3)"], out)
    assert proc.returncode == 3 and "boom" in proc.stderr
    assert out.read_text() == "x\n" and digest == _sha(out)
    saved = list((tmp_path / "raw" / "stderr").glob("*.txt"))
    assert saved and "exit=3" in saved[0].read_text() and "boom" in saved[0].read_text()


def test_stopped_before_start_still_writes_an_empty_raw_file(cfg, tmp_path):
    (tmp_path / "raw").mkdir()
    ex = ManagedExecutor(cfg, tmp_path, lambda: True)
    out = tmp_path / "o.txt"
    proc, digest = capture_stdout(ex, [PY, "-c", "print(1)"], out)
    assert proc.returncode == -15 and out.read_bytes() == b""
    assert digest == hashlib.sha256(b"").hexdigest()


def test_timeout_kills_tool_and_keeps_partial_output(cfg, tmp_path):
    ex = _executor(cfg, tmp_path)
    out = tmp_path / "o.txt"
    code = "import sys, time; print('early', flush=True); time.sleep(60)"
    proc, digest = capture_stdout(ex, [PY, "-c", code], out, timeout=1.5)
    assert proc.returncode != 0 and "hard timeout" in proc.stderr
    assert out.read_text().startswith("early") and digest == _sha(out)


def test_run_zdns_identical_with_streaming_and_text_executors(cfg, tmp_path):
    script = tmp_path / "fake_zdns.py"
    script.write_text(ZDNS, encoding="utf-8")

    def shim(streaming, root):
        ex = _executor(cfg, root, streaming)

        class Shim:
            streams_stdout = streaming

            def __call__(self, command, **kw):
                return ex([PY, str(script)], **kw)
        return Shim()

    names = [f"h{i}.test" for i in range(50)]
    runs = {}
    for streaming in (True, False):
        root = tmp_path / ("s" if streaming else "t")
        root.mkdir()
        jobs, answers = run_zdns("A", names, nameservers=["9.9.9.9"], run_dir=root, executor=shim(streaming, root))
        runs[streaming] = (jobs, answers, outputs.read_text(root / jobs[0].raw_path).encode())
    (j1, a1, raw1), (j2, a2, raw2) = runs[True], runs[False]
    assert raw1 == raw2 and a1 == a2
    for root, job in ((tmp_path / "s", j1[0]), (tmp_path / "t", j2[0])):
        assert job.raw_sha256 == _sha(root / job.raw_path)
    assert j1[0].output_count == j2[0].output_count == 50
    assert json.loads(raw1.split(b"\n")[0])["name"] == "h0.test"


def test_killed_tool_is_reaped_and_has_an_exit_status(cfg, tmp_path):
    ex = _executor(cfg, tmp_path)
    out = tmp_path / "o.txt"
    proc, _digest = capture_stdout(ex, [PY, "-c", "import time; time.sleep(60)"], out, timeout=1.0)
    assert proc.returncode is not None and proc.returncode != 0


@pytest.mark.skipif(sys.platform == "win32", reason="needs a process group and a child that keeps the pipe open")
def test_output_tail_is_written_and_hashed_while_a_stray_child_holds_the_pipe(cfg, tmp_path):
    ex = _executor(cfg, tmp_path)
    out = tmp_path / "o.txt"
    code = ("import subprocess, sys\n"
            "sys.stdout.write('tail without newline'); sys.stdout.flush()\n"
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], start_new_session=True)\n")
    proc, digest = capture_stdout(ex, [PY, "-c", code], out, timeout=1.5)
    assert out.read_text() == "tail without newline"
    assert digest == _sha(out) and "still held open" in proc.stderr


@pytest.mark.skipif(not Path("/dev/full").exists(), reason="needs a device that refuses writes")
def test_write_error_keeps_draining_and_is_reported(cfg, tmp_path):
    ex = _executor(cfg, tmp_path)
    code = "import sys\nfor _ in range(200):\n    sys.stdout.write('x' * 10000 + chr(10))\n"
    proc, digest = capture_stdout(ex, [PY, "-c", code], Path("/dev/full"), timeout=30)
    assert "could not write" in proc.stderr and proc.returncode != 0
    assert digest == hashlib.sha256(b"").hexdigest()


def test_unopenable_output_file_is_reported_not_hung(cfg, tmp_path):
    ex = _executor(cfg, tmp_path)
    code = "import sys\nfor _ in range(200):\n    sys.stdout.write('x' * 10000 + chr(10))\n"
    proc, digest = capture_stdout(ex, [PY, "-c", code], tmp_path / "missing" / "o.txt", timeout=30)
    assert "could not write" in proc.stderr and proc.returncode != 0
    assert digest == hashlib.sha256(b"").hexdigest()
