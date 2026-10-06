"""Managed execution of the external tools (zmap, zgrab2, zdns).

Replaces a bare ``subprocess.run`` so that:
* every tool runs in its own process group and is killed as a group on timeout,
  kill switch, Ctrl-C, SIGTERM or SIGHUP -- zmap can never be orphaned;
* the kill switch is polled while a tool runs, not only between stages;
* every tool has a hard timeout;
* binary names resolve to the configured paths (the reused runners hard-code
  ``zmap`` / ``zgrab2``);
* stderr (zmap's sent/drops/hit-rate lines, zdns progress) is kept on disk.
"""
from __future__ import annotations

import math
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable


def _die_with_parent() -> None:
    """Linux: ask the kernel to SIGKILL this child when the parent dies (PR_SET_PDEATHSIG)."""
    try:
        import ctypes
        ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0)
    except Exception:
        pass


class ManagedExecutor:
    def __init__(self, cfg: Any, run_dir: Path, killed: Callable[[], bool]) -> None:
        self.cfg = cfg
        self.run_dir = Path(run_dir)
        self.killed = killed
        self._seq = 0
        self._bins = {"zmap": cfg.binaries.zmap, "zgrab2": cfg.binaries.zgrab2, "zdns": cfg.binaries.zdns}
        (self.run_dir / "raw" / "stderr").mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ policy

    def timeout_for(self, tool: str, command: list[str], input_text: str | None) -> float:
        m = self.cfg.measurement
        if tool == "zmap":
            return m.zmap_max_runtime + m.zmap_cooldown + 120
        if tool == "zgrab2":
            lines = (input_text or "").count("\n") or 1
            return 1800 + math.ceil(lines / max(1, m.zgrab_senders)) * m.zgrab_target_timeout * 2
        return 3600 * 2   # zdns

    @staticmethod
    def _kill_group(proc: subprocess.Popen) -> None:
        try:
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGTERM)
            else:  # pragma: no cover - the instrument targets Linux
                proc.terminate()
        except (ProcessLookupError, PermissionError):
            return
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        try:       # the leader may be gone while a SIGTERM-ignoring child still holds the pipes: always follow up
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGKILL)
            else:  # pragma: no cover
                proc.kill()
        except (ProcessLookupError, PermissionError):
            pass

    # ------------------------------------------------------------------ call

    def __call__(self, command: list[str], *, input: str | None = None, capture_output: bool = True,   # noqa: A002
                 text: bool = True, check: bool = False, timeout: float | None = None) -> subprocess.CompletedProcess:
        tool = Path(command[0]).name
        argv = [self._bins.get(tool, command[0]), *command[1:]]
        if self.killed():
            # A stop condition (kill file, changed IP, expiry) may have tripped between two batches of one stage:
            # do not start another tool just to have it killed a second later.
            return subprocess.CompletedProcess(argv, -15, "", "scanner: stopped before start")
        limit = timeout or self.timeout_for(tool, command, input)
        self._seq += 1
        label = "-".join([tool, command[1] if len(command) > 1 and not command[1].startswith("-") else ""]).strip("-")
        # Input goes through a file, not a pipe: a pipe would block once the tool lags behind more than the
        # 64 KB pipe buffer, and CPython's communicate() cannot resume writing after a poll timeout.
        stdin_file = None
        if input is not None:
            stdin_file = tempfile.TemporaryFile("w+", encoding="utf-8", newline="")
            stdin_file.write(input)
            stdin_file.seek(0)
        popen_kw: dict[str, Any] = {"stdin": stdin_file if stdin_file is not None else subprocess.DEVNULL,
                                    "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "text": True,
                                    "errors": "replace"}
        if os.name == "posix":
            popen_kw["start_new_session"] = True
            popen_kw["preexec_fn"] = _die_with_parent       # if this process is SIGKILLed or WSL stops, the tool must not keep sending
        proc = subprocess.Popen(argv, **popen_kw)
        started = time.monotonic()
        reason = None
        out = err = ""
        try:
            while True:
                try:
                    out, err = proc.communicate(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if self.killed():
                    reason = "stopped by kill switch / interrupt flag"
                elif time.monotonic() - started > limit:
                    reason = f"killed after {limit:.0f}s hard timeout"
                if reason:
                    self._kill_group(proc)
                    try:
                        out, err = proc.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        out, err = "", ""
                    break
        except BaseException:
            self._kill_group(proc)       # Ctrl-C / SIGTERM-as-KeyboardInterrupt: never leave the tool running
            raise
        finally:
            if stdin_file is not None:
                stdin_file.close()
        code = proc.returncode
        if reason:
            err = f"{err}\nscanner: {reason}".strip()
        try:
            (self.run_dir / "raw" / "stderr" / f"{self._seq:04d}-{label}.txt").write_text(
                f"$ {' '.join(argv)}\nexit={code}\n{err}\n", encoding="utf-8")
        except OSError:
            pass
        return subprocess.CompletedProcess(argv, code, out, err)
