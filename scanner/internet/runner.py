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

import hashlib
import math
import os
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator

from scanner.internet import outputs


def _die_with_parent() -> None:
    """Linux: ask the kernel to SIGKILL this child when the parent dies (PR_SET_PDEATHSIG)."""
    try:
        import ctypes
        ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0)
    except Exception:
        pass


def _pump(src: Any, sink: list[str]) -> None:
    """Drain a text pipe into ``sink`` (stderr is small and kept in memory)."""
    try:
        sink.append(src.read())
    except (OSError, ValueError):
        pass


def _pump_to_file(src: Any, path: Path, sink: list[str], errors: list[str] | None = None,
                  stop: threading.Event | None = None, lock: threading.Lock | None = None) -> None:
    """Copy a text pipe to ``path`` as it arrives, hashing the bytes written; ``sink`` gets the sha256.

    Whatever the pipe has is written at once (no waiting for a full chunk), decoded and newline-translated exactly
    as a text-mode pipe would. After a write error the pipe is still drained so the tool cannot block, the error
    goes to ``errors``, and only bytes that reached the file are hashed. Once ``stop`` is set nothing more is written.
    A ``.zst`` path is compressed as it is written, and the digest is then over the compressed bytes.
    """
    import codecs
    import io
    digest = hashlib.sha256()
    lock = lock or threading.Lock()
    stop = stop or threading.Event()
    decoder = io.IncrementalNewlineDecoder(codecs.getincrementaldecoder(getattr(src, "encoding", None) or "utf-8")(errors="replace"), translate=True)
    fh = None
    failed = False
    comp = outputs.new_compressor() if outputs.is_compressed(path) else None

    def emit(text: str, last: bool = False) -> None:
        nonlocal failed
        if failed or not (text or last):
            return
        raw = text.encode("utf-8")
        if comp is not None:
            raw = comp.compress(raw) + (comp.flush() if last else b"")
        data = memoryview(raw)
        if not len(data):
            return
        with lock:
            if stop.is_set():
                return
            try:
                while len(data):
                    n = fh.write(data)
                    if not n:
                        raise OSError("short write")
                    digest.update(data[:n])
                    data = data[n:]
            except (OSError, ValueError) as exc:
                failed = True
                if errors is not None:
                    errors.append(f"{type(exc).__name__}: {exc}")

    try:
        fd = src.fileno()
        try:
            fh = open(path, "wb", buffering=0)
        except OSError as exc:
            failed = True
            if errors is not None:
                errors.append(f"{type(exc).__name__}: {exc}")
        while not stop.is_set():
            block = os.read(fd, 1 << 16)
            if stop.is_set():
                break
            emit(decoder.decode(block, final=not block), last=not block)
            if not block:
                break
    except (OSError, ValueError):
        pass
    finally:
        with lock:
            if fh is not None:
                try:
                    fh.close()
                except OSError as exc:
                    if errors is not None and not failed:
                        errors.append(f"{type(exc).__name__}: {exc}")
        try:
            src.close()
        except (OSError, ValueError):
            pass
        if not stop.is_set():
            sink.append(digest.hexdigest())


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                digest.update(block)
    except OSError:
        pass
    return digest.hexdigest()


def iter_lines(path: Path) -> Iterator[str]:
    """Lines of a raw output file (compressed or not), one at a time, split on newline only (like ``str.split``)."""
    return outputs.iter_lines(path)


def capture_stdout(executor: Any, command: list[str], out_path: Path, **kw: Any) -> tuple[Any, str]:
    """Run ``executor`` and leave its stdout in ``out_path``; return (result, sha256 of the file).

    A streaming executor writes the file itself, so the output is never held in memory. Any other callable
    returns the text, which is written here.
    """
    if getattr(executor, "streams_stdout", False):
        result = executor(command, stdout_path=out_path, **kw)
        digest = getattr(result, "stdout_sha256", None)
        if digest is not None:
            return result, digest
    else:
        result = executor(command, **kw)
    stdout = getattr(result, "stdout", "") or ""
    data = stdout.encode("utf-8")
    if outputs.is_compressed(out_path):
        data = outputs.compress_bytes(data)
    with open(out_path, "wb") as fh:
        fh.write(data)
    return result, hashlib.sha256(data).hexdigest()


_INHERITED_FDS: dict[int, int] = {}      # fd -> number of holders; handed to the tools named in INHERIT_FOR


def hold_fd(fd: int) -> None:
    """Mark ``fd`` (an advisory lock) as one the sweep tool must inherit, so the lock outlives this process while the tool runs."""
    _INHERITED_FDS[fd] = _INHERITED_FDS.get(fd, 0) + 1


def drop_fd(fd: int) -> None:
    if _INHERITED_FDS.get(fd, 0) <= 1:
        _INHERITED_FDS.pop(fd, None)
    else:
        _INHERITED_FDS[fd] -= 1


class ManagedExecutor:
    streams_stdout = True
    INHERIT_FOR = ("zmap",)     # PDEATHSIG is cleared when a file-capability binary is executed, so these keep the held locks

    def __init__(self, cfg: Any, run_dir: Path, killed: Callable[[], bool]) -> None:
        self.cfg = cfg
        self.run_dir = Path(run_dir)
        self.killed = killed
        self._seq = 0
        self._seq_lock = threading.Lock()      # stages may run tools from several threads at once
        self._active = 0                       # tools running right now (read by the run monitor)
        self._bins = {"zmap": cfg.binaries.zmap, "zgrab2": cfg.binaries.zgrab2, "zdns": cfg.binaries.zdns}
        (self.run_dir / "raw" / "stderr").mkdir(parents=True, exist_ok=True)

    @property
    def active_tools(self) -> int:
        return self._active

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
            proc.poll()
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
        try:       # reap the leader so its exit status is known
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    # ------------------------------------------------------------------ call

    def __call__(self, command: list[str], *, input: str | None = None, capture_output: bool = True,   # noqa: A002
                 text: bool = True, check: bool = False, timeout: float | None = None,
                 stdout_path: Path | None = None, pass_fds: tuple[int, ...] = ()) -> subprocess.CompletedProcess:
        tool = Path(command[0]).name
        argv = [self._bins.get(tool, command[0]), *command[1:]]
        if self.killed():
            # A stop condition (kill file, changed IP, expiry) may have tripped between two batches of one stage:
            # do not start another tool just to have it killed a second later.
            return subprocess.CompletedProcess(argv, -15, "", "scanner: stopped before start")
        limit = timeout or self.timeout_for(tool, command, input)
        with self._seq_lock:
            self._seq += 1
            seq = self._seq
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
            fds = tuple(pass_fds) + (tuple(sorted(_INHERITED_FDS)) if tool in self.INHERIT_FOR else ())
            if fds:
                popen_kw["pass_fds"] = fds       # a held lock stays held until the tool is gone, even if this process is killed outright
        proc = subprocess.Popen(argv, **popen_kw)
        started = time.monotonic()
        reason = None
        out_sink: list[str] = []
        err_sink: list[str] = []
        write_errors: list[str] = []
        pump_stop, pump_lock = threading.Event(), threading.Lock()
        counted = False
        t_out = t_err = None
        try:
            with self._seq_lock:
                self._active += 1
            counted = True
            # Both pipes are drained continuously by threads; with ``stdout_path`` the output goes straight to disk.
            if stdout_path is not None:
                t_out = threading.Thread(target=_pump_to_file, daemon=True,
                                         args=(proc.stdout, Path(stdout_path), out_sink, write_errors, pump_stop, pump_lock))
            else:
                t_out = threading.Thread(target=_pump, args=(proc.stdout, out_sink), daemon=True)
            t_err = threading.Thread(target=_pump, args=(proc.stderr, err_sink), daemon=True)
            t_out.start()
            t_err.start()
            while True:
                if proc.poll() is None:
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
                else:       # exited: wait for the pipes to close (a stray child holding them is bounded by the timeout below)
                    t_out.join(timeout=0.5)
                    t_err.join(timeout=0.5)
                    if not t_out.is_alive() and not t_err.is_alive():
                        break
                if self.killed():
                    reason = "stopped by kill switch / interrupt flag"
                elif time.monotonic() - started > limit:
                    reason = f"killed after {limit:.0f}s hard timeout"
                if reason:
                    self._kill_group(proc)
                    t_out.join(timeout=10)
                    t_err.join(timeout=10)
                    break
        except BaseException:
            self._kill_group(proc)       # Ctrl-C / SIGTERM-as-KeyboardInterrupt: never leave the tool running
            raise
        finally:
            if counted:
                with self._seq_lock:
                    self._active -= 1
            if stdin_file is not None:
                stdin_file.close()
            for t, pipe in ((t_out, proc.stdout), (t_err, proc.stderr)):
                if t is None or not t.is_alive():        # a pump still blocked in read owns its pipe and closes it when it ends
                    try:
                        pipe.close()
                    except (OSError, ValueError):
                        pass
        assert t_out is not None and t_err is not None
        stuck = stdout_path is not None and t_out.is_alive()
        if stuck:       # the pipe never closed (a stray child holds it): nothing may be appended to the file from here on
            pump_stop.set()
            with pump_lock:
                pass
        err = err_sink[0] if err_sink and not t_err.is_alive() else ""
        out = out_sink[0] if out_sink and not t_out.is_alive() and stdout_path is None else ""
        out_sha = out_sink[0] if out_sink and not t_out.is_alive() and stdout_path is not None else None
        code = proc.poll()
        if code is None:        # a group member kept the leader from being reaped in time
            code = -int(signal.SIGKILL)
        if reason:
            err = f"{err}\nscanner: {reason}".strip()
        if stuck:
            err = f"{err}\nscanner: stdout pipe still held open after the tool ended; output hashed as written to disk".strip()
        if write_errors:
            err = f"{err}\nscanner: could not write the raw output file: {write_errors[0]}".strip()
            if code == 0:
                code = 1
        try:
            (self.run_dir / "raw" / "stderr" / f"{seq:04d}-{label}.txt").write_text(
                f"$ {' '.join(argv)}\nexit={code}\n{err}\n", encoding="utf-8")
        except OSError:
            pass
        result = subprocess.CompletedProcess(argv, code, out, err)
        if stdout_path is not None:
            if out_sha is None:     # hash what reached the disk
                out_sha = _file_sha256(Path(stdout_path))
            result.stdout_sha256 = out_sha
        return result
