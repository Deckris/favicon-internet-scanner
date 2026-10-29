"""Overlapped campaigns: shard N+1 runs its network stages while shard N works through its favicon stage.

``campaign --pipeline 2`` turns the campaign process into a supervisor that runs every shard in a child process
(``python -m scanner.internet.supervisor --child``). Two advisory file locks in the campaign directory keep the
load per target what it is when shards run one after another:

* ``phase-a.lock`` is held from the start of a shard to the end of its network stages (sample list, ZMap, TLS, HTTP,
  PTR, candidates, DNS, SNI confirmation), so at most one ZMap sweep is on the wire and the approved packet rate holds.
* ``phase-b.lock`` is held from the start of the favicon stage to the end of the write-out, so at most one favicon
  stage runs at a time.

The kernel drops a lock when its process ends, however it ends. Shards are disjoint slices of one seeded ZMap
permutation, so two shards never contact the same address and the per-address spacing is unaffected by overlap.
At most two shards are in flight; the next one starts as soon as the previous one has left phase A.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Iterator

from scanner.internet import campaign, runner
from scanner.internet.config import load_config
from scanner.internet.preflight import PreflightFailed

try:
    import fcntl
except ImportError:             # Windows: campaigns run the shards one after another
    fcntl = None                # type: ignore[assignment]

DEPTH = 2
LOCKS = {"a": "phase-a.lock", "b": "phase-b.lock"}
PHASE_B_NICE = 5               # keeps ZMap's receiver ahead of the Python favicon workers when both are busy
LETS_SIBLING_FINISH = ("crashed", "stage_errors", "zero_responsive", "drain")    # any other stop (kill switch, stall, ...) ends a sweep in progress
EXIT_REFUSED, EXIT_CRASHED, EXIT_MISMATCH, EXIT_INTERRUPTED = 2, 3, 4, 5


def available() -> bool:
    return fcntl is not None


def check_overlap_safe(cfg: Any) -> None:
    """Refuse configurations in which a shard's traffic could reach another shard's addresses."""
    if cfg.shards < 2 or cfg.target_ips:
        raise ValueError("--pipeline 2 needs a random sample split into 2 or more shards (sample.shards)")
    if cfg.favicon.offhost.enabled:
        raise ValueError("--pipeline 2 cannot be combined with favicon.offhost_icons: an off-host icon fetch can reach an address "
                         "in another shard's slice while that shard is scanning it. Disable off-host icons or use --pipeline 1")
    if cfg.measurement.zmap_seed is None:
        raise ValueError("--pipeline 2 needs a fixed sample seed so that the shards are disjoint slices of one permutation")


class PhaseGate:
    """``gate("a")`` / ``gate("b")``: context managers that hold the matching lock for the duration of the block."""

    depth = DEPTH

    def __init__(self, directory: Path, run_id: str) -> None:
        self.directory = Path(directory)
        self.run_id = run_id
        (self.directory / "phases").mkdir(parents=True, exist_ok=True)

    def marker(self, phase: str, event: str) -> Path:
        return self.directory / "phases" / f"{self.run_id}.{phase}-{event}"

    @contextlib.contextmanager
    def __call__(self, phase: str) -> Iterator[None]:
        fd = os.open(self.directory / LOCKS[phase], os.O_CREAT | os.O_RDWR, 0o644)
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(0.25)         # a short sleep, so that a signal is handled at once
            if phase == "a":
                runner.hold_fd(fd)       # the sweep tool inherits it: see ManagedExecutor
            self.marker(phase, "start").touch()
            if phase == "b":
                with contextlib.suppress(OSError, AttributeError):
                    os.nice(PHASE_B_NICE)
            try:
                yield
            finally:
                if phase == "a":
                    runner.drop_fd(fd)
                os.close(fd)
                fd = -1
                self.marker(phase, "done").touch()
        finally:
            if fd >= 0:
                os.close(fd)


# ------------------------------------------------------------------ child process

def _import_factory(spec: str) -> Callable[[], dict[str, Any]]:
    import importlib
    module, _, name = spec.partition(":")
    return getattr(importlib.import_module(module), name)


def _die_with_parent(expected_ppid: int | None = None) -> bool:
    """A shard must not outlive its supervisor: the next supervisor would repeat it while this one still runs.

    False means the supervisor is already gone (the signal only covers a parent that dies after this call).
    """
    if not sys.platform.startswith("linux"):
        return True
    with contextlib.suppress(Exception):
        import ctypes
        ctypes.CDLL(None).prctl(1, int(signal.SIGTERM), 0, 0, 0)      # PR_SET_PDEATHSIG
    return expected_ppid is None or os.getppid() == expected_ppid


def _spawn_child() -> None:
    """Runs in the forked child before exec, so the death signal is armed before any of our modules is imported."""
    with contextlib.suppress(Exception):
        import ctypes
        ctypes.CDLL(None).prctl(1, int(signal.SIGTERM), 0, 0, 0)


def child_main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scanner.internet.supervisor")
    ap.add_argument("--child", action="store_true", required=True)
    ap.add_argument("--config", type=Path, required=True)
    ap.add_argument("--shard", type=int, required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--checksum", required=True)
    ap.add_argument("--campaign-dir", type=Path, required=True)
    ap.add_argument("--kwargs-factory", help="module:function returning extra keyword arguments for pipeline.run")
    ap.add_argument("--supervisor-pid", type=int, help="pid of the supervisor that started this process")
    ap.add_argument("--resume-from", type=Path, help="run directory of an earlier attempt whose favicon lookup records to reuse")
    args = ap.parse_args(argv)
    if not _die_with_parent(args.supervisor_pid):
        print("the supervisor is gone; not starting", file=sys.stderr)
        return EXIT_INTERRUPTED
    from scanner.internet import pipeline
    gate = PhaseGate(args.campaign_dir, args.run_id)
    error_file = args.campaign_dir / "phases" / f"{args.run_id}.error"

    def fail(code: int, text: str) -> int:
        error_file.write_text(text[:2000], encoding="utf-8")
        print(text, file=sys.stderr)
        return code
    try:
        cfg = load_config(args.config)
        if cfg.checksum != args.checksum:
            return fail(EXIT_MISMATCH, "the configuration changed since the campaign started (checksum differs)")
        kwargs = _import_factory(args.kwargs_factory)() if args.kwargs_factory else {}
        run_dir = pipeline.run(replace(cfg, shard=args.shard), run_id=args.run_id, phase_gate=gate,
                               resume_from=args.resume_from, **kwargs)
    except PreflightFailed as exc:
        return fail(EXIT_REFUSED, str(exc))
    except KeyboardInterrupt as exc:
        return fail(EXIT_INTERRUPTED, f"interrupted before the run started: {exc}")
    except Exception as exc:
        return fail(EXIT_CRASHED, f"{type(exc).__name__}: {exc}")
    print(f"done: {run_dir}", flush=True)
    return 0


# ------------------------------------------------------------------ supervisor

class _Child:
    def __init__(self, shard: int, run_id: str, proc: subprocess.Popen) -> None:
        self.shard, self.run_id, self.proc = shard, run_id, proc


def child_command(cfg: Any, config_path: Path, shard: int, run_id: str, kwargs_factory: str | None = None,
                  resume_from: Path | None = None) -> list[str]:
    cmd = [sys.executable, "-m", "scanner.internet.supervisor", "--child", "--config", str(config_path), "--shard", str(shard),
           "--run-id", run_id, "--checksum", cfg.checksum, "--campaign-dir", str(campaign.campaign_dir(cfg)),
           "--supervisor-pid", str(os.getpid())]
    if resume_from is not None:
        cmd += ["--resume-from", str(resume_from)]
    if kwargs_factory:
        cmd += ["--kwargs-factory", kwargs_factory]
    return cmd


def _settle(cfg: Any, state: dict[str, Any], child: _Child, rc: int, run_dirs: dict[int, Path]) -> dict[str, Any] | None:
    """Record the outcome of a finished child in the state file; returns why the campaign must stop, if it must."""
    i = child.shard
    entry = state["shard_states"][str(i)]
    run_dir = Path(cfg.output_dir) / child.run_id
    err = campaign.campaign_dir(cfg) / "phases" / f"{child.run_id}.error"
    detail = err.read_text(encoding="utf-8") if err.exists() else ""
    if rc == 0:
        try:
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            if manifest.get("config_checksum") != cfg.checksum or (manifest.get("shard") or {}).get("index") != i:
                raise ValueError("manifest does not belong to this shard of this configuration")
        except (OSError, ValueError) as exc:
            return campaign.record_failure(entry, i, RuntimeError(f"shard process finished without a usable manifest ({exc})"))
        run_dirs[i] = run_dir
        return campaign.record_finished(entry, i, run_dir)
    if (run_dir / "manifest.json").exists():
        run_dirs[i] = run_dir
    if rc == EXIT_REFUSED:
        entry.update(status="refused", error=detail[:500])
        return {"shard": i, "reason": "preflight_failed", "detail": detail[:300]}
    if rc == EXIT_INTERRUPTED:
        entry.update(status="incomplete", abort_reason="interrupt", error=detail[:500])
        return {"shard": i, "reason": "interrupt", "detail": detail[:300]}
    how = f"killed by signal {-rc}" if rc < 0 else f"exited with code {rc}"
    return campaign.record_failure(entry, i, RuntimeError(detail or f"shard process {how}"))


def run_overlapped(cfg: Any, *, log: Callable[[str], None] = print, config_path: Path | None = None, kwargs_factory: str | None = None,
                   launcher: Callable[[int, str], list[str]] | None = None, poll: float = 0.2) -> dict[str, Any]:
    check_overlap_safe(cfg)
    if launcher is None:
        if config_path is None:
            raise ValueError("--pipeline 2 needs the configuration file path")
        launcher = lambda i, run_id: child_command(cfg, Path(config_path), i, run_id, kwargs_factory,    # noqa: E731
                                                   campaign.resume_source(cfg, i, run_id))
    state = campaign.load_state(cfg)
    state["pipeline"] = DEPTH
    cdir = campaign.campaign_dir(cfg)
    phases = cdir / "phases"
    phases.mkdir(parents=True, exist_ok=True)
    for old in phases.iterdir():                       # the campaign lock is ours: nothing from an earlier supervisor is live
        old.unlink(missing_ok=True)
    run_dirs: dict[int, Path] = {}
    failures: dict[int, dict[str, Any]] = {}
    inflight: dict[int, _Child] = {}
    halted: dict[str, Any] | None = None               # drain: no further shard starts
    terminating = False
    kill_sent = False

    def terminate_children() -> None:
        for c in inflight.values():
            with contextlib.suppress(OSError):
                if c.proc.poll() is None:
                    c.proc.send_signal(signal.SIGTERM)

    def on_signal(signum: int, _frame: Any) -> None:
        nonlocal terminating
        terminating = True
        terminate_children()

    previous: dict[int, Any] = {}
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGINT, getattr(signal, "SIGHUP", None)):
            if sig is not None:
                previous[sig] = signal.signal(sig, on_signal)
    spawn_kw: dict[str, Any] = {"preexec_fn": _spawn_child} if sys.platform.startswith("linux") else {}
    next_shard = 0
    try:
        while True:
            for i, c in list(inflight.items()):
                rc = c.proc.poll()
                if rc is None:
                    continue
                del inflight[i]
                stop = _settle(cfg, state, c, rc, run_dirs)
                if stop:
                    failures[i] = stop
                    log(f"[campaign] shard {i + 1}/{cfg.shards} stopped: {stop['reason']}")
                    if stop["reason"] not in LETS_SIBLING_FINISH:
                        for other in inflight.values():          # a sibling still sweeping must not go on sending
                            if not (phases / f"{other.run_id}.a-done").exists() and other.proc.poll() is None:
                                with contextlib.suppress(OSError):
                                    other.proc.send_signal(signal.SIGTERM)
                campaign._write_json(cdir / "campaign.json", state)
            switch = Path(cfg.kill_switch_file).exists()
            if switch and inflight and not kill_sent:
                kill_sent = True
                terminate_children()
            a_free = all((phases / f"{c.run_id}.a-done").exists() for c in inflight.values())
            while (not failures and halted is None and not terminating and next_shard < cfg.shards
                   and len(inflight) < DEPTH and a_free and not (switch and inflight)):
                i = next_shard
                action, run_id = campaign.begin_shard(cfg, state, i, log)
                next_shard += 1
                entry = state["shard_states"][str(i)]
                if action == "complete":
                    run_dirs[i] = Path(entry["run_dir"])
                    continue
                if action == "drain":
                    halted = {"shard": i, "reason": "drain", "detail": "stopped between shards on request"}
                    break
                inflight[i] = _Child(i, run_id, subprocess.Popen(launcher(i, run_id), **spawn_kw))
                a_free = False
            if not inflight and (failures or halted is not None or terminating or next_shard >= cfg.shards):
                break
            time.sleep(poll)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        for c in inflight.values():                    # only reached on an unexpected error: leave nothing running
            with contextlib.suppress(OSError):
                c.proc.kill()
                c.proc.wait()
    stopped = failures[min(failures)] if failures else halted
    if stopped is None and terminating:
        stopped = {"shard": None, "reason": "interrupt", "detail": "the campaign process was asked to stop"}
    return campaign.end_campaign(cfg, state, run_dirs, stopped)


if __name__ == "__main__":
    sys.exit(child_main())
