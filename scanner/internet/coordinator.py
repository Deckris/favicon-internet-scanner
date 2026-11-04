"""Decoupled campaigns: ZMap, network and favicon stages of different shards run side by side.

``campaign --decoupled`` turns the campaign process into a coordinator, the only writer of ``campaign.json``. It starts
worker processes (``python -m scanner.internet stage-worker``), one per stage of a shard:

* **zmap**: sample list and ZMap sweep of a shard (``pipeline.run(stop_after_zmap=True)``). Exactly one at a time,
  machine-wide. It never waits for downstream work; the next shard's sweep starts as soon as this one is done.
* **network**: TLS, HTTP, PTR, candidates, DNS and SNI from the shard's fact store (``pipeline.run(from_zmap=True)``).
  Up to ``network_workers`` at once, on any shard whose sweep is done. It never sends a ZMap probe.
* **favicon**: ``pipeline.run_favicon_only`` on a shard whose network stages are done. Up to ``favicon_workers`` at once.

Every shard keeps one run directory for all attempts of all its stages. The shard entry in ``campaign.json`` carries a
``stages`` record per stage (status, attempts, owner pid, heartbeat, error); the shard ``status`` is derived from it and
keeps the values of the other campaign modes (``pending``, ``running``, ``zmap_done``, ``network_done``, ``complete``).

``zmap.lock`` in the campaign directory is an advisory ``flock`` taken before each sweep starts. Its file descriptor is
handed to the worker, which hands it on to ZMap, so a sweep still on the wire keeps the lock when the coordinator or the
worker dies, and a restarted coordinator waits for it rather than sending a second sweep.

A worker that exits 0 has its stage verified in the manifest. Any other exit code fails the attempt; a stage is
attempted ``MAX_ATTEMPTS`` times. ``EXIT_RECYCLE`` asks for a fresh process without counting an attempt. A stage whose
worker is gone without a record of its end (the coordinator died, or was stopped) returns to pending with the same attempt
and continues in place from the units already committed to the shard's fact store.
"""
from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from scanner.internet import campaign
from scanner.internet import preflight as pre

try:
    import fcntl
except ImportError:             # Windows: no machine-wide lock; the coordinator itself still runs one sweep at a time
    fcntl = None                # type: ignore[assignment]

STAGES = ("zmap", "network", "favicon")
MAX_ATTEMPTS = 3
DEFAULT_NETWORK_WORKERS = 2
DEFAULT_FAVICON_WORKERS = 3
EXIT_REFUSED = 2                # stage-worker: configuration, approval or preflight refusal; never retried
EXIT_RECYCLE = 75               # stage-worker: "start me again in a fresh process" (e.g. memory ceiling); restarted without counting an attempt
LOCK_NAME = "zmap.lock"
HEARTBEAT_SECONDS = 30.0
EGRESS_UNKNOWN_LIMIT = 3        # consecutive failed egress lookups tolerated before a sweep start is given up on
STOP_GRACE_SECONDS = 120.0


def _now() -> str:
    return datetime.now(UTC).isoformat()


def available() -> bool:
    return fcntl is not None


def run_id_for(cfg: Any, i: int) -> str:
    """One run directory per shard, reused by every attempt of every stage."""
    return f"scanner-{cfg.run_label}-{cfg.checksum[:8]}-s{i:03d}of{cfg.shards:03d}"


def _fresh_stage() -> dict[str, Any]:
    return {"status": "pending", "attempts": 0, "owner_pid": None, "started_at": None, "heartbeat": None, "finished_at": None, "error": None}


def _done_stage() -> dict[str, Any]:
    return {**_fresh_stage(), "status": "done", "finished_at": _now()}


def derive_status(stages: dict[str, dict[str, Any]]) -> str:
    if stages["favicon"]["status"] == "done":
        return "complete"
    if stages["network"]["status"] == "done":
        return "network_done"
    if stages["zmap"]["status"] == "done":
        return "zmap_done"
    if any(s["status"] == "running" for s in stages.values()):
        return "running"
    return "pending"


def stage_done_in(stage: str, manifest: dict[str, Any]) -> bool:
    """Does the shard's manifest say that ``stage`` finished? Later stages imply the earlier ones."""
    if manifest.get("complete"):
        return True
    if stage == "favicon":
        return False
    if manifest.get("network_done"):
        return True
    return stage == "zmap" and bool(manifest.get("zmap_done"))


def _entry_for(cfg: Any, i: int, entry: dict[str, Any] | None) -> dict[str, Any]:
    """The decoupled form of shard ``i``'s entry; entries written by the other campaign modes are carried over."""
    if entry is not None and "stages" in entry:
        entry["stages"] = {**{s: _fresh_stage() for s in STAGES}, **entry["stages"]}
        return entry
    entry = entry or {"status": "pending", "attempts": 0}
    old_dir = Path(entry["run_dir"]) if entry.get("run_dir") else (Path(cfg.output_dir) / entry["run_id"] if entry.get("run_id") else None)
    stages = {s: _fresh_stage() for s in STAGES}
    prior = None
    if entry.get("status") not in ("complete", "network_done") and entry.get("attempts", 0) == 0:
        prior = campaign._prior_complete(cfg, i)             # a finished run the state file does not know about is not probed again
    if entry.get("status") == "complete" or prior is not None:
        stages = {s: _done_stage() for s in STAGES}
        old_dir = old_dir if entry.get("status") == "complete" and old_dir is not None else prior
    elif entry.get("status") == "network_done" and old_dir is not None and campaign._network_done(old_dir):
        stages["zmap"], stages["network"] = _done_stage(), _done_stage()
    if all(s["status"] == "pending" for s in stages.values()):
        return {"status": "pending", "run_id": run_id_for(cfg, i), "run_dir": str(Path(cfg.output_dir) / run_id_for(cfg, i)), "stages": stages}
    out = {k: v for k, v in entry.items() if k not in ("stages", "attempts")}
    out.update(run_id=old_dir.name, run_dir=str(old_dir), stages=stages)
    return out


def stage_command(cfg: Any, config_path: Path, stage: str, shard: int, run_dir: Path, confirm: str | None,
                  zmap_lock_fd: int | None = None) -> list[str]:
    cmd = [sys.executable, "-m", "scanner.internet", "stage-worker", "--config", str(config_path), "--stage", stage,
           "--shard", str(shard), "--run-dir", str(run_dir), "--parent-pid", str(os.getpid()),
           "--skip-pilot-check"]                            # the coordinator has applied the pilot rule once for the campaign
    if confirm is not None:
        cmd += ["--confirm", confirm]
    if zmap_lock_fd is not None:
        cmd += ["--zmap-lock-fd", str(zmap_lock_fd)]
    return cmd


def _spawn_process(cmd: list[str], pass_fds: tuple[int, ...]) -> subprocess.Popen:
    kw: dict[str, Any] = {}
    if pass_fds:
        kw["pass_fds"] = pass_fds
    if sys.platform.startswith("linux"):
        from scanner.internet.supervisor import _spawn_child
        kw["preexec_fn"] = _spawn_child
    return subprocess.Popen(cmd, **kw)


def pid_alive(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        campaign._check_alive(pid)
    except PermissionError:
        return True
    except (ProcessLookupError, OSError):
        return False
    return True


def _try_zmap_lock(cdir: Path) -> int | None | bool:
    """A file descriptor holding ``zmap.lock``; ``None`` where there are no file locks; ``False`` when another sweep holds it."""
    if fcntl is None:
        return None
    fd = os.open(cdir / LOCK_NAME, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return False
    os.set_inheritable(fd, True)
    return fd


class _Job:
    def __init__(self, shard: int, stage: str, proc: Any) -> None:
        self.shard, self.stage, self.proc, self.started = shard, stage, proc, time.monotonic()


def run_decoupled(cfg: Any, *, config_path: Path, confirm: str | None = None, log: Callable[[str], None] = print,
                  network_workers: int = DEFAULT_NETWORK_WORKERS, favicon_workers: int = DEFAULT_FAVICON_WORKERS,
                  shards_from: int = 0, shards_to: int | None = None, archive: Any = None,
                  spawn: Callable[[list[str], tuple[int, ...]], Any] | None = None, tick: float = 1.0,
                  sleep: Callable[[float], None] = time.sleep, alive: Callable[[int | None], bool] = pid_alive,
                  egress: Callable[[Any], str | None] | None = None, max_attempts: int = MAX_ATTEMPTS) -> dict[str, Any]:
    """Run the campaign with decoupled stages; returns the same result record as the other campaign modes."""
    if network_workers < 1 or favicon_workers < 1:
        raise ValueError("--network-workers and --favicon-workers must be at least 1")
    span = campaign.shard_span(cfg, shards_from, shards_to)
    lock = campaign._acquire_lock(cfg)
    try:
        return _coordinate(cfg, span, Path(config_path), confirm, log, network_workers, favicon_workers, archive,
                           spawn or _spawn_process, tick, sleep, alive, egress or (lambda c: pre.current_egress(c)), max_attempts)
    finally:
        lock.unlink(missing_ok=True)


def _coordinate(cfg: Any, span: range, config_path: Path, confirm: str | None, log: Callable[[str], None], n_workers: int, f_workers: int,
                archive: Any, spawn: Callable[[list[str], tuple[int, ...]], Any], tick: float, sleep: Callable[[float], None],
                alive: Callable[[int | None], bool], egress: Callable[[Any], str | None], max_attempts: int) -> dict[str, Any]:
    cdir = campaign.campaign_dir(cfg)
    cdir.mkdir(parents=True, exist_ok=True)
    path = cdir / "campaign.json"
    state = campaign.load_state(cfg)
    state["decoupled"] = {"network_workers": n_workers, "favicon_workers": f_workers, "max_attempts": max_attempts}
    shards: dict[int, dict[str, Any]] = {}
    for i in span:
        entry = state["shard_states"][str(i)] = _entry_for(cfg, i, state["shard_states"].get(str(i)))
        shards[i] = entry
    # resume: a stage left running by a coordinator that is gone returns to pending, same attempt
    for i, entry in shards.items():
        for name, st in entry["stages"].items():
            if st["status"] == "failed":
                log(f"[coordinator] shard {i + 1}/{cfg.shards} {name}: failed earlier ({st.get('error')}); trying again with fresh attempts")
                st.update(status="pending", attempts=0, owner_pid=None)
            if st["status"] != "running":
                continue
            if alive(st.get("owner_pid")):
                raise campaign.CampaignLocked(f"stage worker {st['owner_pid']} ({name} of shard {i}) from an earlier coordinator is still running")
            if stage_done_in(name, campaign._manifest(Path(entry["run_dir"]))):
                st.update(status="done", owner_pid=None, finished_at=_now(), error=None)
                log(f"[coordinator] shard {i + 1}/{cfg.shards} {name}: finished before the earlier coordinator ended; not repeating it")
            else:
                st.update(status="pending", owner_pid=None)
                log(f"[coordinator] shard {i + 1}/{cfg.shards} {name}: worker is gone, continuing in place (attempt {st['attempts'] + 1})")
        entry["status"] = derive_status(entry["stages"])
    campaign._write_json(path, state)

    jobs: dict[tuple[int, str], _Job] = {}
    stopping: dict[str, Any] | None = None        # hard stop: children are asked to end, nothing starts
    halted: dict[str, Any] | None = None          # a stage failed for good: running children finish, nothing starts
    notes: set[str] = set()
    egress_unknown = 0
    last_beat = time.monotonic()
    stop_asked = 0.0
    dirty = False

    def note(key: str, text: str) -> None:
        if key not in notes:
            notes.add(key)
            log(f"[coordinator] {text}")

    def ask_stop(reason: str, detail: str) -> None:
        nonlocal stopping, stop_asked
        if stopping is None:
            stopping = {"shard": None, "reason": reason, "detail": detail}
            stop_asked = time.monotonic()
            log(f"[coordinator] stopping: {reason}: {detail}")
            for j in jobs.values():
                with contextlib.suppress(OSError):
                    if j.proc.poll() is None:
                        j.proc.send_signal(signal.SIGTERM)

    def on_signal(signum: int, _frame: Any) -> None:
        ask_stop("interrupt", f"signal {signum}")

    previous: dict[int, Any] = {}
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGINT, getattr(signal, "SIGHUP", None)):
            if sig is not None:
                previous[sig] = signal.signal(sig, on_signal)

    def start(i: int, name: str, lock_fd: int | None = None) -> None:
        nonlocal dirty
        entry = shards[i]
        cmd = stage_command(cfg, config_path, name, i, Path(entry["run_dir"]), confirm, lock_fd)
        proc = spawn(cmd, (lock_fd,) if lock_fd is not None else ())
        st = entry["stages"][name]
        now = _now()
        st.update(status="running", owner_pid=getattr(proc, "pid", None), started_at=now, heartbeat=now, finished_at=None, error=None)
        entry["status"] = derive_status(entry["stages"])
        jobs[(i, name)] = _Job(i, name, proc)
        dirty = True
        log(f"[coordinator] shard {i + 1}/{cfg.shards} {name} started (attempt {st['attempts'] + 1}, pid {st['owner_pid']})")

    def settle(job: _Job, rc: int) -> None:
        nonlocal halted, dirty, stopping
        i, name = job.shard, job.stage
        entry, st = shards[i], shards[i]["stages"][name]
        dirty = True
        st.update(owner_pid=None, heartbeat=_now())
        manifest = campaign._manifest(Path(entry["run_dir"]))
        if rc == 0 and stage_done_in(name, manifest):
            if name == "network" and manifest.get("zero_responsive"):
                st.update(status="failed", error="no endpoint answered although every tool ran cleanly")
                entry["status"] = derive_status(entry["stages"])
                _stop_for(i, name, "zero_responsive", st["error"])
                return
            st.update(status="done", finished_at=_now(), error=None)
            entry["status"] = derive_status(entry["stages"])
            log(f"[coordinator] shard {i + 1}/{cfg.shards} {name} done")
            if name == "favicon":
                stop = campaign.record_finished(entry, i, Path(entry["run_dir"]))
                if stop:
                    _stop_for(i, name, stop["reason"], str(stop.get("detail")))
                else:
                    entry["status"] = derive_status(entry["stages"])
                    campaign.prune_finished(cfg, entry, i, log)
            return
        if rc == EXIT_RECYCLE or (stopping is not None and rc != 0):
            st.update(status="pending")
            entry["status"] = derive_status(entry["stages"])
            log(f"[coordinator] shard {i + 1}/{cfg.shards} {name} ends without a result ({'recycle' if rc == EXIT_RECYCLE else 'stopped'}); not counted")
            return
        how = (f"exited 0 but the manifest does not show the {name} stage as finished" if rc == 0
               else f"killed by signal {-rc}" if rc < 0 else f"exited with code {rc}")
        st["error"] = how[:500]
        if rc == EXIT_REFUSED:
            st.update(status="failed", attempts=max(st["attempts"], max_attempts))
            entry["status"] = derive_status(entry["stages"])
            _stop_for(i, name, "preflight_failed", "the stage worker was refused (configuration, approval or preflight)")
            return
        st["attempts"] += 1
        if st["attempts"] >= max_attempts:
            st["status"] = "failed"
            log(f"[coordinator] shard {i + 1}/{cfg.shards} {name} failed after {st['attempts']} attempts: {how}")
            _stop_for(i, name, "crashed", f"{name} of shard {i} {how}")
        else:
            st["status"] = "pending"
            log(f"[coordinator] shard {i + 1}/{cfg.shards} {name} attempt {st['attempts']} failed ({how}); will retry")
        entry["status"] = derive_status(entry["stages"])

    def _stop_for(i: int, name: str, reason: str, detail: str) -> None:
        nonlocal halted
        if halted is None:
            halted = {"shard": i, "reason": reason, "detail": detail, "stage": name}
            log(f"[coordinator] shard {i + 1}/{cfg.shards} {name}: {reason}; nothing further starts, running stages finish")

    def count(name: str) -> int:
        return sum(1 for (_, n) in jobs if n == name)

    def pending(name: str, needs: str | None) -> list[int]:
        return [i for i, e in shards.items() if e["stages"][name]["status"] == "pending"
                and (needs is None or e["stages"][needs]["status"] == "done")]

    try:
        while True:
            for key, job in list(jobs.items()):
                rc = job.proc.poll()
                if rc is None:
                    continue
                del jobs[key]
                settle(job, rc)
            now_m = time.monotonic()
            if Path(cfg.kill_switch_file).exists():
                ask_stop("kill_switch", f"{cfg.kill_switch_file} exists")
            if stopping is not None and jobs and now_m - stop_asked > STOP_GRACE_SECONDS:
                for j in jobs.values():
                    with contextlib.suppress(OSError):
                        j.proc.kill()
            if now_m - last_beat >= HEARTBEAT_SECONDS:
                last_beat = now_m
                for (i, name) in jobs:
                    shards[i]["stages"][name]["heartbeat"] = _now()
                dirty = True
            blocked_zmap: str | None = None
            if stopping is None and halted is None:
                for name, limit, needs in (("favicon", f_workers, "network"), ("network", n_workers, "zmap")):
                    for i in pending(name, needs):
                        if count(name) >= limit:
                            break
                        start(i, name)
                nxt = pending("zmap", None)
                if nxt and count("zmap") == 0:
                    if (cdir / "DRAIN").exists():
                        blocked_zmap = "drain"
                    elif (short := campaign.disk_shortfall(cfg, state)) is not None:
                        blocked_zmap = "disk"
                        note("disk", f"not starting the sweep of shard {nxt[0] + 1}/{cfg.shards}: {short}")
                        disk_detail = short
                    else:
                        if archive is not None:
                            campaign.archive_finished(cfg, state, archive, log)
                        seen = egress(cfg)
                        if seen is None:
                            egress_unknown += 1
                            note(f"egress{egress_unknown}", f"the egress address could not be determined ({egress_unknown}/{EGRESS_UNKNOWN_LIMIT})")
                            if egress_unknown >= EGRESS_UNKNOWN_LIMIT:
                                ask_stop("egress_unknown", "the egress address could not be determined before a sweep start")
                        elif seen != cfg.vantage.public_egress_ip:
                            ask_stop("egress_changed", f"scan traffic would leave from {seen}, not the approved {cfg.vantage.public_egress_ip}")
                        else:
                            egress_unknown = 0
                            lock_fd = _try_zmap_lock(cdir)
                            if lock_fd is False:
                                note("lock", f"{LOCK_NAME} is held by a sweep from an earlier coordinator; waiting for it to end")
                            else:
                                notes.discard("lock")
                                try:
                                    start(nxt[0], "zmap", lock_fd)
                                finally:
                                    if isinstance(lock_fd, int):
                                        os.close(lock_fd)      # the worker (and ZMap) hold the lock from here on
            if dirty:
                campaign._write_json(path, state)
                dirty = False
            if not jobs:
                if stopping is not None or halted is not None:
                    break
                if all(e["stages"]["favicon"]["status"] == "done" for e in shards.values()):
                    break
                if blocked_zmap is not None:
                    # nothing else is running and the sweeps are held back: report why and end resumable
                    if blocked_zmap == "drain":
                        halted = {"shard": None, "reason": "drain", "detail": "stopped between shards on request"}
                    else:
                        halted = {"shard": None, "reason": "disk", "detail": disk_detail}
                    break
            sleep(tick)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        for j in jobs.values():                        # only reached on an unexpected error: leave nothing running
            with contextlib.suppress(OSError):
                j.proc.kill()
                j.proc.wait()
        for i, entry in shards.items():
            for st in entry["stages"].values():
                if st["status"] == "running":
                    st.update(status="pending", owner_pid=None)
            if entry["status"] != "zero_responsive":
                entry["status"] = derive_status(entry["stages"])
        campaign._write_json(path, state)
    stopped = stopping or halted
    run_dirs = {i: Path(e["run_dir"]) for i, e in shards.items() if e["stages"]["favicon"]["status"] == "done"}
    return campaign.end_campaign(cfg, state, run_dirs, stopped, span)
