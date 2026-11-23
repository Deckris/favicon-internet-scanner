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

``zmap.lock`` is an advisory ``flock`` taken before each sweep starts. It is one file for the whole machine, shared by
every campaign (``zmap_lock_path``). Its file descriptor is handed to the worker, which hands it on to ZMap, so a sweep
still on the wire keeps the lock when the coordinator or the worker dies, and a restarted coordinator waits for it rather
than sending a second sweep.

A worker that exits 0 has its stage verified in the manifest. Any other exit code fails the attempt; a stage is
attempted ``MAX_ATTEMPTS`` times. ``EXIT_RECYCLE`` asks for a fresh process without counting an attempt. ``EXIT_LIMITER`` (the
limiter daemon stayed unreachable for longer than a worker waits) does not count either: the stage is parked for a cooldown
(``LIMITER_COOLDOWNS``), at most ``MAX_LIMITER_PARKS`` times, and no stage starts while the daemon does not answer a probe. A stage whose
worker is gone without a record of its end (the coordinator died, or was stopped) returns to pending with the same attempt
and continues in place from the units already committed to the shard's fact store. A stage that failed stays failed across
restarts of the coordinator, with its attempt count; only ``retry_failed`` (``--retry-failed``) gives it fresh attempts.

A ZMap sweep unit that is lost after the zmap stage was marked done (missing from the fact store, or reported by the network
worker with ``EXIT_ZMAP_MISSING``) sends the shard back to a pending zmap stage. The sweep then repeats only the missing
units, because the finished ones are kept in the store. Such a return is counted in ``resweeps`` and capped at ``max_attempts``.
"""
from __future__ import annotations

import contextlib
from dataclasses import replace
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
from scanner.internet import resume as resume_mod

try:
    import fcntl
except ImportError:             # Windows: no machine-wide lock; the coordinator itself still runs one sweep at a time
    fcntl = None                # type: ignore[assignment]

STAGES = ("zmap", "network", "favicon")
MAX_ATTEMPTS = 3
DEFAULT_NETWORK_WORKERS = 2
DEFAULT_FAVICON_WORKERS = 3
EXIT_REFUSED = 2                # stage-worker: configuration, approval or preflight refusal; never retried
EXIT_ZMAP_MISSING = 76          # stage-worker (network): sweep units of the fact store are missing; the shard goes back to the zmap stage
EXIT_RECYCLE = 75               # stage-worker: "start me again in a fresh process" (e.g. memory ceiling); restarted without counting an attempt
EXIT_LIMITER = 77               # stage-worker: unfinished, and every failure was the limiter daemon being unreachable; parked, not counted
LIMITER_COOLDOWNS = (30, 60, 120, 300, 600)     # seconds a parked stage waits; the last value repeats
MAX_LIMITER_PARKS = 20          # parks of one stage before the next one counts as an ordinary failed attempt
LIMITER_START_WAIT = 120.0      # how long a stage worker waits for the daemon at its start
LIMITER_OUTAGE_LIMIT = 600.0    # how long a running worker waits for the daemon before it gives the stage up
LIMITER_PROBE_TIMEOUT = 2.0
LIMITER_PROBE_RETRY = 5.0       # a failed probe is not repeated sooner than this
LIMITER_PROBE_FRESH = 2.0       # an answered probe is reused for this long
LIMITER_PROBE_LOG = 60.0        # a failing probe is logged this often
LIMITER_PROBE_ALERT = 600.0     # a probe that has failed this long with nothing running raises an alert
LOCK_NAME = "zmap.lock"
LOCK_ENV = "SCANNER_ZMAP_LOCK"
RUN_DIR = Path("/run/scanner")
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


def _env_seconds(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


def limiter_budget_seconds(start_wait: float = LIMITER_START_WAIT, outage_limit: float = LIMITER_OUTAGE_LIMIT,
                           cooldown: float = max(LIMITER_COOLDOWNS)) -> float:
    """The longest a shard can be held up by the limiter in one go: the start wait, the outage limit and the longest cooldown."""
    return float(start_wait) + float(outage_limit) + float(cooldown)


def limiter_budget_problem(cfg: Any) -> str | None:
    """A note when ``limiter_budget_seconds`` is not below ``operations.stall_minutes``: a shard held for the limiter would
    then look stalled to the stall rule and to a watchdog that goes by output. None when it fits or the rule is off."""
    minutes = getattr(cfg, "stall_minutes", None)
    if minutes is None:
        minutes = getattr(getattr(cfg, "operations", None), "stall_minutes", 0)
    minutes = minutes or 0
    if minutes <= 0:
        return None
    budget = limiter_budget_seconds(_env_seconds("SCANNER_LIMITER_START_WAIT", LIMITER_START_WAIT),
                                    _env_seconds("SCANNER_LIMITER_OUTAGE_LIMIT", LIMITER_OUTAGE_LIMIT))
    if budget < minutes * 60:
        return None
    return (f"a limiter outage can hold a shard for up to {budget:.0f} s (start wait, outage limit and longest cooldown), "
            f"which is not below operations.stall_minutes ({minutes} min = {minutes * 60} s); raise stall_minutes or lower "
            "SCANNER_LIMITER_OUTAGE_LIMIT")


def limiter_socket_of(cfg: Any) -> str | None:
    """The limiter daemon's socket as the stage workers resolve it: the configuration first, then the environment."""
    return getattr(getattr(cfg, "measurement", None), "limiter_socket", None) or os.environ.get("SCANNER_LIMITER_SOCKET") or None


def probe_limiter(cfg: Any, timeout: float = LIMITER_PROBE_TIMEOUT) -> str | None:
    """None when the daemon answers a ``hello`` and a ``ping`` within ``timeout`` seconds on a connection of its own;
    otherwise what went wrong. A daemon that refuses this configuration for good does answer: the stage reports that itself."""
    import socket
    from scanner.internet import limiterd as proto
    path = limiter_socket_of(cfg)
    if not path:
        return None
    if not hasattr(socket, "AF_UNIX"):
        return "Unix domain sockets are not available"
    m = cfg.measurement
    deadline = time.monotonic() + timeout

    def take(s: Any, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            s.settimeout(max(deadline - time.monotonic(), 0.05))
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed")
            buf += chunk
        return buf

    def exchange(s: Any, message: dict[str, Any]) -> dict[str, Any]:
        s.settimeout(max(deadline - time.monotonic(), 0.05))
        s.sendall(proto.pack_frame(message))
        return proto.decode_frame(take(s, proto.unpack_length(take(s, 4))))

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(str(path))
        hello = exchange(s, {"op": "hello", "protocol": proto.PROTOCOL, "cap": m.max_connections_per_subnet,
                             "gap": m.min_seconds_between_probes_per_ip, "client": f"probe-{os.getpid()}-{os.urandom(6).hex()}",
                             "held": {}, "busy": [], "recent": {}})
        if not hello.get("ok"):
            return None if hello.get("fatal") else f"the daemon answered: {hello.get('error', 'refused')}"
        if not exchange(s, {"op": "ping"}).get("ok"):
            return "the daemon did not answer a ping"
        with contextlib.suppress(OSError, ValueError):
            exchange(s, {"op": "goodbye"})
        return None
    except (OSError, ValueError) as exc:
        return f"{type(exc).__name__}: {exc}"
    finally:
        s.close()


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
                  zmap_lock_fd: int | None = None, extra_args: tuple[str, ...] = ()) -> list[str]:
    cmd = [sys.executable, "-m", "scanner.internet", "stage-worker", "--config", str(config_path), "--stage", stage,
           "--shard", str(shard), "--run-dir", str(run_dir), "--parent-pid", str(os.getpid()),
           "--skip-pilot-check"]                            # the coordinator has applied the pilot rule once for the campaign
    if confirm is not None:
        cmd += ["--confirm", confirm]
    if zmap_lock_fd is not None:
        cmd += ["--zmap-lock-fd", str(zmap_lock_fd)]
    overlay = getattr(cfg, "exclusions_overlay_file", None)
    if overlay:                                             # a command-line overlay is not in the config file the worker loads
        cmd += ["--exclusions-overlay", str(overlay)]
    return cmd + list(extra_args)


def _spawn_process(cmd: list[str], pass_fds: tuple[int, ...]) -> subprocess.Popen:
    kw: dict[str, Any] = {}
    if pass_fds:
        kw["pass_fds"] = pass_fds
    if os.name == "posix":
        kw["start_new_session"] = True                      # its own group, so an escalation reaches the worker and what it started
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


def process_identity(pid: int | None) -> dict[str, str] | None:
    """Start time of ``pid`` (field 22 of ``/proc/<pid>/stat``) and the boot id; ``None`` where /proc does not give them.
    A pid recorded before a reboot, or reused since, has another identity."""
    if not pid or pid <= 0:
        return None
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
        start = stat[stat.rindex(")") + 2:].split()[19]      # field 22; the fields before it include the parenthesised name
    except (OSError, ValueError, IndexError):
        return None
    return {"owner_start": start, "owner_boot": boot}


def owner_alive(st: dict[str, Any], alive: Callable[[int | None], bool]) -> bool:
    """Is the process that ``st`` records still the same one? A different start time or boot id means the pid was reused."""
    pid = st.get("owner_pid")
    if not alive(pid):
        return False
    now = process_identity(pid)
    if now is None:
        return True
    for key in ("owner_start", "owner_boot"):
        if st.get(key) and st[key] != now[key]:
            return False
    return True


def _descendants(pid: int) -> list[int]:
    """All live descendants of ``pid`` (Linux /proc); empty elsewhere."""
    children: dict[int, list[int]] = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        return []
    for name in names:
        if not name.isdigit():
            continue
        try:
            stat = Path(f"/proc/{name}/stat").read_text(encoding="utf-8", errors="replace")
            ppid = int(stat[stat.rindex(")") + 2:].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        children.setdefault(ppid, []).append(int(name))
    out, todo = [], [pid]
    while todo:
        for child in children.get(todo.pop(), []):
            out.append(child)
            todo.append(child)
    return out


def _kill_tree(proc: Any) -> None:
    """SIGKILL a worker, its process group and everything it started, ZMap included (it runs in a session of its own and
    clears its death signal, so it would keep sending after a plain kill of the worker)."""
    pid = getattr(proc, "pid", None)
    if os.name == "posix" and isinstance(pid, int) and pid > 1:
        pids = [pid, *_descendants(pid)]
        groups = set()
        for p in pids:
            with contextlib.suppress(OSError):
                groups.add(os.getpgid(p))
        groups.discard(os.getpgrp())                        # never the coordinator's own group
        for g in groups:
            with contextlib.suppress(OSError):
                os.killpg(g, signal.SIGKILL)
        for p in pids:
            with contextlib.suppress(OSError):
                os.kill(p, signal.SIGKILL)
    with contextlib.suppress(OSError):
        proc.kill()


def zmap_lock_path(cfg: Any, explicit: Path | str | None = None) -> Path:
    """The one ``zmap.lock`` of this machine: ``explicit`` (``--zmap-lock-file``), else ``$SCANNER_ZMAP_LOCK``, else
    ``/run/scanner/zmap.lock`` when that directory is writable, else ``zmap.lock`` in the output root."""
    chosen = explicit or os.environ.get(LOCK_ENV)
    if chosen:
        return Path(chosen)
    if RUN_DIR.is_dir() and os.access(RUN_DIR, os.W_OK):
        return RUN_DIR / LOCK_NAME
    return Path(cfg.output_dir) / LOCK_NAME


def limiter_refusal(cfg: Any, network_workers: int, favicon_workers: int, allow: bool) -> str | None:
    """Several target-facing workers each enforce the per-network cap and the per-address pause for themselves unless a
    limiter daemon is shared; together they would exceed both."""
    if allow or network_workers + favicon_workers <= 1:
        return None
    if os.environ.get("SCANNER_LIMITER_SOCKET") or getattr(cfg.measurement, "limiter_socket", None):
        return None
    return (f"{network_workers} network and {favicon_workers} favicon workers would each apply the per-network cap and the "
            "per-address pause on their own. Start the limiter daemon and pass --limiter-socket (or set "
            "SCANNER_LIMITER_SOCKET or measurement.limiter_socket), or pass --allow-per-process-limits on purpose")


def _try_zmap_lock(path: Path) -> int | None | bool:
    """A file descriptor holding the ZMap lock file ``path``; ``None`` where there are no file locks; ``False`` when another sweep holds it."""
    if fcntl is None:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o644)
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
                  egress: Callable[[Any], str | None] | None = None, max_attempts: int = MAX_ATTEMPTS,
                  retry_failed: bool = False, zmap_lock: Path | str | None = None, worker_args: tuple[str, ...] = (),
                  allow_per_process_limits: bool = False, limiter_probe: Callable[[Any], str | None] | None = None,
                  clock: Callable[[], float] = time.time) -> dict[str, Any]:
    """Run the campaign with decoupled stages; returns the same result record as the other campaign modes.

    ``retry_failed`` gives stages that failed in an earlier run fresh attempts (and a fresh count of limiter parks); without it
    they stay failed and the campaign ends at once. ``limiter_probe(cfg)`` (``probe_limiter`` from the command line; none by default) returns None when the limiter
    daemon answers and is only asked when a limiter socket is configured and ``clock`` is the wall clock behind ``not_before``. ``worker_args`` are command-line options handed to every stage worker."""
    if network_workers < 1 or favicon_workers < 1:
        raise ValueError("--network-workers and --favicon-workers must be at least 1")
    refusal = limiter_refusal(cfg, network_workers, favicon_workers, allow_per_process_limits)
    if refusal:
        raise ValueError(refusal)
    span = campaign.shard_span(cfg, shards_from, shards_to)
    lock = campaign._acquire_lock(cfg)
    try:
        return _coordinate(cfg, span, Path(config_path), confirm, log, network_workers, favicon_workers, archive,
                           spawn or _spawn_process, tick, sleep, alive, egress or (lambda c: pre.current_egress(c)), max_attempts,
                           retry_failed, zmap_lock_path(cfg, zmap_lock), tuple(worker_args), limiter_probe, clock)
    finally:
        lock.unlink(missing_ok=True)


def _coordinate(cfg: Any, span: range, config_path: Path, confirm: str | None, log: Callable[[str], None], n_workers: int, f_workers: int,
                archive: Any, spawn: Callable[[list[str], tuple[int, ...]], Any], tick: float, sleep: Callable[[float], None],
                alive: Callable[[int | None], bool], egress: Callable[[Any], str | None], max_attempts: int,
                retry_failed: bool, lock_path: Path, worker_args: tuple[str, ...],
                limiter_probe: Callable[[Any], str | None] | None = None, clock: Callable[[], float] = time.time) -> dict[str, Any]:
    cdir = campaign.campaign_dir(cfg)
    cdir.mkdir(parents=True, exist_ok=True)
    path = cdir / "campaign.json"
    state = campaign.load_state(cfg)
    if limiter_socket_of(cfg) and (problem := limiter_budget_problem(cfg)):
        log(f"[coordinator] WARNING: {problem}")
    state["decoupled"] = {"network_workers": n_workers, "favicon_workers": f_workers, "max_attempts": max_attempts}
    shards: dict[int, dict[str, Any]] = {}
    for i in span:
        entry = state["shard_states"][str(i)] = _entry_for(cfg, i, state["shard_states"].get(str(i)))
        shards[i] = entry
    # resume: a stage left running by a coordinator that is gone returns to pending, same attempt
    halted: dict[str, Any] | None = None          # a stage failed for good: running children finish, nothing starts
    for i, entry in shards.items():
        for name, st in entry["stages"].items():
            if st["status"] == "failed":
                if retry_failed:
                    log(f"[coordinator] shard {i + 1}/{cfg.shards} {name}: failed earlier ({st.get('error')}); trying again with fresh attempts")
                    st.update(status="pending", attempts=0, owner_pid=None, stop_reason=None, limiter_parks=0, not_before=None)
                elif halted is None:
                    halted = {"shard": i, "reason": st.get("stop_reason") or "crashed", "stage": name,
                              "detail": f"{name} of shard {i} failed earlier ({st.get('error')}); pass --retry-failed to try it again"}
                    log(f"[coordinator] shard {i + 1}/{cfg.shards} {name}: failed earlier ({st.get('error')}); not trying again without --retry-failed")
            if st.get("not_before"):          # a clock set back must not stretch a cooldown
                st["not_before"] = min(st["not_before"], clock() + max(LIMITER_COOLDOWNS))
            if st["status"] != "running":
                continue
            if owner_alive(st, alive):
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
        cmd = stage_command(cfg, config_path, name, i, Path(entry["run_dir"]), confirm, lock_fd, worker_args)
        proc = spawn(cmd, (lock_fd,) if lock_fd is not None else ())
        st = entry["stages"][name]
        now = _now()
        pid = getattr(proc, "pid", None)
        st.update(status="running", owner_pid=pid, started_at=now, heartbeat=now, finished_at=None, error=None, not_before=None,
                  **(process_identity(pid) or {"owner_start": None, "owner_boot": None}))
        entry["status"] = derive_status(entry["stages"])
        jobs[(i, name)] = _Job(i, name, proc)
        dirty = True
        log(f"[coordinator] shard {i + 1}/{cfg.shards} {name} started (attempt {st['attempts'] + 1}, pid {st['owner_pid']})")

    def settle(job: _Job, rc: int) -> None:
        nonlocal halted, dirty, stopping
        i, name = job.shard, job.stage
        entry, st = shards[i], shards[i]["stages"][name]
        dirty = True
        st.update(owner_pid=None, owner_start=None, owner_boot=None, heartbeat=_now())
        manifest = campaign._manifest(Path(entry["run_dir"]))
        if rc == 0 and stage_done_in(name, manifest):
            if name == "network" and manifest.get("zero_responsive"):
                st.update(status="failed", stop_reason="zero_responsive", error="no endpoint answered although every tool ran cleanly")
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
        if rc == EXIT_ZMAP_MISSING and name == "network" and stopping is None:
            reopen_zmap(i, "the network worker found its sweep results missing")
            return
        if rc == EXIT_LIMITER and stopping is None:
            parks = st.get("limiter_parks", 0)
            if parks < MAX_LIMITER_PARKS:
                wait = LIMITER_COOLDOWNS[min(parks, len(LIMITER_COOLDOWNS) - 1)]
                st.update(status="pending", limiter_parks=parks + 1, not_before=clock() + wait, error="the limiter daemon was unreachable")
                entry["status"] = derive_status(entry["stages"])
                log(f"[coordinator] shard {i + 1}/{cfg.shards} {name} ended because the limiter daemon was unreachable; "
                    f"not counted, trying again in {wait} s (park {parks + 1}/{MAX_LIMITER_PARKS})")
                return
            raise_alert(i, name, parks)
        if rc == EXIT_RECYCLE or (stopping is not None and rc != 0):
            st.update(status="pending")
            entry["status"] = derive_status(entry["stages"])
            log(f"[coordinator] shard {i + 1}/{cfg.shards} {name} ends without a result ({'recycle' if rc == EXIT_RECYCLE else 'stopped'}); not counted")
            return
        how = (f"exited 0 but the manifest does not show the {name} stage as finished" if rc == 0
               else f"killed by signal {-rc}" if rc < 0 else f"exited with code {rc}")
        st["error"] = how[:500]
        if rc == EXIT_REFUSED:
            st.update(status="failed", stop_reason="preflight_failed", attempts=max(st["attempts"], max_attempts))
            entry["status"] = derive_status(entry["stages"])
            _stop_for(i, name, "preflight_failed", "the stage worker was refused (configuration, approval or preflight)")
            return
        st["attempts"] += 1
        if st["attempts"] >= max_attempts:
            st.update(status="failed", stop_reason="crashed")
            log(f"[coordinator] shard {i + 1}/{cfg.shards} {name} failed after {st['attempts']} attempts: {how}")
            _stop_for(i, name, "crashed", f"{name} of shard {i} {how}")
        else:
            st["status"] = "pending"
            log(f"[coordinator] shard {i + 1}/{cfg.shards} {name} attempt {st['attempts']} failed ({how}); will retry")
        entry["status"] = derive_status(entry["stages"])

    def raise_alert(i: int, name: str, parks: int) -> None:
        write_alert(f"shard {i + 1}/{cfg.shards} {name}: the limiter daemon was unreachable on {parks} earlier runs of this stage; "
                    "this failure counts as an attempt")

    def write_alert(text: str) -> None:
        log(f"[coordinator] ALERT {text}")
        with contextlib.suppress(OSError):
            with (cdir / "ALERT").open("a", encoding="utf-8") as fh:
                fh.write(f"{_now()} {text}\n")

    probe: dict[str, Any] = {"at": float("-inf"), "problem": None, "logged": float("-inf"), "since": None, "alerted": False}

    def limiter_ready() -> bool:
        """May a stage start? Without a limiter socket always; otherwise only while the daemon answers a probe."""
        if limiter_probe is None or not limiter_socket_of(cfg):
            return True
        now_m = time.monotonic()
        reuse = LIMITER_PROBE_FRESH if probe["problem"] is None else LIMITER_PROBE_RETRY
        if now_m - probe["at"] >= reuse:
            probe["problem"], probe["at"] = limiter_probe(cfg), now_m
        if probe["problem"] is None:
            probe["since"], probe["alerted"] = None, False
            return True
        if probe["since"] is None:
            probe["since"] = now_m
        if not probe["alerted"] and not jobs and now_m - probe["since"] >= LIMITER_PROBE_ALERT:
            probe["alerted"] = True
            write_alert(f"the limiter daemon has not answered for {now_m - probe['since']:.0f} s and no stage is running "
                        f"({probe['problem']})")
        if now_m - probe["logged"] >= LIMITER_PROBE_LOG:
            probe["logged"] = now_m
            log(f"[coordinator] the limiter daemon does not answer ({probe['problem']}); no stage starts until it does")
        return False

    def reopen_zmap(i: int, why: str) -> None:
        """Send shard ``i`` back to a pending zmap stage; the sweep repeats the missing units only."""
        nonlocal dirty
        entry = shards[i]
        zst, nst = entry["stages"]["zmap"], entry["stages"]["network"]
        dirty = True
        zst["resweeps"] = zst.get("resweeps", 0) + 1
        if zst["resweeps"] > max_attempts:
            zst.update(status="failed", stop_reason="crashed", error=f"sweep results lost again after {max_attempts} repeated sweeps: {why}"[:500])
            entry["status"] = derive_status(entry["stages"])
            log(f"[coordinator] shard {i + 1}/{cfg.shards} zmap: {zst['error']}")
            _stop_for(i, "zmap", "crashed", f"zmap of shard {i} {zst['error']}")
            return
        zst.update(status="pending", attempts=0, owner_pid=None, finished_at=None, error=why[:500])
        nst.update(status="pending", owner_pid=None)
        entry["status"] = derive_status(entry["stages"])
        log(f"[coordinator] shard {i + 1}/{cfg.shards} zmap: {why}; sweeping the missing units again ({zst['resweeps']}/{max_attempts})")

    def sweeps_lost(i: int) -> bool:
        """True when the fact store of shard ``i`` exists but lacks finished sweep units of the configured ports."""
        run_dir = Path(shards[i]["run_dir"])
        if not (run_dir / "work" / "facts.sqlite").is_file():
            return False                       # no store at all: the network worker reports it with EXIT_ZMAP_MISSING
        return bool(resume_mod.missing_zmap_ports(run_dir, replace(cfg, shard=i)))

    def _stop_for(i: int, name: str, reason: str, detail: str) -> None:
        nonlocal halted
        if halted is None:
            halted = {"shard": i, "reason": reason, "detail": detail, "stage": name}
            log(f"[coordinator] shard {i + 1}/{cfg.shards} {name}: {reason}; nothing further starts, running stages finish")

    def count(name: str) -> int:
        return sum(1 for (_, n) in jobs if n == name)

    def pending(name: str, needs: str | None) -> list[int]:
        wall = clock()
        latest = wall + max(LIMITER_COOLDOWNS)
        for e in shards.values():
            if (e["stages"][name].get("not_before") or 0) > latest:     # the clock was set back: a park is never longer than a cooldown
                e["stages"][name]["not_before"] = latest
        return [i for i, e in shards.items() if e["stages"][name]["status"] == "pending"
                and (e["stages"][name].get("not_before") or 0) <= wall
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
                    _kill_tree(j.proc)
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
                        if name == "network" and sweeps_lost(i):
                            reopen_zmap(i, "sweep units are missing from the fact store")
                            continue
                        if not limiter_ready():
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
                    elif limiter_ready():
                        lock_fd = _try_zmap_lock(lock_path)       # first: while an earlier sweep runs there is nothing to look up
                        if lock_fd is False:
                            note("lock", f"{lock_path} is held by a sweep that is still running; waiting for it to end")
                        else:
                            notes.discard("lock")
                            try:
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
                                    start(nxt[0], "zmap", lock_fd)
                            finally:
                                if isinstance(lock_fd, int):
                                    os.close(lock_fd)          # a started worker (and ZMap) holds the lock from here on
            if dirty:
                campaign._write_json(path, state)
                dirty = False
            if not jobs:
                if stopping is not None or halted is not None:
                    break
                if all(e["stages"]["favicon"]["status"] == "done" for e in shards.values()):
                    break
                if blocked_zmap is not None and not any(
                        st["status"] == "pending" and (st.get("not_before") or 0) > clock()
                        for e in shards.values() for st in e["stages"].values()):
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
            _kill_tree(j.proc)
            with contextlib.suppress(OSError):
                j.proc.wait()
        for i, entry in shards.items():
            for st in entry["stages"].values():
                if st["status"] == "running":
                    st.update(status="pending", owner_pid=None, owner_start=None, owner_boot=None)
            if entry["status"] != "zero_responsive":
                entry["status"] = derive_status(entry["stages"])
        campaign._write_json(path, state)
    stopped = stopping or halted
    run_dirs = {i: Path(e["run_dir"]) for i, e in shards.items() if e["stages"]["favicon"]["status"] == "done"}
    return campaign.end_campaign(cfg, state, run_dirs, stopped, span)
