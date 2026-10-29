"""scanner orchestrator: IP -> ZMap -> ZGrab2 (TLS first) -> PTR/cert names -> ZDNS -> SNI confirm -> favicon.

Each stage is failure-isolated: an exception or tool failure is recorded under
``stage_errors`` and the run continues with whatever the stage managed to
produce, so one bad host or one bad stage never discards the rest of the run.
The manifest is written even when the run ends early (kill switch, error).
"""
from __future__ import annotations

import contextlib
import csv
import faulthandler
import hashlib
import json
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from scanner import asn_context
from scanner.internet import candidates as cand
from scanner.internet import enrich
from scanner.internet import favicon as fav
from scanner.internet import icon_store
from scanner.internet import outputs
from scanner.internet import overlap as ovl
from scanner.internet import pacing
from scanner.internet import population as pop
from scanner.internet import preflight as pre
from scanner.internet import tls as tlsmod
from scanner.internet.config import ConfigError, ScanConfig, read_exclusions, sha256_file
from scanner.internet.runner import ManagedExecutor
from scanner.internet.shardstore import EndpointFacts, IpFacts, ShardStore
from scanner.models import ToolJob, canonical_json, write_jsonl
from scanner.safety import HostnamePolicyInput, ProductionPolicyInput, TargetPolicy
from scanner.zdns_runner import ptr_names, resolve, run_zdns
from scanner.zgrab_runner import ZGrabTarget, run_zgrab_batches
from scanner.zmap_runner import run_zmap

Executor = Callable[..., Any]
SCHEMA_VERSION = 1
INSTRUMENT_VERSION = "scanner.3"
MONITOR_TICK = 0.5          # how often the run monitor evaluates the stop conditions
WEB_PROTOCOLS = ("https", "http")
# TLS outcomes after which a plain-HTTP probe is still worth sending: the port did not prove it speaks TLS.
HTTP_FALLBACK = frozenset({tlsmod.NOT_TLS, tlsmod.CLOSED, tlsmod.RESET, tlsmod.TIMEOUT, tlsmod.OTHER})
# TLS outcomes that prove the port speaks TLS even though no handshake completed without SNI.
TLS_PROVEN = frozenset({tlsmod.ALERT_UNRECOGNIZED_NAME, tlsmod.ALERT_OTHER, tlsmod.VERSION, tlsmod.NO_CIPHER})
# DNS outcomes that say nothing about the mapping (maps_to_scanned_ip is then null, not false).
DNS_UNKNOWN = frozenset({"tool_error", "timeout", "servfail", "cname_loop", "too_many_cnames"})


def confirm_token(cfg: ScanConfig, splan: pop.SamplePlan) -> str:
    """Token ``plan`` prints and ``run`` must be given: ties a run to a reviewed plan."""
    blob = f"{cfg.checksum}|{cfg.approval_sha256}|{splan.total_targets or splan.targets_per_port}|{splan.shards}|{list(splan.ports)}|{splan.rate}"
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


def build_policy(cfg: ScanConfig) -> tuple[TargetPolicy, pop.SamplePlan, list[str]]:
    exclusions = read_exclusions(cfg.exclusions_file)
    if cfg.target_ips:                      # known targets: the population IS the listed addresses
        population = [f"{ip}/32" for ip in cfg.target_ips]
        allowed = pop.allowed_addresses(population, exclusions)
        splan = pop.SamplePlan(tuple(population), allowed, cfg.sample_fraction, allowed, tuple(cfg.measurement.ports),
                               cfg.measurement.zmap_rate, cfg.measurement.zmap_probes, 1, 0, allowed)
    else:
        population = pop.population_cidrs()
        splan = pop.plan(population, exclusions, fraction=cfg.sample_fraction, ports=cfg.measurement.ports,
                         rate=cfg.measurement.zmap_rate, probes=cfg.measurement.zmap_probes, shards=cfg.shards, shard=cfg.shard)
    policy = TargetPolicy.production(ProductionPolicyInput(
        approval_reference=cfg.approval.approval_reference if cfg.approval else "unapproved",
        population=tuple(population),
        hostname_policy=HostnamePolicyInput(cfg.hostname_mode, cfg.hostname_suffixes),
        exclusions=tuple(exclusions),
    ))
    return policy, splan, exclusions


def _scrub(value: Any) -> Any:
    """Replace lone surrogates (they cannot be encoded as UTF-8) so one hostile string cannot lose a whole output file."""
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, (list, tuple)):
        return [_scrub(v) for v in value]
    if isinstance(value, dict):
        return {_scrub(k): _scrub(v) for k, v in value.items()}
    return value


def _earlier_attempt_records(resume_from: Path | None, have: dict, fjobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Favicon records of an earlier attempt that belong to this attempt's jobs and are not already in hand."""
    if resume_from is None:
        return []
    path = Path(resume_from)
    if path.is_dir():
        path = path / "raw" / "favicon_records.jsonl"
    try:
        prior = fav.RecordLog(path).load()
    except (OSError, UnicodeDecodeError):
        return []
    wanted = {(j["ip"], j["port"], j.get("hostname")) for j in fjobs}
    return [rec for key, rec in prior.items() if key in wanted and key not in have]


def _jsonable(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, SimpleNamespace):
        return vars(value)
    return value


class _Stages:
    """Stage runner: failure isolation plus the stop conditions (kill switch, interrupt, approval expiry)."""

    def __init__(self, cfg: ScanConfig, run_dir: Path | None = None, guards: bool = False) -> None:
        self.cfg = cfg
        self.run_dir = run_dir
        self.guards = guards                 # live checks that touch the network (public IP); off for offline runs
        self.label = f"shard {cfg.shard + 1}/{cfg.shards}" if cfg.shards > 1 else "run"
        now = time.monotonic()
        self._next_egress = now + cfg.egress_check_seconds
        self._next_disk = now
        self._egress_unknown = 0
        self._guard_lock = threading.Lock()      # one lookup at a time, whichever thread polls first
        self.timings: dict[str, float] = {}
        self.errors: dict[str, str] = {}
        self.skipped: list[str] = []
        self.interrupted = False
        self.reason: str | None = None
        self.stop = threading.Event()            # set (with ``reason``) as soon as any stop condition fires
        self.pending: str | None = None          # a stop asked for from a signal handler; promoted to ``stop`` outside it
        self.executor: Any = None                # for the tool count the stall check consults
        self.stall_seconds = float(getattr(cfg, "stall_minutes", 30)) * 60
        self._progress = 0
        self._last_progress = (0, now)
        self._monitor: threading.Thread | None = None
        self._guard_thread: threading.Thread | None = None
        self._monitor_done = threading.Event()
        self.phase_gate: Callable[[str], Any] | None = None     # overlapped campaigns: serialises phase A and phase B across shards
        self.phases = contextlib.ExitStack()

    def progress(self) -> None:
        """Called whenever a stage gets a result; a run that stops calling it for ``stall_minutes`` is aborted."""
        self._progress += 1

    def request_stop(self, reason: str) -> None:
        """Set the stop reason and wake every waiting thread. Not for signal handlers: ``Event.set`` takes a lock (see ``flag_stop``)."""
        if self.reason is None:
            self.reason = reason
        self.stop.set()

    def flag_stop(self, reason: str) -> None:
        """What a signal handler may do: one plain assignment. ``killed`` and the monitor turn it into ``request_stop``."""
        if self.pending is None:
            self.pending = reason

    def guard(self, name: str, fn: Callable[[], Any], default: Any = None) -> Any:
        """Run a step between or after the stages. A failure is recorded under ``name`` and the run goes on to its manifest."""
        try:
            return fn()
        except KeyboardInterrupt as exc:
            self.interrupted = True
            self.errors.setdefault(name, f"interrupted: {exc}"[:200])
        except Exception as exc:
            self.errors.setdefault(name, f"{type(exc).__name__}: {exc}"[:500])
        return default

    def killed(self) -> bool:
        if self.reason:
            return True
        if self.pending:
            self.request_stop(self.pending)
            return True
        if self.interrupted:
            self.request_stop("interrupt")
            return True
        if self._monitor is not None:       # the monitor evaluates the conditions; this is only a flag read
            return False
        reason = self._condition()
        if reason:
            self.request_stop(reason)
        return reason is not None

    def check_now(self) -> bool:
        """``killed`` with the conditions evaluated here and now (stage boundaries), not at the monitor's next tick."""
        if not self.killed() and self._monitor is not None:
            reason = self._operator_condition()
            if reason:
                self.request_stop(reason)
        return self.killed()

    def _operator_condition(self) -> str | None:
        """The conditions that are a file read or a clock read: the kill file and the approval window."""
        if Path(self.cfg.kill_switch_file).exists():
            return "kill_switch"
        if self.cfg.approval is not None and datetime.now(UTC) >= self.cfg.approval.valid_until:
            return "approval_expired"
        return None

    def _condition(self) -> str | None:
        return self._operator_condition() or self._guard_reason()

    def start_monitor(self) -> None:
        if self._monitor is not None:
            return
        reason = self._condition()          # a stop condition that already holds must be seen before the first stage
        if reason:
            self.request_stop(reason)
        self._monitor_done.clear()
        self._last_progress = (self._progress, time.monotonic())
        self._monitor = threading.Thread(target=self._watch, name="run-monitor", daemon=True)
        self._monitor.start()
        # The egress lookup can take seconds; it runs on its own thread so the kill file is never waiting behind it.
        self._guard_thread = threading.Thread(target=self._watch_guards, name="run-guards", daemon=True)
        self._guard_thread.start()

    def stop_monitor(self) -> None:
        thread, self._monitor = self._monitor, None
        guard, self._guard_thread = self._guard_thread, None
        self._monitor_done.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=10)
        if guard is not None and guard is not threading.current_thread():
            guard.join(timeout=10)

    def _watch_guards(self) -> None:
        while not self._monitor_done.wait(MONITOR_TICK):
            if self.reason:
                continue
            try:
                reason = self._guard_reason()
            except Exception:           # a failing check must not end the monitoring
                continue
            if reason:
                self.request_stop(reason)

    def _watch(self) -> None:
        while not self._monitor_done.wait(MONITOR_TICK):
            if self.pending and not self.reason:
                self.request_stop(self.pending)
            if self.reason:
                self.stop.set()
                continue
            try:
                reason = "interrupt" if self.interrupted else self._operator_condition() or self._stalled()
            except Exception:           # a failing check must not end the monitoring
                continue
            if reason:
                self.request_stop(reason)

    def _stalled(self) -> str | None:
        if self.stall_seconds <= 0:
            return None
        now = time.monotonic()
        if self._progress != self._last_progress[0] or getattr(self.executor, "active_tools", 0):
            self._last_progress = (self._progress, now)       # a running tool is progress of its own
            return None
        return "stalled" if now - self._last_progress[1] >= self.stall_seconds else None

    def _guard_reason(self) -> str | None:
        """Conditions that must stop a long run: low disk, and a public IP that is no longer the approved source."""
        if not self._guard_lock.acquire(blocking=False):
            return None
        try:
            return self._guard_reason_locked()
        finally:
            self._guard_lock.release()

    def _guard_reason_locked(self) -> str | None:
        now = time.monotonic()
        if self.run_dir is not None and now >= self._next_disk:
            self._next_disk = now + 15
            try:
                if shutil.disk_usage(self.run_dir).free < self.cfg.min_free_mib << 20:
                    return "disk_low"
            except OSError:
                pass
        if self.guards and self.cfg.egress_check_seconds and now >= self._next_egress:
            self._next_egress = now + self.cfg.egress_check_seconds
            seen = pre.current_egress(self.cfg, timeout=6.0)
            if seen is None:
                self._egress_unknown += 1
                if self._egress_unknown >= 3:        # a single failed lookup is tolerated; three in a row is not
                    return "egress_unknown"
            else:
                self._egress_unknown = 0
                if seen != self.cfg.vantage.public_egress_ip:
                    return "egress_changed"
        return None

    def run(self, name: str, fn: Callable[[], Any], default: Any) -> Any:
        if name == "favicon" and self.phase_gate is not None:
            self.phases.close()                  # phase A ends here; phase B (favicon and write-out) waits for its slot
            try:
                self.phases.enter_context(self.phase_gate("b"))
            except KeyboardInterrupt as exc:
                self.interrupted = True
                self.errors[name] = f"interrupted: {exc}"[:200]
        if self.check_now():
            self.skipped.append(name)
            return default
        t = time.monotonic()
        self.progress()
        print(f"[scanner {self.label}] {name}: start", file=sys.stderr, flush=True)
        try:
            return fn()
        except KeyboardInterrupt as exc:      # Ctrl-C, SIGTERM or SIGHUP (mapped to KeyboardInterrupt)
            self.interrupted = True
            self.errors[name] = f"interrupted: {exc}"[:200]
            self.request_stop("interrupt")        # the handler only flagged it: wake the other threads from here
            return default
        except Exception as exc:
            self.errors[name] = f"{type(exc).__name__}: {exc}"[:500] + " | " + traceback.format_exc().splitlines()[-3].strip()[:200]
            return default
        finally:
            self.timings[name] = round(time.monotonic() - t, 3)
            self.progress()
            print(f"[scanner {self.label}] {name}: {self.timings[name]} s", file=sys.stderr, flush=True)


def _install_signal_handlers(on_signal: Callable[[], None] | None = None) -> Callable[[], None]:
    """SIGTERM/SIGHUP behave like Ctrl-C so tools are killed and the manifest is still written.

    ``on_signal`` runs first, in the handler, so it must not take a lock: it only flags the stop, and the worker
    threads, which never see the exception, are woken by the main thread's unwinding or by the run monitor.
    """
    if threading.current_thread() is not threading.main_thread():
        return lambda: None
    previous = {}

    def handler(signum, _frame):
        if on_signal is not None:
            on_signal()
        raise KeyboardInterrupt(f"signal {signum}")
    for sig in (signal.SIGTERM, getattr(signal, "SIGHUP", None)):
        if sig is None:
            continue
        if sig == getattr(signal, "SIGHUP", None) and signal.getsignal(sig) == signal.SIG_IGN:
            continue                      # started under nohup: the operator asked us to survive a hangup
        try:
            previous[sig] = signal.signal(sig, handler)
        except (ValueError, OSError):
            pass

    def restore() -> None:
        for sig, h in previous.items():
            try:
                signal.signal(sig, h)
            except (ValueError, OSError):
                pass
    return restore


def _register_stack_dump(run_dir: Path) -> Callable[[], None]:
    """SIGUSR1 writes every thread's stack to raw/stacks.txt (POSIX); the file is removed again if it stayed empty."""
    if not hasattr(signal, "SIGUSR1") or not hasattr(faulthandler, "register"):
        return lambda: None
    path = run_dir / "raw" / "stacks.txt"
    try:
        fh = open(path, "w", encoding="utf-8")
        faulthandler.register(signal.SIGUSR1, file=fh, all_threads=True)
    except (OSError, ValueError, RuntimeError):
        return lambda: None

    def release() -> None:
        try:
            faulthandler.unregister(signal.SIGUSR1)
        except (ValueError, RuntimeError):
            pass
        fh.close()
        try:
            if path.stat().st_size == 0:
                path.unlink()
        except OSError:
            pass
    return release


def run(
    cfg: ScanConfig,
    *,
    run_id: str | None = None,
    executor: Executor | None = None,
    fetcher: Any = None,
    skip_preflight: bool = False,
    offline_preflight: bool = False,
    phase_gate: Callable[[str], Any] | None = None,
    resume_from: Path | None = None,
) -> Path:
    """``resume_from``: the run directory (or the ``favicon_records.jsonl`` itself) of an earlier unfinished attempt of
    this shard; the favicon lookups it completed are reused instead of being sent again."""
    if cfg.approval is None:
        raise ConfigError("run requires an authorized config (approval not loaded)")
    started = datetime.now(UTC)
    wall = time.monotonic()
    policy, splan, exclusions = build_policy(cfg)
    shard_tag = f"-s{cfg.shard:03d}of{cfg.shards:03d}" if cfg.shards > 1 else ""
    run_id = run_id or f"scanner-{cfg.run_label}{shard_tag}-{started.strftime('%Y%m%dT%H%M%SZ')}"
    run_dir = Path(cfg.output_dir) / run_id
    if (run_dir / "manifest.json").exists():
        raise ConfigError(f"run directory {run_dir} already holds a run; refusing to mix two runs in one directory")
    for sub in ("raw", "normalized", "report"):
        (run_dir / sub).mkdir(parents=True, exist_ok=True)
    (run_dir / "config.snapshot.json").write_text(json.dumps(cfg.raw, indent=2, sort_keys=True, default=str), encoding="utf-8")

    st = _Stages(cfg, run_dir, guards=not offline_preflight)
    executor = executor or ManagedExecutor(cfg, run_dir, st.killed)
    st.executor = executor
    restore_signals = _install_signal_handlers(lambda: st.flag_stop("interrupt"))
    release_stacks = _register_stack_dump(run_dir)
    st.start_monitor()
    jobs: list[ToolJob] = []
    counts: dict[str, Any] = {}
    try:
        if phase_gate is not None:
            st.phase_gate = phase_gate
            st.phases.enter_context(phase_gate("a"))
        report = pre.run_preflight(cfg, splan, run_dir=run_dir, executor=executor, offline=offline_preflight)
        (run_dir / "preflight.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        if not report["ok"] and not skip_preflight:
            raise pre.PreflightFailed(report)
        return _run_stages(cfg, st, policy, splan, exclusions, run_dir, executor, fetcher, jobs, counts, report,
                           started, wall, run_id, resume_from)
    finally:
        st.phases.close()
        st.stop_monitor()
        release_stacks()
        restore_signals()


def _run_stages(cfg, st, policy, splan, exclusions, run_dir, executor, fetcher, jobs, counts, report, started, wall, run_id,
                resume_from=None) -> Path:
    # What the stages learn about each endpoint goes to disk, not into dictionaries: memory then stays flat in the shard size.
    try:
        store = ShardStore(run_dir / "work" / "facts.sqlite", reset=True)
    except Exception as exc:
        st.errors["store"] = f"{type(exc).__name__}: {exc}"[:500]
        return _bare_manifest(cfg, st, run_dir, counts, started, wall, run_id)
    try:
        return _run_stages_with(store, cfg, st, policy, splan, exclusions, run_dir, executor, fetcher, jobs, counts, report,
                                started, wall, run_id, resume_from)
    except Exception as exc:               # whatever escaped the stages: the run still ends with a manifest
        st.errors["run"] = f"{type(exc).__name__}: {exc}"[:500]
        return _bare_manifest(cfg, st, run_dir, counts, started, wall, run_id)
    finally:
        st.guard("store_close", store.close)


def _bare_manifest(cfg, st, run_dir: Path, counts, started, wall, run_id) -> Path:
    """The manifest of a run that could not get through its write-out: what is known, marked incomplete."""
    manifest = {
        "schema_version": SCHEMA_VERSION, "instrument_version": INSTRUMENT_VERSION, "experiment": "scanner",
        "run_id": run_id, "started_at": started.isoformat(), "finished_at": datetime.now(UTC).isoformat(),
        "elapsed_seconds": round(time.monotonic() - wall, 3), "stage_seconds": st.timings,
        "stage_errors": st.errors, "stages_skipped": st.skipped, "abort_reason": st.reason,
        "status": "finished", "complete": False, "config_checksum": cfg.checksum,
        "approval_reference": cfg.approval.approval_reference if cfg.approval else None,
        "shard": {"index": cfg.shard, "of": cfg.shards}, "stage_counts": counts,
        "output_schema": outputs.OUTPUT_SCHEMA, "limitations": LIMITATIONS,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, default=_jsonable), encoding="utf-8")
    return run_dir


def _run_stages_with(store, cfg, st, policy, splan, exclusions, run_dir, executor, fetcher, jobs, counts, report, started, wall, run_id,
                     resume_from=None) -> Path:
    from scanner.internet.zmap_compat import output_args, packet_rate_args
    killed = st.killed
    pace = cfg.measurement.min_seconds_between_probes_per_ip

    def store_problem() -> str | None:
        """Rows the store lost may include the SYN-ACK windows that flag tarpits: nothing more is sent on that footing."""
        try:
            store.flush()
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}"[:300]
        if store.dropped_rows or store.errors:
            return f"{store.dropped_rows} rows could not be written: " + "; ".join(store.errors[:3])[:300]
        return None

    def target_stage(name: str, fn: Callable[[], Any]) -> Any:
        problem = store_problem()
        if problem:
            st.errors.setdefault("store", problem)
            st.skipped.append(name)
            return None
        return st.run(name, fn, None)
    gap = pacing.Gap(pace, killed, stop_event=st.stop)             # pause between ZMap port runs
    ledger = pacing.ContactLedger(pace, killed, stop_event=st.stop)    # last contact per address, shared by every target-facing step
    gateway_mac = cfg.vantage.gateway_mac or report.get("gateway_mac")
    # Stub manifest before the first probe: if the process is killed hard (OOM, WSL shutdown) the run still
    # leaves evidence of what was started and the run-once guard still sees it.
    (run_dir / "manifest.json").write_text(json.dumps({
        "schema_version": SCHEMA_VERSION, "experiment": "scanner", "run_id": run_id, "status": "started",
        "complete": False, "started_at": started.isoformat(), "config_checksum": cfg.checksum,
        "shard": {"index": cfg.shard, "of": cfg.shards},
        "approval_reference": cfg.approval.approval_reference if cfg.approval else None,
    }, indent=2), encoding="utf-8")
    # A full scan gives ZMap no target count: each shard then covers its whole slice of the allowed space.
    full = cfg.sample_fraction >= 1.0 and not cfg.target_ips
    mview = SimpleNamespace(**{**vars(cfg.measurement), "zmap_max_targets": None if full else splan.targets_per_port,
                                                    "zmap_output_fields": "saddr,window,ttl",
                                                    "zmap_shards": cfg.shards, "zmap_shard": cfg.shard,
                                                    # one sender thread is plenty (and ZMap's default of one per core burns ~12 cores)
                                                    "zmap_sender_threads": 1,
                                                    "zmap_rate": packet_rate_args(cfg.measurement.zmap_version,
                                                        cfg.measurement.zmap_rate, cfg.measurement.zmap_probes),
                                                    "zmap_extra_args": output_args(cfg.measurement.zmap_version)})
    cfgview = SimpleNamespace(vantage=cfg.vantage, measurement=mview, fetch=cfg.fetch)

    # ---- Stage 0: the complete list of sampled targets (ZMap --dryrun prints targets, sends nothing) --
    sample_ips: list[str] = []
    send_order: dict[str, int] = {}       # ZMap's send position of each target (the dry run lists them in order)

    def sample_stage() -> None:
        if splan.targets_per_port > cfg.max_listed_targets:
            counts["sample_listing"] = ("skipped: more than output.max_listed_targets targets in this shard; "
                                        "the seed, shard and fraction in the manifest regenerate the list")
            return
        raw = run_dir / "raw" / "zmap"
        raw.mkdir(parents=True, exist_ok=True)
        allow, block = raw / "sample-allowlist.txt", raw / "sample-blocklist.txt"
        allow.write_text("".join(f"{c}\n" for c in policy.target_cidrs()), encoding="utf-8")
        block.write_text("".join(f"{c}\n" for c in policy.exclusion_cidrs()), encoding="utf-8")
        cmd = ["zmap", "-C", "/dev/null", "-T", "1", "-p", str(cfg.measurement.ports[0]), "-w", str(allow), "-b", str(block),
               "-i", cfg.vantage.interface, "-S", cfg.vantage.source_ipv4, "-r", "100000", "--cooldown-time", "1",
               "--max-runtime", "600", "-O", "csv", "-f", "saddr", "-o", str(raw / "sample-dryrun.csv"),
               "-P", "1", "--seed", str(cfg.measurement.zmap_seed), "--dryrun"]
        if not full:
            cmd += ["-n", str(splan.targets_per_port)]
        cmd += output_args(cfg.measurement.zmap_version)
        if cfg.shards > 1:
            cmd += ["--shards", str(cfg.shards), "--shard", str(cfg.shard)]
        if gateway_mac:
            cmd += ["-G", gateway_mac]
        res = executor(cmd, capture_output=True, text=True, check=False)
        text = (getattr(res, "stdout", "") or "") + (getattr(res, "stderr", "") or "")
        listed = re.findall(r"daddr: (\d+\.\d+\.\d+\.\d+)", text)
        for ip in listed:
            send_order.setdefault(ip, len(send_order))
        found = sorted(set(listed), key=lambda x: tuple(int(o) for o in x.split(".")))
        sample_ips.extend(ip for ip in found if policy.check_ip(ip, stage="zmap", context="sample_list") is None)
        expected = splan.targets_per_port
        # Shards of a full scan are slices of ZMap's permutation, so their sizes vary a little around the even share.
        low, high = (0.9, 1.1) if full and cfg.shards > 1 else (0.99, 1.0001)
        if st.guards and not expected * low <= len(sample_ips) <= expected * high + 1:
            # Live runs only: a dry run that does not reproduce the plan means -n / --shards / the allowlist is not
            # doing what we think, so nothing is scanned. (The dry run sends nothing.)
            st.reason = "sample_list_mismatch"
            st.errors["sample_list"] = f"dry run listed {len(sample_ips)} targets, the plan expects {expected}"
        (run_dir / "scanned_ips.txt").write_text("".join(f"{ip}\n" for ip in sample_ips), encoding="utf-8")

    st.run("sample_list", sample_stage, None)
    counts["sample_listed"] = len(sample_ips)

    # ---- Stage 1: ZMap L4 discovery (same seed -> same sample on every port) ----------------
    m = cfg.measurement
    tiny = cfg.tarpit.tiny_window_below
    dns_kw = dict(nameservers=list(cfg.dns.resolvers), run_dir=run_dir, threads=cfg.dns.threads, timeout=cfg.dns.timeout,
                  retries=cfg.dns.retries, network_timeout=cfg.dns.network_timeout, binary=cfg.binaries.zdns, executor=executor)
    # PTR goes to the resolvers, never to the targets: each port's new addresses are looked up while ZMap sweeps the next.
    ptr_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ptr")
    ptr_early: list[Any] = []       # one future per port, in port order

    def ptr_lookup(addresses: list[str]) -> list[ToolJob]:
        """One PTR batch. The answers go straight to the store; if it fails the addresses count as not sent again."""
        try:
            wanted = set(addresses)
            j, part = run_zdns("PTR", addresses, **dns_kw)
            store.put_ptr_many((ip, ptr_names(a), a.status) for ip, a in part.items() if ip in wanted)
        except BaseException:
            store.unmark_ptr_sent(addresses)
            raise
        return j

    gate: ovl.OverlapGate | None = None
    tls_ports: queue.Queue[int | None] = queue.Queue()
    if m.overlap_tls_with_zmap:
        if send_order:
            gate = ovl.OverlapGate(ovl.ZmapProgress(m.zmap_probes), send_order, sweeps_total=len(m.ports),
                                   rate_targets=m.zmap_rate / m.zmap_probes, pace=pace)
            counts["overlap"] = {"enabled": True, "traffic": "outbound traffic during the sweep is the ZMap rate plus the "
                                 "concurrent ZGrab2 TLS connections"}
        else:
            counts["overlap"] = {"enabled": False, "reason": "no ZMap send order: the sample listing was skipped or failed"}

    def zmap_stage() -> None:
        for port in m.ports:
            if killed():
                st.skipped.append(f"zmap:{port}")
                continue
            # Every port probes the same seeded sample, so a pause between port runs keeps one address's SYNs apart.
            if not gap.wait():
                st.skipped.append(f"zmap:{port}")
                continue
            status = run_dir / "raw" / "zmap" / f"status-{port}.csv" if gate else None
            if gate:
                gate.progress.start_sweep(status)
            try:
                job, res = run_zmap(cfgview, policy, port, run_dir, executor=executor, gateway_mac=gateway_mac, status_file=status)
            except Exception as exc:
                st.errors[f"zmap:{port}"] = f"{type(exc).__name__}: {exc}"[:500]
                continue
            finally:
                gap.mark()
                if gate:
                    gate.progress.end_sweep()
            jobs.append(job)
            st.progress()
            if job.error:
                st.errors[f"zmap:{port}"] = job.error[:500]
            ips = sorted({r.target_ip for r in res})
            store.put_endpoints((ip, port) for ip in ips)
            try:
                store.put_synack_port(port, enrich.parse_synack_csv((run_dir / job.raw_path).read_text(encoding="utf-8", errors="replace")))
            except OSError:
                pass
            new = store.mark_ptr_sent(ips)
            if new:
                ptr_early.append(ptr_pool.submit(ptr_lookup, new))
            if gate:
                tls_ports.put(port)

    # ---- Stage 2: TLS first, direct IP (no SNI) ---------------------------------------------
    tls_jobs: list[ToolJob] = []
    # With overlap a batch must end by a known time: the gate leaves room for that, and the executor enforces it.
    tls_limit = m.zgrab_connect_timeout + m.zgrab_target_timeout + 15

    def tls_runner(timeout: float | None = None) -> Callable[[list], Any]:
        def one(batch):
            batch_jobs, results = tlsmod.run_tls_batches(batch, mode="direct_ip", cfg=cfgview, policy=policy, run_dir=run_dir,
                                                         binary=cfg.binaries.zgrab2, executor=executor, timeout=timeout)
            store.put_tls_many(results)
            st.progress()
            return batch_jobs
        return one

    def collect_tls(out: list[Any]) -> None:
        for batch_jobs in out:
            tls_jobs.extend(batch_jobs)

    def tls_stage() -> None:
        items = [(ip, port, None) for ip, port in store.iter_endpoints() if ip not in tarpit_ips]
        collect_tls(pacing.paced_batches(items, lambda t: t[0], ledger, tls_runner(), batch_size=m.zgrab_batch_size,
                                         workers=m.zgrab_parallel_batches))

    def tls_overlap_stage() -> None:
        assert gate is not None
        size = max(1, min(m.zgrab_batch_size, m.zgrab_senders))      # every target of a batch in flight at once
        while (port := tls_ports.get()) is not None:
            if killed():
                continue
            problem = store_problem()
            if problem:
                st.errors.setdefault("store", problem)
                st.skipped.append(f"tls_direct:{port}")
                continue
            # Tarpits seen on the ports swept so far are left alone; one flagged only on a later port is counted below.
            skip = store.tarpit_ips(tiny)
            # ZMap's own order: neighbours in a batch become due together
            items = sorted(((ip, port, None) for ip, _ in store.iter_endpoints(port) if ip not in skip),
                           key=lambda t: (send_order.get(t[0], 1 << 62), t[0]))
            collect_tls(pacing.paced_batches(items, lambda t: t[0], ledger, tls_runner(tls_limit), batch_size=size,
                                             workers=m.zgrab_parallel_batches,
                                             extra=lambda b: gate.admit([t[0] for t in b], tls_limit + 10)))
            del items

    tls_thread = None
    if gate:
        tls_thread = threading.Thread(target=st.run, args=("tls_direct", tls_overlap_stage, None), name="tls-overlap", daemon=True)
        tls_thread.start()
    try:
        st.run("zmap", zmap_stage, None)
    finally:
        if gate:
            tls_ports.put(None)    # first: whatever fails below, the overlap thread must be told to finish
        st.guard("ledger", ledger.mark_all)          # the sweep touched every sampled address: the pause counts from its end
        if gate:
            st.guard("overlap_progress", gate.progress.finish)
            counts["overlap"]["tls_endpoints_during_sweep"] = st.guard("store:count_tls", store.count_tls)
    while tls_thread is not None and tls_thread.is_alive():
        try:
            tls_thread.join(0.5)
        except KeyboardInterrupt as exc:      # signals reach the main thread only; the tool is stopped via killed()
            st.interrupted = True
            st.errors.setdefault("tls_direct", f"interrupted: {exc}"[:200])
    by_port = st.guard("store:count_endpoints_by_port", store.count_endpoints_by_port, {})
    counts["l4_per_port"] = {str(p): by_port.get(p, 0) for p in m.ports}
    counts["l4_endpoints"] = st.guard("store:count_endpoints", store.count_endpoints, 0)
    counts["l4_unique_ips"] = st.guard("store:count_unique_ips", store.count_unique_ips, 0)
    # An address whose SYN-ACK advertises a zero or tiny TCP window is a tarpit: it holds connections open on purpose.
    # It stays in the results (flagged) but receives nothing beyond the ZMap SYN.
    # If the list cannot be read it stays None, and nothing more is sent to the sampled addresses on the strength of it.
    tarpit_ips = st.guard("store:tarpit_ips", lambda: store.tarpit_ips(tiny))
    counts["tarpit_ips_not_probed"] = 0 if tarpit_ips is None else st.guard(
        "store:iter_ip_names", lambda: sum(1 for ip in store.iter_ip_names() if ip in tarpit_ips), 0)
    counts["sample_targets_per_port"] = splan.targets_per_port

    if gate:
        counts["overlap"]["zmap_status_readings"] = gate.progress.readings
        # A tarpit flagged only on a later port may already have had a handshake. Its result is dropped so no
        # later step contacts it again; the handshake stays in the raw ZGrab2 output and the tool jobs.
        late = [] if tarpit_ips is None else st.guard("store:delete_tls_for_ips", lambda: store.delete_tls_for_ips(tarpit_ips), [])
        counts["overlap"]["tarpit_ips_probed_before_flagged"] = len({ip for ip, _ in late})
    elif tarpit_ips is not None:
        target_stage("tls_direct", tls_stage)
    else:
        st.skipped.append("tls_direct")
    jobs.extend(tls_jobs)

    # ---- Stage 3: plain HTTP only where TLS did not prove the port speaks TLS ---------------
    def http_stage() -> None:
        targets = [ZGrabTarget(ip, None, port) for ip, port in store.iter_endpoints_with_tls_outcome(HTTP_FALLBACK)]
        def one(batch):
            batch_jobs, results = run_zgrab_batches(batch, scheme="http", mode="direct_ip", cfg=cfgview, policy=policy,
                                                    run_dir=run_dir, executor=executor)
            store.put_http_many(results)
            st.progress()
            return batch_jobs
        for batch_jobs in pacing.paced_batches(targets, lambda t: t.ip, ledger, one, batch_size=m.zgrab_batch_size,
                                               workers=m.zgrab_parallel_batches):
            jobs.extend(batch_jobs)

    def tarpits_known(name: str, fn: Callable[[], Any]) -> Any:
        if tarpit_ips is None:             # overlap mode reaches here without the late-flag cleanup having run
            st.errors.setdefault("tarpit_ips", "the tarpit list could not be read; no further target-facing stage was run")
            st.skipped.append(name)
            return None
        return target_stage(name, fn)

    tarpits_known("http_direct", http_stage)

    # ---- Stage 4: PTR via ZDNS for every responsive IP --------------------------------------
    def ptr_stage() -> None:
        for future in ptr_early:                    # port order, so the job list does not depend on timing
            try:
                jobs.extend(future.result())
            except Exception as exc:
                counts["ptr_early_failed"] = f"{type(exc).__name__}: {exc}"[:300]     # its addresses are asked again below
        missing = list(store.iter_unsent_ptr_ips())
        if missing:
            j, part = run_zdns("PTR", missing, **dns_kw)
            jobs.extend(j)
            wanted = set(missing)
            store.put_ptr_many((ip, ptr_names(a), a.status) for ip, a in part.items() if ip in wanted)
        store.fill_missing_ptr()

    try:
        st.run("ptr", ptr_stage, None)
    finally:
        ptr_pool.shutdown(wait=True, cancel_futures=True)

    # ---- Stage 5: hostname candidates = PTR U cert SAN/CN ----------------------------------
    def cand_stage() -> None:
        for g in store.iter_ips():
            for e in g.endpoints:
                store.put_names(g.ip, e.port, cand.build_endpoint_names(
                    g.ptr_names, e.tls.certificate if e.tls else None, policy, max_candidates=cfg.max_candidates_per_ip,
                    operator_names=cfg.target_hostnames))

    st.run("candidates", cand_stage, None)      # an endpoint without an entry reads as having no names

    # ---- Stage 6: forward verification via ZDNS (A + AAAA, CNAME chains) -------------------
    def dns_stage() -> None:
        names = list(store.iter_candidate_names())
        if not names:
            return
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="dns") as pool:     # resolver traffic only
            fa, fb = pool.submit(run_zdns, "A", names, **dns_kw), pool.submit(run_zdns, "AAAA", names, **dns_kw)
            (ja, a_ans), (jb, aaaa_ans) = fa.result(), fb.result()
        jobs.extend(ja)
        jobs.extend(jb)
        store.put_resolutions(resolve(n, a_ans.get(n), aaaa_ans.get(n), max_cnames=cfg.dns.max_cnames) for n in names)
        share = enrich.dns_unknown_share_of_counts(store.resolution_status_counts())
        counts["dns_unknown_share"] = round(share, 4)
        if len(names) >= 20 and share > 0.10:
            # Rate limiting or an unhealthy resolver would otherwise quietly turn real names into "unverified".
            st.errors["dns_degraded"] = f"{share:.0%} of {len(names)} forward lookups got no usable answer (servfail/timeout/tool error)"

    st.run("dns_forward", dns_stage, None)

    # ---- Stage 7: optional SNI confirmation (batched, verified names only) -----------------
    def sni_stage() -> None:
        targets: list[tuple[str, int, str | None]] = []
        for g in store.iter_ips():
            skipped: list[tuple[str, int, str, str]] = []
            for e in g.endpoints:
                t = e.tls
                for i, h in enumerate(_verified_names(g, e)):
                    if not cfg.sni_confirm.enabled:
                        skipped.append((g.ip, e.port, h, "disabled"))
                    elif t is None or t.outcome in (tlsmod.NOT_TLS, tlsmod.CONNECT_TIMEOUT):
                        skipped.append((g.ip, e.port, h, "port_not_tls"))
                    elif i >= cfg.sni_confirm.max_per_endpoint:
                        skipped.append((g.ip, e.port, h, "cap"))
                    else:
                        targets.append((g.ip, e.port, h))
            store.put_sni_skipped_many(skipped)
        if not targets:
            return
        def one(batch):
            batch_jobs, results = tlsmod.run_tls_batches(batch, mode="hostname_aware", cfg=cfgview, policy=policy, run_dir=run_dir,
                                                         binary=cfg.binaries.zgrab2, executor=executor)
            for r in results:
                if r.ip and r.sni:
                    store.put_sni(r)
            st.progress()
            return batch_jobs
        for batch_jobs in pacing.paced_batches(targets, lambda t: t[0], ledger, one, batch_size=m.zgrab_batch_size,
                                               workers=m.zgrab_parallel_batches):
            jobs.extend(batch_jobs)

    tarpits_known("sni_confirm", sni_stage)

    # ---- Stage 8: favicon acquisition (HTTP and HTTPS), bounded, sample-and-port-confined ---
    offhost_log: list[dict[str, Any]] = []

    def favicon_stage() -> None:
        if not cfg.favicon.enabled:
            return
        fjobs: list[dict[str, Any]] = []
        job_ips: set[str] = set()
        job_endpoints: set[tuple[str, int]] = set()
        for g in store.iter_ips():
            for e in g.endpoints:
                proto = _protocol_of(e)
                first = len(fjobs)
                # A bare-IP request only makes sense where a bare-IP session works; a host that answered
                # only with SNI would just fail (and record a misleading direct-IP failure).
                if proto == "http" or (proto == "https" and e.tls.ok):
                    fjobs.append({"scheme": proto, "ip": g.ip, "port": e.port, "hostname": None})
                for h in _verified_names(g, e)[: cfg.favicon.max_hostnames_per_endpoint]:
                    sni = e.sni.get(h)
                    if proto == "http":
                        scheme = "http"
                    elif proto == "https" and (e.tls.ok or (sni is not None and sni.ok)):
                        scheme = "https"
                    else:
                        continue
                    fjobs.append({"scheme": scheme, "ip": g.ip, "port": e.port, "hostname": h})
                # Unverified names: same scanned ip:port, just a different Host/SNI. Recorded as unverified in the rows.
                if proto in ("http", "https", "tls_unestablished"):
                    for h in _unverified_names(g, e)[: cfg.favicon.max_unverified_names_per_endpoint]:
                        fjobs.append({"scheme": "http" if proto == "http" else "https", "ip": g.ip, "port": e.port, "hostname": h})
                        counts["favicon_jobs_unverified_names"] = counts.get("favicon_jobs_unverified_names", 0) + 1
                if len(fjobs) > first:
                    job_ips.add(g.ip)
                    job_endpoints.add((g.ip, e.port))
        if not fjobs or not ledger.wait(job_ips):
            return
        fp = fav.fetch_policy(cfg, sorted(job_ips))
        deadline = time.monotonic() + cfg.favicon.stage_max_seconds

        def stop() -> bool:
            return killed() or time.monotonic() > deadline
        # The fetcher and the pacer see the stage deadline too: workers left behind at the cap must not go on to
        # the remaining icons of their page.
        pacer = pacing.IpPacer(pace, stop, stop_event=st.stop)       # pause between HTTP requests to one address
        f = fetcher or fav.make_fetcher(cfg, fp, fav.RedirectResolver(cfg.dns.resolvers, cfg.dns.timeout),
                                        job_endpoints, exclusions=exclusions, killed=stop,
                                        state_path=Path(cfg.output_dir) / f"campaign-{cfg.checksum[:12]}" / "offhost_state.json", pacer=pacer)
        icons = icon_store.IconStore(run_dir / "favicons") if cfg.favicon.store_images else None
        record_log = fav.RecordLog(run_dir / "raw" / "favicon_records.jsonl")
        earlier = record_log.load()
        carried = _earlier_attempt_records(resume_from, earlier, fjobs)
        for rec in carried:                 # logged again here: a second crash must not lose them with this attempt
            record_log.append(rec)
            earlier[(rec["ip"], rec["port"], rec.get("hostname"))] = rec
        if earlier:
            counts["favicon_lookups_resumed"] = len(earlier)
        try:
            # every record, reused ones included, goes to the store with its position in the job list
            fav.run_favicon_stage(f, fjobs, workers=cfg.favicon.workers, max_icons=cfg.favicon.max_icons_per_page, killed=stop,
                                  icon_store=icons, on_record=lambda rec: (record_log.append(rec), st.progress()), done=earlier,
                                  record_sink=store.put_favicon)
            skipped = store.count_favicon_outcome("skipped_kill_switch")
            if time.monotonic() > deadline and skipped:
                st.errors["favicon_deadline"] = f"stage cap of {cfg.favicon.stage_max_seconds} s reached; {skipped} of {len(fjobs)} lookups skipped"
        finally:
            # each step on its own: one failing must neither replace the error being handled nor skip the others
            st.guard("favicon_records_close", record_log.close)
            if record_log.dropped:
                counts["favicon_records_dropped"] = record_log.dropped
                st.errors.setdefault("favicon_records", f"{record_log.dropped} lookup records were not logged for resume")
            if icons is not None:
                def index_icons() -> None:
                    counts["favicon_images_stored"] = len(icons)
                    counts["favicon_images_indexed"] = icons.write_index(store.iter_favicons(), spool=run_dir / "work" / "icon-index.sqlite")
                st.guard("favicon_icon_index", index_icons)
            offhost = getattr(f, "offhost", None)
            st.guard("favicon_offhost_state", getattr(offhost, "save_state", lambda: None))

            def count_offhost() -> None:
                third_party = getattr(offhost, "log", None)
                if third_party:
                    offhost_log.extend(third_party)
                    sent = [e for e in third_party if not e["cached"] and e["outcome"] != "policy_refused"]
                    counts["offhost_icon_requests"] = len(sent)
                    counts["offhost_icon_logged"] = len(third_party)
                    counts["offhost_icon_refused"] = sum(1 for e in third_party if e["outcome"] == "policy_refused")
            st.guard("favicon_offhost_log", count_offhost)

    tarpits_known("favicon", favicon_stage)
    st.check_now()          # a stop that arrived after the last check still belongs in the manifest

    # ---- Records (never allowed to prevent the manifest from being written) ----------------
    tool_errors = [j.job_id for j in jobs if j.error]      # tools that crashed or exited non-zero
    incomplete = bool(st.errors or st.skipped or tool_errors)
    normalized = run_dir / "normalized"
    checksums: dict[str, str] = {}
    tally = _SummaryTally()
    streamed: dict[str, str] = {}
    try:
        streamed = _write_records(cfg, store, normalized, incomplete, tally, st.progress)
    except Exception as exc:
        st.errors["write_outputs" if isinstance(exc, OSError) else "records"] = f"{type(exc).__name__}: {exc}"[:500]
    if {"records", "write_outputs"} & set(st.errors):
        # the per-address rows it reads were not all parked: every missing one would read as "responsive=no"
        st.errors["ip_results"] = "not written: the records write-out failed"
    else:
        try:
            _write_ip_results(run_dir / "ip_results.csv", sample_ips, store)
        except Exception as exc:
            st.errors["ip_results"] = f"{type(exc).__name__}: {exc}"[:500]
    try:
        if streamed:
            checksums["normalized/endpoints.jsonl"] = streamed["endpoints"]
            checksums["normalized/hostname_resolution.jsonl"] = streamed["hostnames"]
        checksums["normalized/tool_jobs.jsonl"] = write_jsonl(normalized / "tool_jobs.jsonl", jobs)
        if cfg.favicon.offhost.enabled:
            checksums["normalized/offhost_icon_fetches.jsonl"] = write_jsonl(normalized / "offhost_icon_fetches.jsonl", offhost_log)
        checksums["normalized/policy_refusals.jsonl"] = write_jsonl(normalized / "policy_refusals.jsonl", [r.as_dict() for r in policy.refusals])
    except Exception as exc:
        st.errors["write_outputs"] = f"{type(exc).__name__}: {exc}"[:500]
    st.guard("store_close", store.close)          # the final flush; what it or any earlier write lost is counted, not hidden
    if store.dropped_rows:
        counts["store_dropped_rows"] = store.dropped_rows
        st.errors.setdefault("store", f"{store.dropped_rows} rows could not be written: " + "; ".join(store.errors[:3])[:300])
    if not {"records", "ip_results", "write_outputs"} & set(st.errors):
        store.delete()                  # kept after a failed write-out, for diagnosis; never part of the listed outputs
        shutil.rmtree(run_dir / "work", ignore_errors=True)
    for p in sorted(run_dir.rglob("*")):
        rel = str(p.relative_to(run_dir)).replace("\\", "/")
        if p.is_file() and p.name not in ("manifest.json", "stacks.txt") and "report" not in p.parts and rel.split("/")[0] != "work":
            if rel not in checksums:            # the streamed outputs were hashed as they were written
                checksums[rel] = sha256_file(p)

    incomplete = bool(st.errors or st.skipped or tool_errors)      # again: the writers above may just have failed
    summary = _summarize(cfg, splan, tally, counts, st, jobs)
    (run_dir / "report" / "summary.json").write_text(json.dumps(summary, indent=2, default=_jsonable), encoding="utf-8")
    (run_dir / "report" / "summary.md").write_text(_summary_md(summary), encoding="utf-8")
    checksums["report/summary.json"] = sha256_file(run_dir / "report" / "summary.json")

    finished = datetime.now(UTC)
    manifest = {
        "schema_version": SCHEMA_VERSION, "instrument_version": INSTRUMENT_VERSION, "experiment": "scanner",
        "run_id": run_id, "started_at": started.isoformat(), "finished_at": finished.isoformat(),
        "elapsed_seconds": round(time.monotonic() - wall, 3), "stage_seconds": st.timings,
        "stage_errors": st.errors, "stages_skipped": st.skipped, "abort_reason": st.reason,
        "anonymous_traffic": cfg.transparency.anonymous,
        "status": "finished", "complete": not (incomplete or st.reason or st.interrupted), "tool_job_errors": tool_errors,
        # "nothing answered" is only a finding when ZMap actually ran cleanly on every port
        "zero_responsive": counts.get("l4_endpoints", 0) == 0 and st.reason is None and not st.errors,
        "config_checksum": cfg.checksum, "approval_reference": cfg.approval.approval_reference if cfg.approval else None,
        "approval_sha256": cfg.approval_sha256, "approval_valid_until": cfg.approval.valid_until.isoformat() if cfg.approval else None,
        "exclusions_sha256": cfg.exclusions_sha256, "exclusion_count": len(exclusions),
        "shard": {"index": cfg.shard, "of": cfg.shards, "total_targets": splan.total_targets},
        "sample": {"fraction": cfg.sample_fraction, "seed": cfg.sample_seed, "target_ips": list(cfg.target_ips),
                   "target_hostnames": list(cfg.target_hostnames), "allowed_addresses": splan.allowed_addresses,
                   "targets_per_port": splan.targets_per_port, "ports": list(splan.ports), "rate_pps": splan.rate,
                   "probes": splan.probes, "population_cidrs": len(splan.population)},
        "vantage": {"id": cfg.vantage.id, "interface": cfg.vantage.interface, "source_ipv4": cfg.vantage.source_ipv4,
                    "gateway_mac": gateway_mac,
                    "public_egress_ip": cfg.vantage.public_egress_ip},
        "parameters": {"dns_resolvers": list(cfg.dns.resolvers), "dns_threads": cfg.dns.threads, "dns_timeout": cfg.dns.timeout,
                       "zmap_version": cfg.measurement.zmap_version, "zmap_cli_rate": mview.zmap_rate,
                       "zmap_sender_threads": 1,
                       "dns_network_timeout": cfg.dns.network_timeout, "dns_retries": cfg.dns.retries,
                       "zgrab_senders": cfg.measurement.zgrab_senders, "zgrab_batch_size": cfg.measurement.zgrab_batch_size,
                       "zgrab_parallel_batches": cfg.measurement.zgrab_parallel_batches,
                       "overlap_tls_with_zmap": cfg.measurement.overlap_tls_with_zmap,
                       "min_seconds_between_probes_per_ip": cfg.measurement.min_seconds_between_probes_per_ip,
                       "zgrab_connect_timeout": cfg.measurement.zgrab_connect_timeout, "zgrab_target_timeout": cfg.measurement.zgrab_target_timeout,
                       "max_candidates_per_ip": cfg.max_candidates_per_ip, "sni_confirm": vars(cfg.sni_confirm),
                       "favicon": vars(cfg.favicon), "fetch": vars(cfg.fetch),
                       **({"pipeline": getattr(st.phase_gate, "depth", 2)} if st.phase_gate is not None else {})},
        "tools": report.get("tool_versions", {}), "stage_counts": counts, "tool_job_counts": _job_counts(jobs),
        "output_schema": outputs.OUTPUT_SCHEMA, "compression": outputs.COMPRESSION,
        **({"compression_note": outputs.COMPRESSION_NOTE} if outputs.COMPRESSION_NOTE else {}),
        "output_checksums": checksums, "limitations": LIMITATIONS,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, default=_jsonable), encoding="utf-8")
    return run_dir


LIMITATIONS = (
    "Single vantage, single observation window; results describe what this vantage could observe at that time.",
    "Hostname evidence is PTR plus certificate SAN/CN only; no CT, passive DNS, ASN or brand matching.",
    "A verified mapping means the name resolved to the scanned IP via the configured resolvers at query time.",
    "Wildcard certificate names are recorded as evidence but never queried.",
    "ZMap loss and rate limiting can miss responsive hosts; the sample is a seeded random subset of IPv4.",
    "Favicons are fetched only from scanned IPs and only on ports that answered the scan; other redirect targets are refused.",
    "The sample is the first N targets of ZMap's seeded permutation of the allowed space: well spread, but not documented as a simple random sample.",
    "protocol=https means a TLS handshake completed (bare IP or with SNI); it does not prove the service speaks HTTP.",
    "Approval rate limits cover ZMap packets only; ZGrab2, ZDNS and favicon concurrency are bounded by configuration, not by the approval.",
)


def _job_counts(jobs: list[ToolJob]) -> dict[str, int]:
    out: dict[str, int] = {}
    for j in jobs:
        out[j.tool] = out.get(j.tool, 0) + 1
    return out


def _cert_fields(t: tlsmod.TlsResult | None) -> dict[str, Any]:
    c = t.certificate if t else None
    return {
        "certificate_present": c is not None,
        "certificate_sha256": c.sha256 if c else None,
        "certificate_cn": c.subject_cn if c else None,
        "certificate_sans": list(c.san_dns[:50]) if c else [],
        "certificate_san_count": len(c.san_dns) if c else 0,
        "certificate_not_before": c.not_before if c else None,
        "certificate_not_after": c.not_after if c else None,
        "certificate_self_signed": c.self_signed if c else None,
        "certificate_expired": c.expired_at_observation if c else None,
        "certificate_not_yet_valid": c.not_yet_valid_at_observation if c else None,
        "certificate_parse_error": t.cert_parse_error if t else None,
    }


def _protocol_of(e: EndpointFacts) -> str:
    t = e.tls
    if t is None:
        return "not_attempted"
    if t.ok or e.sni_ok:
        return "https"                       # a TLS session was established (bare IP, or with SNI)
    if t.outcome in TLS_PROVEN:
        return "tls_unestablished"           # speaks TLS but wants a name we do not (yet) have
    h = e.http
    if h is not None and h.http_status is not None:
        return "http"
    return "tcp_only"


def _dns_status(g: IpFacts, host: str) -> str:
    return cand.judge_dns(g.resolutions.get(host), g.ip)


def _verified_names(g: IpFacts, e: EndpointFacts) -> list[str]:
    """Verified names for an endpoint, best-corroborated first: several sources, then PTR, then alphabetical."""
    names = e.names.names
    ok = [h for h in names if _dns_status(g, h) in cand.VERIFIED]
    return sorted(ok, key=lambda h: (-len(names[h]), cand.SRC_PTR not in names[h], h))


def _unverified_names(g: IpFacts, e: EndpointFacts) -> list[str]:
    """Candidate names that did NOT verify, best-corroborated first. Used only as Host/SNI on the scanned IP."""
    names = e.names.names
    bad = [h for h in names if _dns_status(g, h) not in cand.VERIFIED]
    return sorted(bad, key=lambda h: (-len(names[h]), cand.SRC_PTR not in names[h], h))


def _ip_rows(cfg, g: IpFacts, asn, incomplete: bool) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The endpoint rows and hostname rows of one address (ascending port), as they appear in the output files."""
    rows: list[dict[str, Any]] = []
    ep_rows: list[dict[str, Any]] = []
    tarpit = enrich.tarpit_assessment(
        [{"protocol": _protocol_of(e), "window": e.synack_window,
          "doc_sha256": (e.favicons.get(None) or {}).get("document_body_sha256"), "doc_status": (e.favicons.get(None) or {}).get("http_status")}
         for e in g.endpoints],
        len(cfg.measurement.ports), cfg.tarpit.min_open_ports, cfg.tarpit.tiny_window_below)
    ip = g.ip
    for e in g.endpoints:
        port = e.port
        t = e.tls
        h = e.http
        names = e.names
        direct_fav = e.favicons.get(None) or {}
        protocol = _protocol_of(e)
        base: dict[str, Any] = {
            "target_ip": ip, "port": port, "zmap_result": "synack",
            **(asn.lookup(ip) if asn else asn_context.empty_fields()),
            "protocol": protocol, **tarpit,
            "synack_window": e.synack_window, "synack_ttl": e.synack_ttl,
            "tls_status": "success" if t and t.ok else ("not_tls" if t and t.outcome == tlsmod.NOT_TLS else ("failed" if t else "not_attempted")),
            "tls_outcome": t.outcome if t else None,
            "tls_failure_reason": None if (t is None or t.ok) else t.error,
            "tls_version": t.tls_version if t else None, "tls_cipher": t.cipher_suite if t else None,
            **_cert_fields(t),
            "certificate_wildcards": sorted(names.wildcards),
            "http_zgrab_status": h.status if h else None, "http_status": h.http_status if h else None,
            "http_location": h.location if h else None, "http_error": h.error if h else None,
            "ptr_status": g.ptr_status, "ptr_names": g.ptr_names[:20], "ptr_name_count": len(g.ptr_names),
            "run_incomplete": incomplete,
            "candidate_names_total": names.source_count, "candidate_names_truncated": names.truncated,
            "dropped_names": names.dropped[:50],
            "direct_favicon_outcome": direct_fav.get("favicon_outcome"), "direct_favicon_is_image": bool(direct_fav.get("favicon_is_image")),
            "direct_favicon_sha256": direct_fav.get("favicon_sha256"), "direct_favicon_file": direct_fav.get("favicon_file"),
            "direct_favicon_mmh3": direct_fav.get("favicon_mmh3"), "direct_favicon_md5": direct_fav.get("favicon_md5"), "direct_favicon_url": direct_fav.get("favicon_url"),
            "direct_document_outcome": direct_fav.get("document_outcome"), "direct_document_status": direct_fav.get("http_status"),
            "direct_document_title": direct_fav.get("document_title"), "direct_document_body_sha256": direct_fav.get("document_body_sha256"),
            "direct_icon_declared_count": direct_fav.get("icon_declared_count"), "direct_icon_offhost_hosts": direct_fav.get("icon_offhost_hosts") or [],
            "direct_icon_embedded_images": direct_fav.get("icon_embedded_images"),
        }
        ep_rows.append({**base, "hostnames": sorted(names.names)})
        if not names.names:
            rows.append({**base, "hostname": None, "hostname_sources": [], "dns_status": None, "cname_chain": [],
                         "a_answers": [], "aaaa_answers": [], "maps_to_scanned_ip": None,
                         "sni_confirmation_attempted": False, "sni_confirmation_result": None, "sni_confirmation_outcome": None,
                         "sni_skipped_reason": None,
                         "sni_certificate_sha256": None, "sni_certificate_hostname_match": None,
                         "hostname_favicon_outcome": None, "hostname_favicon_is_image": False, "hostname_favicon_sha256": None, "hostname_favicon_file": None, "hostname_favicon_mmh3": None, "hostname_favicon_md5": None,
                         "hostname_favicon_url": None, "hostname_document_title": None, "hostname_icon_offhost_hosts": [],
                         "hostname_icon_embedded_images": None, "final_hostname_status": "no_hostname_evidence", "icon_scope": "none"})
            continue
        for host in sorted(names.names):
            res = g.resolutions.get(host)
            status = _dns_status(g, host)
            sources = names.names[host]
            sni = e.sni.get(host)
            hf = e.favicons.get(host) or {}
            rows.append({
                **base, "hostname": host, "hostname_sources": sorted(sources), "dns_status": status,
                "cname_chain": list(res.cname_chain) if res else [], "a_answers": list(res.a) if res else [],
                "aaaa_answers": list(res.aaaa) if res else [],
                "maps_to_scanned_ip": None if status in DNS_UNKNOWN else status in cand.VERIFIED,
                "sni_skipped_reason": e.sni_skipped.get(host),
                "sni_confirmation_attempted": sni is not None,
                "sni_confirmation_result": _sni_result(sni),
                "sni_confirmation_outcome": sni.outcome if sni else None,
                "sni_certificate_sha256": sni.certificate.sha256 if sni and sni.certificate else None,
                "sni_certificate_hostname_match": sni.certificate.hostname_matches if sni and sni.certificate else None,
                "hostname_favicon_outcome": hf.get("favicon_outcome"), "hostname_favicon_is_image": bool(hf.get("favicon_is_image")),
                "hostname_favicon_sha256": hf.get("favicon_sha256"), "hostname_favicon_file": hf.get("favicon_file"),
                "hostname_favicon_mmh3": hf.get("favicon_mmh3"), "hostname_favicon_md5": hf.get("favicon_md5"), "hostname_favicon_url": hf.get("favicon_url"),
                "hostname_document_title": hf.get("document_title"), "hostname_icon_offhost_hosts": hf.get("icon_offhost_hosts") or [],
                "hostname_icon_embedded_images": hf.get("icon_embedded_images"),
                "final_hostname_status": cand.final_status(status, sources),
                # a name that does not verify describes the scanned address, never the domain
                "icon_scope": _icon_scope(cand.final_status(status, sources) == "verified", bool(hf.get("favicon_is_image"))),
            })
    return ep_rows, rows


def _icon_scope(verified: bool, is_image: bool) -> str:
    """domain_verified: the name resolves to this address; served_at_ip: an icon came back but the name does not verify."""
    if not is_image:
        return "none"
    return "domain_verified" if verified else "served_at_ip"


def _sni_result(sni: Any) -> str | None:
    """confirmed: handshake ok and the certificate covers the name; tls_ok_cert_mismatch: a default/shared cert came back."""
    if sni is None:
        return None
    if not sni.ok:
        return "failed"
    return "confirmed" if sni.certificate is not None and sni.certificate.hostname_matches else "tls_ok_cert_mismatch"


_csv_cell = outputs.csv_cell
_CsvSink = outputs.CsvSink


class _HashedFile:
    """Output file written as UTF-8 text without newline translation; keeps the SHA-256 of what it wrote."""

    def __init__(self, path: Path) -> None:
        self._fh = open(path, "wb")
        self._digest = hashlib.sha256()

    def write(self, text: str) -> int:
        data = text.encode("utf-8")
        self._digest.update(data)
        self._fh.write(data)
        return len(text)

    def hexdigest(self) -> str:
        return self._digest.hexdigest()

    def __enter__(self) -> "_HashedFile":
        return self

    def __exit__(self, *exc: Any) -> None:
        self._fh.close()


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with _HashedFile(path) as out:
        sink = _CsvSink(out)
        for r in rows:
            sink.write(r)


def _write_records(cfg, store: ShardStore, normalized: Path, incomplete: bool, tally: "_SummaryTally",
                   tick: Callable[[], None]) -> dict[str, str]:
    """endpoints.jsonl and hostname_resolution.jsonl in one pass over the store, an address at a time.

    Every row is scrubbed as it is written. The summary tallies and the ip_results rows are gathered on the way, so
    nothing is held beyond the address in hand. The hostname rows are written in their slim form (see ``outputs``).
    Returns the SHA-256 of the two files.
    """
    asn = asn_context.AsnContext(cfg.asn_ipasn) if getattr(cfg, "asn_ipasn", None) else None
    normalized.mkdir(parents=True, exist_ok=True)
    with _HashedFile(normalized / "endpoints.jsonl") as ep_out, _HashedFile(normalized / "hostname_resolution.jsonl") as row_out:
        for g in store.iter_ips(order="string"):
            ep_rows, rows = _ip_rows(cfg, g, asn, incomplete)
            ep_rows, rows = [_scrub(r) for r in ep_rows], [_scrub(r) for r in rows]
            for r in ep_rows:
                ep_out.write(canonical_json(r) + "\n")
            for r in rows:
                row_out.write(canonical_json(outputs.slim_hostname_row(r)) + "\n")
            tally.add(ep_rows, rows)
            store.put_ip_result(g.ip, _ip_result_row(g.ip, ep_rows, rows))
            tick()
    return {"endpoints": ep_out.hexdigest(), "hostnames": row_out.hexdigest()}


IP_RESULT_HEADER = ("ip,responsive,open_ports,endpoints,ptr_names,verified_hostnames,other_hostnames,certificate_cns,tarpit_suspect,"
                    "tarpit_confidence,tarpit_signals,tarpit_reason,document_titles,icon_offhost_hosts,favicon_sha256,unverified_name_favicon_sha256\n")


def _ip_result_row(ip: str, eps: list[dict[str, Any]], rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The ip_results row of one address from its (scrubbed) endpoint rows and hostname rows."""
    hosts = [r for r in rows if r["hostname"]]
    verified = sorted({h["hostname"] for h in hosts if h["final_hostname_status"] == "verified"})
    other = sorted({f'{h["hostname"]}:{h["final_hostname_status"]}' for h in hosts if h["final_hostname_status"] != "verified"})
    return {
        "ip": ip,
        "responsive": "yes" if eps else "no",
        "open_ports": "|".join(str(e["port"]) for e in eps),
        "endpoints": "; ".join(
            f'{e["port"]}={e["protocol"]}' + (f'({e["tls_outcome"]})' if e["tls_outcome"] not in (None, "tls_success") else "")
            + (f'[http {e["http_status"]}]' if e["http_status"] else "") for e in eps),
        "ptr_names": "|".join(sorted({n for e in eps for n in e["ptr_names"]})),
        "verified_hostnames": "|".join(verified),
        "other_hostnames": "|".join(other),
        "certificate_cns": "|".join(sorted({e["certificate_cn"] for e in eps if e["certificate_cn"]})),
        "tarpit_suspect": "yes" if eps and eps[0]["tarpit_suspect"] else "no",
        "tarpit_confidence": (eps[0]["tarpit_confidence"] or "") if eps else "",
        "tarpit_signals": "|".join(eps[0]["tarpit_signals"]) if eps else "",
        "tarpit_reason": (eps[0]["tarpit_reason"] or "") if eps else "",
        "document_titles": "|".join(sorted({e["direct_document_title"] for e in eps if e["direct_document_title"]}
                                           | {h["hostname_document_title"] for h in hosts if h["hostname_document_title"]})),
        "icon_offhost_hosts": "|".join(sorted({x for e in eps for x in e["direct_icon_offhost_hosts"]}
                                              | {x for h in hosts for x in h["hostname_icon_offhost_hosts"]})),
        # only real images: the hash of an HTML error page is not a favicon
        "favicon_sha256": "|".join(sorted({e["direct_favicon_sha256"] for e in eps if e["direct_favicon_is_image"] and e["direct_favicon_sha256"]}
                                          | {h["hostname_favicon_sha256"] for h in hosts if h["icon_scope"] == "domain_verified" and h["hostname_favicon_sha256"]})),
        # icons fetched under names that do not verify: they describe the address, so they stay out of favicon_sha256
        "unverified_name_favicon_sha256": "|".join(sorted({h["hostname_favicon_sha256"] for h in hosts if h["icon_scope"] == "served_at_ip" and h["hostname_favicon_sha256"]})),
    }


def _write_ip_results(path: Path, sample_ips: list[str], store: ShardStore) -> None:
    """One row per sampled IP, in address order: did anything answer, on which ports, and what it gave us.

    The rows of the responsive addresses were parked in the store by ``_write_records``; the sampled addresses that
    did not answer are merged in here.
    """
    def key(ip: str) -> tuple[int, ...]:
        return tuple(int(o) for o in ip.split("."))

    silent = sorted(set(sample_ips), key=key)
    keys = [key(ip) for ip in silent]
    n = 0
    with _HashedFile(path) as out:
        sink = _CsvSink(out)
        i = 0
        for ip, row in store.iter_ip_results():
            k = key(ip)
            while i < len(silent) and keys[i] < k:
                sink.write(_ip_result_row(silent[i], [], []))
                n += 1
                i += 1
            if i < len(silent) and keys[i] == k:
                i += 1                      # sampled and responsive: its own row is the one to write
            sink.write(row)
            n += 1
        for ip in silent[i:]:
            sink.write(_ip_result_row(ip, [], []))
            n += 1
    if not n:
        path.write_text(IP_RESULT_HEADER, encoding="utf-8")


def _bump(counts: dict[str, int], value: Any) -> None:
    key = str(value)
    counts[key] = counts.get(key, 0) + 1


class _SummaryTally:
    """The figures of the run summary, accumulated one address at a time from its output rows."""

    def __init__(self) -> None:
        self.protocol: dict[str, int] = {}
        self.tls_outcome: dict[str, int] = {}
        self.final_status: dict[str, int] = {}
        self.dns_status: dict[str, int] = {}
        self.sni_result: dict[str, int] = {}
        self.favicon_direct: dict[str, int] = {}
        self.favicon_hostname: dict[str, int] = {}
        self.tarpit_confidence: dict[str, int] = {}
        self.ips_verified = 0
        self.both = 0
        self.sni_needed = 0
        self.tarpit_suspect = 0
        self.offhost = 0
        self.wildcards = 0

    def add(self, ep_rows: list[dict[str, Any]], rows: list[dict[str, Any]]) -> None:
        named = [r for r in rows if r["hostname"]]
        for r in ep_rows:
            _bump(self.protocol, r["protocol"])
            _bump(self.tls_outcome, r["tls_outcome"])
            if r["direct_favicon_outcome"]:
                _bump(self.favicon_direct, r["direct_favicon_outcome"])
            if r["certificate_wildcards"]:
                self.wildcards += 1
        if any(r["tarpit_suspect"] for r in ep_rows):
            self.tarpit_suspect += 1
        confident = [r for r in ep_rows if r["tarpit_confidence"]]
        if confident:
            _bump(self.tarpit_confidence, confident[-1]["tarpit_confidence"])
        for r in rows:
            _bump(self.final_status, r["final_hostname_status"])
        for r in named:
            _bump(self.dns_status, r["dns_status"])
            if r["sni_confirmation_attempted"]:
                _bump(self.sni_result, r["sni_confirmation_result"])
            if r["hostname_favicon_outcome"]:
                _bump(self.favicon_hostname, r["hostname_favicon_outcome"])
            if {"ptr"} < set(r["hostname_sources"]) and any(x.startswith("certificate") for x in r["hostname_sources"]):
                self.both += 1
        if any(r["final_hostname_status"] == "verified" for r in named):
            self.ips_verified += 1
        sni_ok = {(x["target_ip"], x["port"]) for x in rows if x["sni_confirmation_outcome"] == tlsmod.OK}
        self.sni_needed += sum(1 for r in ep_rows if r["tls_status"] == "failed" and (r["target_ip"], r["port"]) in sni_ok)
        self.offhost += len({(r["target_ip"], r["port"]) for r in ep_rows if r["direct_icon_offhost_hosts"]}
                            | {(r["target_ip"], r["port"]) for r in named if r["hostname_icon_offhost_hosts"]})


def _summarize(cfg, splan, tally: _SummaryTally, counts, st, jobs) -> dict[str, Any]:
    def ordered(d: dict[str, int]) -> dict[str, int]:
        return dict(sorted(d.items()))
    return {
        "counts": counts,
        "protocol_by_endpoint": ordered(tally.protocol),
        "tls_outcome_by_endpoint": ordered(tally.tls_outcome),
        "final_hostname_status_by_row": ordered(tally.final_status),
        "dns_status_by_row": ordered(tally.dns_status),
        "ips_with_verified_hostname": tally.ips_verified,
        "unique_ips": counts.get("l4_unique_ips", 0),
        "hostname_rows_with_ptr_and_certificate": tally.both,
        "tls_failed_but_sni_handshake_ok": tally.sni_needed,
        "sni_confirmation_by_row": ordered(tally.sni_result),
        "favicon_direct_by_endpoint": ordered(tally.favicon_direct),
        "favicon_hostname_by_row": ordered(tally.favicon_hostname),
        "tarpit_suspect_ips": tally.tarpit_suspect,
        "tarpit_ips_by_confidence": ordered(tally.tarpit_confidence),
        "icons_declared_on_other_hosts": tally.offhost,
        "wildcard_certificates": tally.wildcards,
        "stage_seconds": st.timings, "stage_errors": st.errors, "stages_skipped": st.skipped,
        "tool_job_counts": _job_counts(jobs),
        "warnings": _warnings(cfg, splan, counts, st),
    }


def _warnings(cfg, splan, counts, st) -> list[str]:
    out: list[str] = []
    total = counts.get("l4_endpoints", 0)
    listed = counts.get("sample_listed", 0)
    uneven = cfg.sample_fraction >= 1.0 and cfg.shards > 1 and abs(listed - splan.targets_per_port) <= 0.1 * splan.targets_per_port
    if "sample_listing" not in counts and listed != splan.targets_per_port and not st.reason and not uneven:
        out.append(f"sample list has {listed} targets but the plan expected {splan.targets_per_port}; check raw/zmap/sample-*.")
    if st.reason:
        out.append(f"run stopped early ({st.reason}); outputs are partial, see stages_skipped.")
    if total == 0 and not st.reason:
        out.append("ZERO responsive endpoints: check egress/NAT (WSL2), ZMap interface/gateway settings and raw/stderr/*zmap*.txt.")
    elif total:
        for port, n in counts.get("l4_per_port", {}).items():
            rate = n / max(1, splan.targets_per_port)
            if rate < 0.003 and int(port) in (80, 443):
                out.append(f"port {port}: hit rate {rate:.4%} is far below typical Internet rates; scan may be impaired (NAT, loss, filtering).")
    if st.errors:
        out.append(f"{len(st.errors)} stage error(s) recorded; see manifest stage_errors.")
    return out


def _summary_md(s: dict[str, Any]) -> str:
    lines = ["# scanner run summary", ""]
    for k in ("counts", "protocol_by_endpoint", "tls_outcome_by_endpoint", "final_hostname_status_by_row", "dns_status_by_row",
              "sni_confirmation_by_row", "favicon_direct_by_endpoint", "favicon_hostname_by_row", "stage_seconds", "stage_errors"):
        lines += [f"## {k}", "```", json.dumps(s.get(k), indent=2, default=_jsonable), "```", ""]
    for k in ("ips_with_verified_hostname", "unique_ips", "hostname_rows_with_ptr_and_certificate", "tls_failed_but_sni_handshake_ok", "wildcard_certificates",
              "tarpit_suspect_ips", "icons_declared_on_other_hosts"):
        lines.append(f"- {k}: {s.get(k)}")
    lines += ["", "## warnings", *(f"- {w}" for w in s.get("warnings", [])), ""]
    return "\n".join(lines)
