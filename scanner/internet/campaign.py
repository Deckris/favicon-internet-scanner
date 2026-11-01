"""Campaign: one sampled scan run as N independent, resumable shard runs.

Each shard is a complete scanner run over a disjoint slice of the same seeded ZMap permutation, so memory,
disk and the length of any single run stay bounded however large the sample is. Progress lives in
``<output>/campaign-<config checksum>/campaign.json``; running ``campaign`` again skips finished shards and
repeats the one that was interrupted (as a new attempt, in a new run directory).

The campaign stops at the first shard that does not finish cleanly: the kill switch, a changed public IP, low
disk, an expired approval and tool errors all end it, and nothing further is sent until the operator looks.
A file named ``DRAIN`` in the campaign directory ends it more gently: the shard in progress finishes, no further shard starts.
So does too little free disk: a shard starts only while the output disk holds ``disk_floor`` bytes (``operations.min_free_gb_between_shards``),
and a campaign that stops for that reason (reason ``disk``) resumes when the same command is run again with space freed.
A finished shard's record files are compacted to ``.zst`` (see ``outputs.compact_run``); a resumed campaign completes a compaction that was interrupted. With ``output.prune_raw_keep_every`` set, the ``raw/`` directory of a compacted shard is then deleted (``outputs.prune_raw``).
With ``pipeline_depth=2`` the shards run as child processes that overlap (see ``supervisor``); the state file and the stop rules stay the same.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from scanner.internet import outputs, pipeline
from scanner.internet.preflight import PreflightFailed

MERGE_DICTS = ("counts", "protocol_by_endpoint", "tls_outcome_by_endpoint", "final_hostname_status_by_row", "dns_status_by_row",
               "sni_confirmation_by_row", "favicon_direct_by_endpoint", "favicon_hostname_by_row", "tarpit_ips_by_confidence")
MERGE_NUMBERS = ("ips_with_verified_hostname", "unique_ips", "tarpit_suspect_ips", "icons_declared_on_other_hosts",
                 "wildcard_certificates", "hostname_rows_with_ptr_and_certificate", "tls_failed_but_sni_handshake_ok")


def campaign_dir(cfg: Any) -> Path:
    return Path(cfg.output_dir) / f"campaign-{cfg.checksum[:12]}"


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True, default=str), encoding="utf-8")
    tmp.replace(path)                                  # never leave a half-written state file behind


class CampaignLocked(RuntimeError):
    """Another campaign process is working on this configuration."""


def _check_alive(pid: int) -> None:
    """Raise ProcessLookupError when ``pid`` is gone. On Windows ``os.kill(pid, 0)`` would send CTRL_C_EVENT to the
    whole console instead of probing, so the process is opened and its exit code read."""
    if os.name != "nt":
        os.kill(pid, 0)
        return
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel32.OpenProcess(0x1000, False, pid)          # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        if ctypes.get_last_error() == 5:                       # ERROR_ACCESS_DENIED: alive, owned by someone else
            raise PermissionError(pid)
        raise ProcessLookupError(pid)
    try:
        code = wintypes.DWORD()
        if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value != 259:   # STILL_ACTIVE
            raise ProcessLookupError(pid)
    finally:
        kernel32.CloseHandle(handle)


def _acquire_lock(cfg: Any) -> Path:
    """One campaign process per configuration: two would write the same run directory and the same caps file."""
    path = campaign_dir(cfg) / "campaign.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(2):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                pid = int(path.read_text(encoding="utf-8").strip() or 0)
                if pid <= 0:
                    raise ProcessLookupError(pid)      # kill(0) would signal our own process group
                _check_alive(pid)                      # raises if that process is gone
            except (ValueError, ProcessLookupError, PermissionError, OSError) as exc:
                if isinstance(exc, PermissionError):   # exists but belongs to someone else: treat as alive
                    raise CampaignLocked(f"{path} is held by another process") from exc
                path.unlink(missing_ok=True)           # stale lock from a crashed campaign
                continue
            raise CampaignLocked(f"{path} is held by running process {pid}")
        with os.fdopen(fd, "w") as fh:
            fh.write(str(os.getpid()))
        return path
    raise CampaignLocked(f"could not take {path}")


def _prior_complete(cfg: Any, shard: int) -> Path | None:
    """A finished run of this exact config and shard that the state file does not know about (e.g. a manual `run --shard`)."""
    for m in sorted(Path(cfg.output_dir).glob("*/manifest.json")) if Path(cfg.output_dir).is_dir() else []:
        try:
            data = json.loads(m.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        sh = data.get("shard")
        index = sh.get("index", 0) if isinstance(sh, dict) else 0
        if data.get("config_checksum") == cfg.checksum and index == shard and data.get("complete") and not data.get("zero_responsive"):
            return m.parent
    return None


def load_state(cfg: Any) -> dict[str, Any]:
    path = campaign_dir(cfg) / "campaign.json"
    if path.exists():
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise ValueError(f"{path} is unreadable ({exc}); restore it from a copy rather than deleting it, "
                             "or finished shards would be scanned again") from exc
        if state.get("config_checksum") != cfg.checksum or state.get("shards") != cfg.shards:
            raise ValueError("campaign.json belongs to a different configuration")
        return state
    return {"config_checksum": cfg.checksum, "shards": cfg.shards, "created_at": datetime.now(UTC).isoformat(), "shard_states": {}}


def _add(into: dict[str, Any], extra: dict[str, Any]) -> None:
    for key, value in extra.items():
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            into[key] = into.get(key, 0) + value
        elif isinstance(value, dict):
            _add(into.setdefault(key, {}), value)


def merge_summaries(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    """Sum the per-shard tallies. Everything is a count, so the campaign total is the sum over shards."""
    merged: dict[str, Any] = {k: {} for k in MERGE_DICTS}
    merged.update({k: 0 for k in MERGE_NUMBERS})
    for s in summaries:
        for k in MERGE_DICTS:
            _add(merged[k], s.get(k) or {})
        for k in MERGE_NUMBERS:
            merged[k] += s.get(k) or 0
    for k in MERGE_DICTS:
        merged[k] = dict(sorted(merged[k].items()))
    merged["shards_merged"] = len(summaries)
    return merged


def _finish(cfg: Any, state: dict[str, Any], run_dirs: dict[int, Path]) -> None:
    summaries = []
    for i, d in sorted(run_dirs.items()):
        if state["shard_states"].get(str(i), {}).get("status") != "complete":
            continue                                   # a partial shard must not leak into the totals
        try:
            summaries.append(json.loads((d / "report" / "summary.json").read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    _write_json(campaign_dir(cfg) / "campaign_summary.json",
                {"complete": all(state["shard_states"].get(str(i), {}).get("status") == "complete" for i in range(cfg.shards)),
                 "shard_states": state["shard_states"], "merged": merge_summaries(summaries)})


def run_campaign(cfg: Any, *, run_fn: Callable[..., Path] = pipeline.run, log: Callable[[str], None] = print,
                 pipeline_depth: int = 1, config_path: Path | None = None, **run_kwargs: Any) -> dict[str, Any]:
    lock = _acquire_lock(cfg)
    try:
        if pipeline_depth > 1:
            from scanner.internet import supervisor
            supervisor.check_overlap_safe(cfg)
            if not supervisor.available():
                log("[campaign] --pipeline 2 needs POSIX file locks; running the shards one after another")
                pipeline_depth = 1
        if pipeline_depth > 1:
            from scanner.internet import supervisor
            return supervisor.run_overlapped(cfg, log=log, config_path=config_path, **run_kwargs)
        return _run_campaign(cfg, run_fn, log, run_kwargs)
    finally:
        lock.unlink(missing_ok=True)


GIB = 1 << 30
DISK_FIRST_SHARD_GB = 20                     # free space wanted before any shard has finished
DISK_MARGIN_GB = 15                          # on top of twice the largest finished shard


def _shard_bytes(entry: dict[str, Any]) -> int:
    """On-disk size of a finished shard: recorded when it finished, measured (once) for a state file that lacks it."""
    if "disk_bytes" not in entry and entry.get("run_dir") and Path(entry["run_dir"]).is_dir():
        entry["disk_bytes"] = outputs.tree_bytes(entry["run_dir"])
    return int(entry.get("disk_bytes") or 0)


def disk_floor(cfg: Any, state: dict[str, Any]) -> tuple[int, str]:
    """Free bytes a campaign wants before it starts a shard, and how that figure came about."""
    if cfg.min_free_gb_between_shards is not None:
        return int(cfg.min_free_gb_between_shards * GIB), f"operations.min_free_gb_between_shards is {cfg.min_free_gb_between_shards:g} GB"
    sizes = [_shard_bytes(e) for e in state["shard_states"].values() if e.get("status") == "complete"]
    if not any(sizes):
        return DISK_FIRST_SHARD_GB * GIB, f"no shard has finished yet, so {DISK_FIRST_SHARD_GB} GB"
    largest = max(sizes)
    return 2 * largest + DISK_MARGIN_GB * GIB, f"twice the largest finished shard ({largest / GIB:.1f} GB) plus {DISK_MARGIN_GB} GB"


def disk_shortfall(cfg: Any, state: dict[str, Any]) -> str | None:
    """A message naming the shortfall when the output disk holds less than ``disk_floor``, else None."""
    wanted, basis = disk_floor(cfg, state)
    if wanted <= 0:
        return None
    probe = Path(cfg.output_dir)
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    try:
        free = shutil.disk_usage(probe).free
    except OSError:
        return None
    if free >= wanted:
        return None
    return (f"{free / GIB:.1f} GB free on the disk of {cfg.output_dir}, {wanted / GIB:.1f} GB needed ({basis}); "
            f"{(wanted - free) / GIB:.1f} GB short. Free space and run the same command again to resume")


def compact_finished(cfg: Any, entry: dict[str, Any], log: Callable[[str], None]) -> None:
    """Finish the compaction of a completed shard (a no-op when it is done, switched off or the shard is gone)."""
    if not cfg.compact_outputs or not entry.get("run_dir") or not Path(entry["run_dir"]).is_dir():
        return
    try:
        result = outputs.compact_run(entry["run_dir"], log=log)
    except Exception as exc:                       # the plain files are still there; the campaign goes on
        log(f"[campaign] could not compact {entry['run_dir']}: {type(exc).__name__}: {exc}")
        return
    if result["status"] == "compacted":
        entry["disk_bytes"] = outputs.tree_bytes(entry["run_dir"])
        log(f"[campaign] compacted {Path(entry['run_dir']).name}")


def prune_finished(cfg: Any, entry: dict[str, Any], i: int, log: Callable[[str], None]) -> None:
    """Delete ``raw/`` of a compacted shard unless ``output.prune_raw_keep_every`` keeps it (off by default).

    A refusal is logged and leaves ``raw/`` where it is; it never stops the campaign.
    """
    keep = cfg.prune_raw_keep_every
    if keep <= 0 or i % keep == 0 or not entry.get("run_dir") or not Path(entry["run_dir"]).is_dir():
        return
    try:
        result = outputs.prune_raw(entry["run_dir"])
    except Exception as exc:                       # raw/ stays (or the next call finishes the removal); the campaign goes on
        log(f"[campaign] could not prune raw/ of {entry['run_dir']}: {type(exc).__name__}: {exc}")
        return
    if result["status"] == "pruned":
        entry["disk_bytes"] = outputs.tree_bytes(entry["run_dir"])
        log(f"[campaign] removed raw/ of {Path(entry['run_dir']).name} ({result['bytes_removed']} bytes)")
    elif result["status"] != "unchanged":
        log(f"[campaign] kept raw/ of {Path(entry['run_dir']).name}: {result['reason']}")


def _run_id(cfg: Any, i: int, attempt: int) -> str:
    return f"scanner-{cfg.run_label}-{cfg.checksum[:8]}-s{i:03d}of{cfg.shards:03d}-a{attempt}"


def _earlier_attempts(cfg: Any, i: int, attempt: int) -> list[Path]:
    """Run directories of attempts 1..attempt-1 of shard ``i`` that exist, newest first."""
    root = Path(cfg.output_dir)
    found = [root / _run_id(cfg, i, a) for a in range(attempt - 1, 0, -1)]
    return [d for d in found if d.is_dir()]


def _finished_cleanly(run_dir: Path) -> bool:
    try:
        data = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return bool(data.get("complete")) and not data.get("zero_responsive")


def discard_stale_work(cfg: Any, i: int, attempt: int, log: Callable[[str], None] = lambda *_: None) -> None:
    """Remove ``work/`` (the fact store and its journal, up to a GB at scale) of earlier attempts that did not finish.

    Manifests, logs and ``raw/`` stay: a later attempt reuses the favicon lookup records from there.
    """
    for d in _earlier_attempts(cfg, i, attempt):
        work = d / "work"
        if work.is_dir() and not _finished_cleanly(d):
            shutil.rmtree(work, ignore_errors=True)
            log(f"[campaign] shard {i + 1}/{cfg.shards}: removed the working files of {d.name}")


def resume_source(cfg: Any, i: int, run_id: str) -> Path | None:
    """The newest earlier attempt of this shard, same configuration, whose favicon lookup records a new attempt can start from."""
    m = re.search(r"-a(\d+)$", run_id)
    if m is None:
        return None
    for d in _earlier_attempts(cfg, i, int(m.group(1))):
        if _finished_cleanly(d) or not outputs.resolve(d / "raw" / "favicon_records.jsonl").is_file():
            continue
        try:
            manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8")) if (d / "manifest.json").exists() else {}
        except (OSError, ValueError):
            continue
        if manifest.get("config_checksum", cfg.checksum) == cfg.checksum:
            return d
    return None


def begin_shard(cfg: Any, state: dict[str, Any], i: int, log: Callable[[str], None]) -> tuple[str, str | None]:
    """Decide what to do with shard ``i``: ``("complete", None)``, ``("drain", None)``, ``("disk", shortfall message)``
    or ``("run", run_id)`` (attempt counted)."""
    path = campaign_dir(cfg) / "campaign.json"
    entry = state["shard_states"].setdefault(str(i), {"status": "pending", "attempts": 0})
    if entry["status"] != "complete" and entry.get("run_id") and _finished_cleanly(Path(cfg.output_dir) / entry["run_id"]):
        # the process ended after the run finished but before the state file heard of it (e.g. while the outputs were compacted)
        entry.update(status="complete", run_dir=str(Path(cfg.output_dir) / entry["run_id"]), adopted=True)
        log(f"[campaign] shard {i + 1}/{cfg.shards}: {entry['run_id']} had finished; not repeating it")
    if entry["status"] != "complete":
        prior = _prior_complete(cfg, i) if entry["attempts"] == 0 else None
        if prior is not None:                      # never probe a shard twice just because the state file did not know
            entry.update(status="complete", run_dir=str(prior), adopted=True)
            log(f"[campaign] shard {i + 1}/{cfg.shards}: adopting the finished run {prior.name}")
    if entry["status"] == "complete":
        compact_finished(cfg, entry, log)
        prune_finished(cfg, entry, i, log)
        return "complete", None
    if (campaign_dir(cfg) / "DRAIN").exists():
        log(f"[campaign] {campaign_dir(cfg) / 'DRAIN'} exists: stopping before shard {i + 1}/{cfg.shards}")
        return "drain", None
    short = disk_shortfall(cfg, state)
    if short is not None:
        log(f"[campaign] not starting shard {i + 1}/{cfg.shards}: {short}")
        return "disk", short
    entry["attempts"] += 1
    for stale in ("run_dir", "error", "finished_at", "abort_reason", "elapsed_seconds"):
        entry.pop(stale, None)
    entry.update(status="running", started_at=datetime.now(UTC).isoformat())
    run_id = _run_id(cfg, i, entry["attempts"])
    discard_stale_work(cfg, i, entry["attempts"], log)
    entry["run_id"] = run_id
    _write_json(path, state)
    log(f"[campaign] shard {i + 1}/{cfg.shards} (attempt {entry['attempts']}) -> {run_id}")
    return "run", run_id


def record_failure(entry: dict[str, Any], i: int, exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, PreflightFailed):
        entry.update(status="refused", error=str(exc)[:500])
        return {"shard": i, "reason": "preflight_failed", "detail": str(exc)[:300]}
    entry.update(status="crashed", error=f"{type(exc).__name__}: {exc}"[:500])
    return {"shard": i, "reason": "crashed", "detail": entry["error"]}


def record_finished(entry: dict[str, Any], i: int, run_dir: Path) -> dict[str, Any] | None:
    """Copy the outcome of a finished shard run from its manifest into the state entry; returns why the campaign must stop, if it must."""
    manifest = json.loads((Path(run_dir) / "manifest.json").read_text(encoding="utf-8"))
    entry.update(run_dir=str(run_dir), finished_at=datetime.now(UTC).isoformat(), abort_reason=manifest.get("abort_reason"),
                 elapsed_seconds=manifest.get("elapsed_seconds"))
    if manifest.get("complete") and manifest.get("zero_responsive"):
        # a shard of thousands of targets with no answer at all is an egress/NAT fault, not an empty Internet
        entry["status"] = "zero_responsive"
        return {"shard": i, "reason": "zero_responsive", "detail": "no endpoint answered although every tool ran cleanly"}
    if manifest.get("complete"):
        entry["status"] = "complete"
        entry["disk_bytes"] = outputs.tree_bytes(run_dir)
        return None
    entry["status"] = "incomplete"
    return {"shard": i, "reason": manifest.get("abort_reason") or "stage_errors", "detail": manifest.get("stage_errors")}


def end_campaign(cfg: Any, state: dict[str, Any], run_dirs: dict[int, Path], stopped: dict[str, Any] | None) -> dict[str, Any]:
    path = campaign_dir(cfg) / "campaign.json"
    _write_json(path, state)
    _finish(cfg, state, run_dirs)
    done = sum(1 for e in state["shard_states"].values() if e["status"] == "complete")
    return {"complete": done == cfg.shards, "shards_complete": done, "shards": cfg.shards, "stopped": stopped,
            "state_file": str(path), "summary_file": str(campaign_dir(cfg) / "campaign_summary.json"), "finished_at": time.time()}


def _run_campaign(cfg: Any, run_fn: Callable[..., Path], log: Callable[[str], None], run_kwargs: dict[str, Any]) -> dict[str, Any]:
    state = load_state(cfg)
    run_dirs: dict[int, Path] = {}
    stopped: dict[str, Any] | None = None
    path = campaign_dir(cfg) / "campaign.json"
    for i in range(cfg.shards):
        action, run_id = begin_shard(cfg, state, i, log)
        entry = state["shard_states"][str(i)]
        if action == "complete":
            run_dirs[i] = Path(entry["run_dir"])
            continue
        if action == "drain":
            stopped = {"shard": i, "reason": "drain", "detail": "stopped between shards on request"}
            break
        if action == "disk":
            stopped = {"shard": i, "reason": "disk", "detail": run_id}
            break
        try:
            resume = resume_source(cfg, i, run_id)
            extra = {"resume_from": resume} if resume is not None else {}
            run_dir = run_fn(replace(cfg, shard=i), run_id=run_id, **extra, **run_kwargs)
        except PreflightFailed as exc:
            stopped = record_failure(entry, i, exc)
            break
        except Exception as exc:                       # a crash must not lose the record of how far we got
            stopped = record_failure(entry, i, exc)
            break
        run_dirs[i] = Path(run_dir)
        stopped = record_finished(entry, i, run_dir)
        if entry["status"] == "complete":
            prune_finished(cfg, entry, i, log)
            _write_json(path, state)
        if stopped:
            break
    return end_campaign(cfg, state, run_dirs, stopped)
