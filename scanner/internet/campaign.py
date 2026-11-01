"""Campaign: one sampled scan run as N independent, resumable shard runs.

Each shard is a complete scanner run over a disjoint slice of the same seeded ZMap permutation, so memory,
disk and the length of any single run stay bounded however large the sample is. Progress lives in
``<output>/campaign-<config checksum>/campaign.json``; running ``campaign`` again skips finished shards and
repeats the one that was interrupted (as a new attempt, in a new run directory). The new attempt continues from
the units the interrupted one finished (see ``resume``): the interrupted attempt's fact store is kept for it, and
``--no-resume`` starts the shard from nothing instead.

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
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from scanner.internet import archive as archive_mod
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
            raise ValueError("campaign.json belongs to a different configuration (or was written before host-derived settings were left out of the checksum)")
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


def _finish(cfg: Any, state: dict[str, Any], run_dirs: dict[int, Path], span: range | None = None) -> None:
    span = range(cfg.shards) if span is None else span
    summaries = []
    for i, d in sorted(run_dirs.items()):
        if state["shard_states"].get(str(i), {}).get("status") != "complete":
            continue                                   # a partial shard must not leak into the totals
        try:
            summaries.append(json.loads((d / "report" / "summary.json").read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    _write_json(campaign_dir(cfg) / "campaign_summary.json",
                {"complete": all(state["shard_states"].get(str(i), {}).get("status") == "complete" for i in span),
                 "shard_range": [span.start, span.stop],
                 "shard_states": state["shard_states"], "merged": merge_summaries(summaries)})


@dataclass(frozen=True)
class ArchivePolicy:
    """Where finished shards go when the output disk runs low (``archive.export_shard``), and whether the copied files are removed."""
    dest: Path
    remove_source: bool = False
    free_gb_below: float | None = None      # "low" means less free than this; None: less than the campaign wants free to start a shard


def shard_span(cfg: Any, shards_from: int = 0, shards_to: int | None = None) -> range:
    """The shards one invocation covers: ``shards_from`` up to, but not including, ``shards_to`` (default: the end).

    Several hosts can share one campaign definition (same checksum, same campaign directory name) and each take a
    slice; the slices must be disjoint, which is up to the operator, since each host keeps its own state file.
    """
    hi = cfg.shards if shards_to is None else shards_to
    if not 0 <= shards_from < hi <= cfg.shards:
        raise ValueError(f"the shard range [{shards_from}, {hi}) must satisfy 0 <= from < to <= {cfg.shards}")
    return range(shards_from, hi)


def run_campaign(cfg: Any, *, run_fn: Callable[..., Path] = pipeline.run, log: Callable[[str], None] = print,
                 pipeline_depth: int = 1, config_path: Path | None = None, shards_from: int = 0, shards_to: int | None = None,
                 network_only: bool = False, archive: ArchivePolicy | None = None, resume: bool = True,
                 **run_kwargs: Any) -> dict[str, Any]:
    """``network_only``: every shard stops after its network stages (state ``network_done``); see ``pipeline.run``.

    ``resume=False``: an interrupted shard starts again from nothing (no unit and no favicon lookup of the earlier
    attempt is reused, and its working files are removed)."""
    span = shard_span(cfg, shards_from, shards_to)
    if not resume:
        run_kwargs["resume"] = False
    if network_only:
        if pipeline_depth > 1:
            raise ValueError("a network-only campaign has no favicon stage to overlap; run it without --pipeline 2")
        run_kwargs["network_only"] = True
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
            return supervisor.run_overlapped(cfg, log=log, config_path=config_path, shards_from=span.start, shards_to=span.stop,
                                             archive=archive, resume=resume, **{k: v for k, v in run_kwargs.items() if k != "resume"})
        return _run_campaign(cfg, run_fn, log, run_kwargs, span, archive)
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
    sizes = [_shard_bytes(e) for e in state["shard_states"].values() if e.get("status") in ("complete", "network_done")]
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


def _low_disk(cfg: Any, state: dict[str, Any], archive: ArchivePolicy) -> bool:
    if archive.free_gb_below is None:
        return disk_shortfall(cfg, state) is not None
    probe = Path(cfg.output_dir)
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    try:
        return shutil.disk_usage(probe).free < archive.free_gb_below * GIB
    except OSError:
        return False


def archive_finished(cfg: Any, state: dict[str, Any], archive: ArchivePolicy, log: Callable[[str], None]) -> None:
    """While the output disk is low, export finished shards (oldest first) to ``archive.dest``.

    A shard stays ``complete`` in the state and gains ``archived_to``; with ``remove_source`` its files leave the disk
    once the copy has been verified. A shard that fails verification is left alone and logged, and the next one is tried.
    """
    for key in sorted(state["shard_states"], key=int):
        if not _low_disk(cfg, state, archive):
            return
        entry = state["shard_states"][key]
        if entry.get("status") != "complete" or entry.get("archived_to") or not entry.get("run_dir") or not Path(entry["run_dir"]).is_dir():
            continue
        try:
            result = archive_mod.export_shard(Path(entry["run_dir"]), archive.dest, remove_source=archive.remove_source, log=log)
        except Exception as exc:                       # nothing was removed; the campaign goes on with the next candidate
            log(f"[campaign] could not export shard {int(key) + 1}/{cfg.shards}: {type(exc).__name__}: {exc}")
            continue
        entry.update(archived_to=result["destination"], archived_at=datetime.now(UTC).isoformat(), source_removed=bool(result["removed_source"]))
        _write_json(campaign_dir(cfg) / "campaign.json", state)


def record_archived(cfg: Any, run_dir: Path, result: dict[str, Any]) -> bool:
    """Note in the campaign state that the shard in ``run_dir`` was exported by hand; False when the state does not list it."""
    lock = _acquire_lock(cfg)
    try:
        state = load_state(cfg)
        for entry in state["shard_states"].values():
            if entry.get("run_dir") and Path(entry["run_dir"]).resolve() == Path(run_dir).resolve():
                entry.update(archived_to=result["destination"], archived_at=datetime.now(UTC).isoformat(),
                             source_removed=bool(result["removed_source"]))
                _write_json(campaign_dir(cfg) / "campaign.json", state)
                return True
        return False
    finally:
        lock.unlink(missing_ok=True)


def record_finished_shard(cfg: Any, run_dir: Path) -> bool:
    """Mark the shard whose favicon stage just finished in ``run_dir`` as complete in the campaign state, if the state lists it."""
    lock = _acquire_lock(cfg)
    try:
        state = load_state(cfg)
        for key, entry in state["shard_states"].items():
            if entry.get("run_id") == Path(run_dir).name and entry.get("status") == "network_done":
                record_finished(entry, int(key), Path(run_dir))
                _write_json(campaign_dir(cfg) / "campaign.json", state)
                return True
        return False
    finally:
        lock.unlink(missing_ok=True)


def compact_finished(cfg: Any, entry: dict[str, Any], log: Callable[[str], None]) -> None:
    """Finish the compaction of a completed shard (a no-op when it is done, switched off or the shard is gone)."""
    if not cfg.compact_outputs or not entry.get("run_dir") or not Path(entry["run_dir"]).is_dir() or entry.get("archived_to"):
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
    if keep <= 0 or i % keep == 0 or not entry.get("run_dir") or not Path(entry["run_dir"]).is_dir() or entry.get("archived_to"):
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


def _manifest(run_dir: Path) -> dict[str, Any]:
    try:
        data = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _network_done(run_dir: Path) -> bool:
    """True for a shard whose network stages are finished and whose favicon stage is still to run (``pipeline.run_favicon_only``)."""
    data = _manifest(run_dir)
    return bool(data.get("network_done")) and not data.get("complete") and (run_dir / "work" / "facts.sqlite").is_file()


def _finished_cleanly(run_dir: Path) -> bool:
    try:
        data = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return bool(data.get("complete")) and not data.get("zero_responsive")


def discard_stale_work(cfg: Any, i: int, attempt: int, log: Callable[[str], None] = lambda *_: None,
                       keep: Path | None = None) -> None:
    """Remove ``work/`` (the fact store and its journal, up to a GB at scale) of earlier attempts that did not finish.

    Manifests, logs and ``raw/`` stay: a later attempt reuses the favicon lookup records from there. The attempt
    named by ``keep`` (the one the new attempt continues from) keeps its ``work/``: its fact store holds the units it finished.
    """
    for d in _earlier_attempts(cfg, i, attempt):
        work = d / "work"
        if keep is not None and Path(d) == Path(keep):
            continue
        if work.is_dir() and not _finished_cleanly(d) and not _network_done(d):
            shutil.rmtree(work, ignore_errors=True)
            log(f"[campaign] shard {i + 1}/{cfg.shards}: removed the working files of {d.name}")


def resume_source(cfg: Any, i: int, run_id: str) -> Path | None:
    """The newest earlier attempt of this shard, same configuration, that a new attempt can continue from: it left favicon
    lookup records, or the fact store with the network units it finished."""
    m = re.search(r"-a(\d+)$", run_id)
    if m is None:
        return None
    for d in _earlier_attempts(cfg, i, int(m.group(1))):
        if _finished_cleanly(d):
            continue
        if not outputs.resolve(d / "raw" / "favicon_records.jsonl").is_file() and not (d / "work" / "facts.sqlite").is_file():
            continue
        try:
            manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8")) if (d / "manifest.json").exists() else {}
        except (OSError, ValueError):
            continue
        if manifest.get("config_checksum", cfg.checksum) == cfg.checksum:
            return d
    return None


def begin_shard(cfg: Any, state: dict[str, Any], i: int, log: Callable[[str], None],
                archive: ArchivePolicy | None = None, resume: bool = True) -> tuple[str, str | None]:
    """Decide what to do with shard ``i``: ``("complete", None)``, ``("network_done", None)``, ``("drain", None)``, ``("disk", shortfall message)``
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
    if entry["status"] == "network_done" and entry.get("run_id") and _network_done(Path(cfg.output_dir) / entry["run_id"]):
        return "network_done", None                # waiting for its favicon stage; neither repeated nor counted as finished
    if entry["status"] == "network_done" and entry.get("run_id"):
        run_dir = Path(cfg.output_dir) / entry["run_id"]
        if not _manifest(run_dir).get("complete"):
            raise ValueError(f"shard {i + 1}/{cfg.shards} is recorded as network_done but {run_dir.name} no longer holds its "
                             "work/facts.sqlite or a manifest that says so; the shard is not scanned again. Restore the run "
                             "directory, or edit its entry in campaign.json to start the shard over on purpose")
    if (campaign_dir(cfg) / "DRAIN").exists():
        log(f"[campaign] {campaign_dir(cfg) / 'DRAIN'} exists: stopping before shard {i + 1}/{cfg.shards}")
        return "drain", None
    if archive is not None:
        archive_finished(cfg, state, archive, log)
    short = disk_shortfall(cfg, state)
    if short is not None:
        log(f"[campaign] not starting shard {i + 1}/{cfg.shards}: {short}")
        return "disk", short
    entry["attempts"] += 1
    for stale in ("run_dir", "error", "finished_at", "abort_reason", "elapsed_seconds"):
        entry.pop(stale, None)
    entry.update(status="running", started_at=datetime.now(UTC).isoformat())
    run_id = _run_id(cfg, i, entry["attempts"])
    discard_stale_work(cfg, i, entry["attempts"], log, keep=resume_source(cfg, i, run_id) if resume else None)
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
    if (manifest.get("complete") or manifest.get("network_done")) and manifest.get("zero_responsive"):
        # a shard of thousands of targets with no answer at all is an egress/NAT fault, not an empty Internet
        entry["status"] = "zero_responsive"
        return {"shard": i, "reason": "zero_responsive", "detail": "no endpoint answered although every tool ran cleanly"}
    if manifest.get("complete"):
        entry["status"] = "complete"
        entry["disk_bytes"] = outputs.tree_bytes(run_dir)
        return None
    if manifest.get("network_done") and not manifest.get("zero_responsive"):
        entry["status"] = "network_done"
        entry["disk_bytes"] = outputs.tree_bytes(run_dir)
        return None
    entry["status"] = "incomplete"
    return {"shard": i, "reason": manifest.get("abort_reason") or "stage_errors", "detail": manifest.get("stage_errors")}


def end_campaign(cfg: Any, state: dict[str, Any], run_dirs: dict[int, Path], stopped: dict[str, Any] | None,
                 span: range | None = None) -> dict[str, Any]:
    span = range(cfg.shards) if span is None else span
    path = campaign_dir(cfg) / "campaign.json"
    _write_json(path, state)
    _finish(cfg, state, run_dirs, span)
    done = sum(1 for i in span if state["shard_states"].get(str(i), {}).get("status") == "complete")
    network = sum(1 for i in span if state["shard_states"].get(str(i), {}).get("status") == "network_done")
    return {"complete": done == len(span), "shards_complete": done, "shards": cfg.shards, "shard_range": [span.start, span.stop],
            **({"shards_network_done": network, "network_complete": done + network == len(span)} if network else {}),
            "stopped": stopped,
            "state_file": str(path), "summary_file": str(campaign_dir(cfg) / "campaign_summary.json"), "finished_at": time.time()}


def _run_campaign(cfg: Any, run_fn: Callable[..., Path], log: Callable[[str], None], run_kwargs: dict[str, Any],
                  span: range | None = None, archive: ArchivePolicy | None = None) -> dict[str, Any]:
    span = range(cfg.shards) if span is None else span
    state = load_state(cfg)
    run_dirs: dict[int, Path] = {}
    stopped: dict[str, Any] | None = None
    path = campaign_dir(cfg) / "campaign.json"
    resume = run_kwargs.get("resume", True)
    for i in span:
        action, run_id = begin_shard(cfg, state, i, log, archive, resume)
        entry = state["shard_states"][str(i)]
        if action == "complete":
            run_dirs[i] = Path(entry["run_dir"])
            continue
        if action == "network_done":
            continue
        if action == "drain":
            stopped = {"shard": i, "reason": "drain", "detail": "stopped between shards on request"}
            break
        if action == "disk":
            stopped = {"shard": i, "reason": "disk", "detail": run_id}
            break
        try:
            source = resume_source(cfg, i, run_id) if resume else None
            extra = {"resume_from": source} if source is not None else {}
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
    return end_campaign(cfg, state, run_dirs, stopped, span)
