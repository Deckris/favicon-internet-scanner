"""Campaign: one sampled scan run as N independent, resumable shard runs.

Each shard is a complete scanner run over a disjoint slice of the same seeded ZMap permutation, so memory,
disk and the length of any single run stay bounded however large the sample is. Progress lives in
``<output>/campaign-<config checksum>/campaign.json``; running ``campaign`` again skips finished shards and
repeats the one that was interrupted (as a new attempt, in a new run directory).

The campaign stops at the first shard that does not finish cleanly: the kill switch, a changed public IP, low
disk, an expired approval and tool errors all end it, and nothing further is sent until the operator looks.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from scanner.internet import pipeline
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
                os.kill(pid, 0)                        # raises if that process is gone
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


def run_campaign(cfg: Any, *, run_fn: Callable[..., Path] = pipeline.run, log: Callable[[str], None] = print, **run_kwargs: Any) -> dict[str, Any]:
    lock = _acquire_lock(cfg)
    try:
        return _run_campaign(cfg, run_fn, log, run_kwargs)
    finally:
        lock.unlink(missing_ok=True)


def _run_campaign(cfg: Any, run_fn: Callable[..., Path], log: Callable[[str], None], run_kwargs: dict[str, Any]) -> dict[str, Any]:
    state = load_state(cfg)
    run_dirs: dict[int, Path] = {}
    stopped: dict[str, Any] | None = None
    path = campaign_dir(cfg) / "campaign.json"
    for i in range(cfg.shards):
        entry = state["shard_states"].setdefault(str(i), {"status": "pending", "attempts": 0})
        if entry["status"] != "complete":
            prior = _prior_complete(cfg, i) if entry["attempts"] == 0 else None
            if prior is not None:                      # never probe a shard twice just because the state file did not know
                entry.update(status="complete", run_dir=str(prior), adopted=True)
                log(f"[campaign] shard {i + 1}/{cfg.shards}: adopting the finished run {prior.name}")
        if entry["status"] == "complete":
            run_dirs[i] = Path(entry["run_dir"])
            continue
        entry["attempts"] += 1
        for stale in ("run_dir", "error", "finished_at", "abort_reason", "elapsed_seconds"):
            entry.pop(stale, None)
        entry.update(status="running", started_at=datetime.now(UTC).isoformat())
        run_id = f"scanner-{cfg.run_label}-{cfg.checksum[:8]}-s{i:03d}of{cfg.shards:03d}-a{entry['attempts']}"
        entry["run_id"] = run_id
        _write_json(path, state)
        log(f"[campaign] shard {i + 1}/{cfg.shards} (attempt {entry['attempts']}) -> {run_id}")
        try:
            run_dir = run_fn(replace(cfg, shard=i), run_id=run_id, **run_kwargs)
        except PreflightFailed as exc:
            entry.update(status="refused", error=str(exc)[:500])
            stopped = {"shard": i, "reason": "preflight_failed", "detail": str(exc)[:300]}
            break
        except Exception as exc:                       # a crash must not lose the record of how far we got
            entry.update(status="crashed", error=f"{type(exc).__name__}: {exc}"[:500])
            stopped = {"shard": i, "reason": "crashed", "detail": entry["error"]}
            break
        run_dirs[i] = Path(run_dir)
        manifest = json.loads((Path(run_dir) / "manifest.json").read_text(encoding="utf-8"))
        entry.update(run_dir=str(run_dir), finished_at=datetime.now(UTC).isoformat(), abort_reason=manifest.get("abort_reason"),
                     elapsed_seconds=manifest.get("elapsed_seconds"))
        if manifest.get("complete") and manifest.get("zero_responsive"):
            # a shard of thousands of targets with no answer at all is an egress/NAT fault, not an empty Internet
            entry["status"] = "zero_responsive"
            stopped = {"shard": i, "reason": "zero_responsive", "detail": "no endpoint answered although every tool ran cleanly"}
            break
        if manifest.get("complete"):
            entry["status"] = "complete"
            _write_json(path, state)
            continue
        entry["status"] = "incomplete"
        stopped = {"shard": i, "reason": manifest.get("abort_reason") or "stage_errors", "detail": manifest.get("stage_errors")}
        break
    _write_json(path, state)
    _finish(cfg, state, run_dirs)
    done = sum(1 for e in state["shard_states"].values() if e["status"] == "complete")
    return {"complete": done == cfg.shards, "shards_complete": done, "shards": cfg.shards, "stopped": stopped,
            "state_file": str(path), "summary_file": str(campaign_dir(cfg) / "campaign_summary.json"), "finished_at": time.time()}
