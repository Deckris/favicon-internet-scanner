"""Favicon-only re-fetch of an earlier scanner run, keeping the icon images.

The favicon stage needs only the endpoints and names a finished run already recorded, so the re-fetch rebuilds
its job list from that run's ``normalized/`` tables instead of scanning again. By default only the lookups that
returned an image the first time are repeated; ``all_jobs=True`` repeats every favicon lookup.

Everything the main run enforces still applies: an approved config, the same fetch policy and fetchers, the
egress / kill-switch / disk / approval-expiry guards, and a confirmation token for the exact job list.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scanner.internet import favicon as fav
from scanner.internet import icon_store
from scanner.internet import pacing
from scanner.internet import pipeline
from scanner.internet import preflight as pre
from scanner.internet.config import ConfigError, ScanConfig
from scanner.internet.runner import ManagedExecutor
from scanner.models import write_jsonl

JobKey = tuple[str, int, str | None]


def _rows(path: Path):
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def _scheme(protocol: str | None) -> str:
    return "http" if protocol == "http" else "https"


def load_source(source: Path, cfg: ScanConfig) -> tuple[dict[str, Any], list[dict[str, Any]], dict[JobKey, dict[str, Any]]]:
    """Return the source manifest, every favicon job it ran, and what each job found."""
    try:
        manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"source run {source} has no readable manifest: {exc}") from exc
    if manifest.get("status") != "finished":
        raise ConfigError(f"source run {source.name} did not finish (status={manifest.get('status')})")
    if manifest.get("config_checksum") != cfg.checksum:
        raise ConfigError("source run was made with a different config; re-fetch needs the config that produced it")
    jobs: dict[JobKey, dict[str, Any]] = {}
    previous: dict[JobKey, dict[str, Any]] = {}
    for row in _rows(source / "normalized" / "endpoints.jsonl"):
        outcome = row.get("direct_favicon_outcome")
        if outcome is None:
            continue
        key = (row["target_ip"], row["port"], None)
        jobs[key] = {"scheme": _scheme(row.get("protocol")), "ip": key[0], "port": key[1], "hostname": None}
        previous[key] = {"outcome": outcome, "sha256": row.get("direct_favicon_sha256")}
    for row in _rows(source / "normalized" / "hostname_resolution.jsonl"):
        outcome = row.get("hostname_favicon_outcome")
        if outcome is None or not row.get("hostname"):
            continue
        key = (row["target_ip"], row["port"], row["hostname"])
        jobs[key] = {"scheme": _scheme(row.get("protocol")), "ip": key[0], "port": key[1], "hostname": key[2]}
        previous[key] = {"outcome": outcome, "sha256": row.get("hostname_favicon_sha256")}
    return manifest, list(jobs.values()), previous


def select_jobs(jobs: list[dict[str, Any]], previous: dict[JobKey, dict[str, Any]], *, all_jobs: bool) -> list[dict[str, Any]]:
    if all_jobs:
        return jobs
    return [j for j in jobs if previous[(j["ip"], j["port"], j["hostname"])]["outcome"] == "image"]


def refetch_token(cfg: ScanConfig, source_run_id: str, jobs: list[dict[str, Any]], all_jobs: bool) -> str:
    blob = json.dumps([cfg.checksum, cfg.approval_sha256, source_run_id, all_jobs,
                       sorted((j["scheme"], j["ip"], j["port"], j["hostname"] or "") for j in jobs)])
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


def plan(cfg: ScanConfig, source: Path, *, all_jobs: bool) -> dict[str, Any]:
    manifest, jobs, previous = load_source(source, cfg)
    chosen = select_jobs(jobs, previous, all_jobs=all_jobs)
    return {
        "source_run": manifest["run_id"], "all_jobs": all_jobs,
        "favicon_jobs_in_source": len(jobs), "jobs_to_run": len(chosen),
        "endpoints": len({(j["ip"], j["port"]) for j in chosen}), "ips": len({j["ip"] for j in chosen}),
        "named_jobs": sum(1 for j in chosen if j["hostname"]),
        "approval_valid_until": cfg.approval.valid_until.isoformat() if cfg.approval else None,
        "confirm_token": refetch_token(cfg, manifest["run_id"], chosen, all_jobs),
    }


def run_refetch(cfg: ScanConfig, source: Path, *, all_jobs: bool = False, run_id: str | None = None,
                fetcher: Any = None, executor: Any = None, offline_preflight: bool = False,
                skip_preflight: bool = False) -> Path:
    if cfg.approval is None:
        raise ConfigError("favicon re-fetch requires an authorized config (approval not loaded)")
    if not cfg.favicon.enabled:
        raise ConfigError("favicon re-fetch requires favicon.enabled")
    started = datetime.now(UTC)
    manifest_src, all_source_jobs, previous = load_source(source, cfg)
    jobs = select_jobs(all_source_jobs, previous, all_jobs=all_jobs)
    if not jobs:
        raise ConfigError("the source run has no favicon jobs to repeat")
    policy, splan, exclusions = pipeline.build_policy(cfg)
    run_id = run_id or f"scanner-{cfg.run_label}-favicons-{started.strftime('%Y%m%dT%H%M%SZ')}"
    run_dir = Path(cfg.output_dir) / run_id
    if (run_dir / "manifest.json").exists():
        raise ConfigError(f"run directory {run_dir} already holds a run")
    for sub in ("raw", "normalized", "report"):
        (run_dir / sub).mkdir(parents=True, exist_ok=True)
    (run_dir / "config.snapshot.json").write_text(json.dumps(cfg.raw, indent=2, sort_keys=True, default=str), encoding="utf-8")
    (run_dir / "manifest.json").write_text(json.dumps({
        "schema_version": pipeline.SCHEMA_VERSION, "experiment": "scanner", "kind": "favicon_refetch", "run_id": run_id,
        "status": "started", "complete": False, "started_at": started.isoformat(), "source_run": manifest_src["run_id"],
        "config_checksum": cfg.checksum,
    }, indent=2), encoding="utf-8")

    st = pipeline._Stages(cfg, run_dir, guards=not offline_preflight)
    executor = executor or ManagedExecutor(cfg, run_dir, st.killed)
    restore_signals = pipeline._install_signal_handlers()
    store = icon_store.IconStore(run_dir / "favicons")
    records: list[dict[str, Any]] = []
    offhost_log: list[dict[str, Any]] = []
    try:
        report = pre.run_preflight(cfg, splan, run_dir=run_dir, executor=executor, offline=offline_preflight)
        (run_dir / "preflight.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        if not report["ok"] and not skip_preflight:
            raise pre.PreflightFailed(report)

        def stage() -> None:
            nonlocal fetcher
            fp = fav.fetch_policy(cfg, [j["ip"] for j in jobs])
            f = fetcher or fav.make_fetcher(
                cfg, fp, fav.RedirectResolver(cfg.dns.resolvers, cfg.dns.timeout), {(j["ip"], j["port"]) for j in jobs},
                exclusions=exclusions, killed=st.killed, state_path=run_dir / "offhost_state.json",
                pacer=pacing.IpPacer(cfg.measurement.min_seconds_between_probes_per_ip, st.killed))
            deadline = time.monotonic() + cfg.favicon.stage_max_seconds

            def stop() -> bool:
                return st.killed() or time.monotonic() > deadline
            try:
                records.extend(fav.run_favicon_stage(f, jobs, workers=cfg.favicon.workers, max_icons=cfg.favicon.max_icons_per_page,
                                                     killed=stop, icon_store=store))
                skipped = sum(1 for r in records if r.get("favicon_outcome") == "skipped_kill_switch")
                if skipped:
                    st.errors["favicon_incomplete"] = f"{skipped} of {len(jobs)} lookups skipped (stage cap or stop condition)"
            finally:
                offhost = getattr(f, "offhost", None)
                if offhost is not None:
                    offhost.save_state()
                    offhost_log.extend(getattr(offhost, "log", []))

        st.run("favicon_refetch", stage, None)
    finally:
        restore_signals()

    indexed = store.write_index(records)
    tool_errors: list[str] = []
    incomplete = bool(st.errors or st.skipped or st.reason or st.interrupted)
    compare = {"same_hash": 0, "different_hash": 0, "lost_image": 0, "new_image": 0}
    for rec in records:
        old = previous.get((rec.get("ip"), rec.get("port"), rec.get("hostname")))
        if old is None or rec.get("favicon_outcome") == "skipped_kill_switch":
            continue
        was, now = old["outcome"] == "image", bool(rec.get("favicon_is_image"))
        if was and now:
            compare["same_hash" if old["sha256"] == rec.get("favicon_sha256") else "different_hash"] += 1
        elif was:
            compare["lost_image"] += 1
        elif now:
            compare["new_image"] += 1
    outcomes: dict[str, int] = {}
    for rec in records:
        outcomes[rec.get("favicon_outcome") or "none"] = outcomes.get(rec.get("favicon_outcome") or "none", 0) + 1
    images = [r for r in records if r.get("favicon_is_image")]
    summary = {
        "source_run": manifest_src["run_id"], "jobs": len(jobs), "all_jobs": all_jobs, "outcomes": dict(sorted(outcomes.items())),
        "image_lookups": len(images), "image_lookups_by_scheme": {s: sum(1 for r in images if r.get("scheme") == s) for s in ("http", "https")},
        "images_stored": len(store), "distinct_images_indexed": indexed, "compared_with_source": compare,
        "offhost_icon_requests": sum(1 for e in offhost_log if not e["cached"] and e["outcome"] != "policy_refused"),
    }
    normalized = run_dir / "normalized"
    checksums = {"normalized/favicon_records.jsonl": write_jsonl(normalized / "favicon_records.jsonl", pipeline._scrub(records))}
    if cfg.favicon.offhost.enabled:
        checksums["normalized/offhost_icon_fetches.jsonl"] = write_jsonl(normalized / "offhost_icon_fetches.jsonl", offhost_log)
    (run_dir / "report" / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    for p in sorted(run_dir.rglob("*")):
        if p.is_file() and p.name != "manifest.json":
            checksums[str(p.relative_to(run_dir)).replace("\\", "/")] = pipeline.sha256_file(p)
    (run_dir / "manifest.json").write_text(json.dumps({
        "schema_version": pipeline.SCHEMA_VERSION, "instrument_version": pipeline.INSTRUMENT_VERSION, "experiment": "scanner",
        "kind": "favicon_refetch", "run_id": run_id, "source_run": manifest_src["run_id"],
        "started_at": started.isoformat(), "finished_at": datetime.now(UTC).isoformat(), "stage_seconds": st.timings,
        "stage_errors": st.errors, "stages_skipped": st.skipped, "abort_reason": st.reason, "status": "finished",
        "complete": not incomplete, "tool_job_errors": tool_errors, "anonymous_traffic": cfg.transparency.anonymous,
        "config_checksum": cfg.checksum, "approval_reference": cfg.approval.approval_reference,
        "approval_sha256": cfg.approval_sha256, "approval_valid_until": cfg.approval.valid_until.isoformat(),
        "vantage": {"id": cfg.vantage.id, "public_egress_ip": cfg.vantage.public_egress_ip},
        "parameters": {"favicon": vars(cfg.favicon), "fetch": vars(cfg.fetch)}, "summary": summary, "output_checksums": checksums,
    }, indent=2, default=pipeline._jsonable), encoding="utf-8")
    print(f"[scanner favicon_refetch] images stored: {len(store)}; {json.dumps(compare)}", file=sys.stderr, flush=True)
    return run_dir
