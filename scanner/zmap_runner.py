"""ZMap L4 discovery stage.

A single controlled ZMap invocation per frozen port/population shard. The
allowlist/blocklist fed to ZMap come entirely from the central target policy;
this module never hard-codes a population, interface or vantage address.
"""
from __future__ import annotations

import csv
import hashlib
import io
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from scanner.models import L4Result, ToolJob, stable_id

Executor = Callable[..., Any]


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


def run_zmap(
    cfg: Any,
    policy: Any,
    port: int,
    run_dir: Path,
    *,
    executor: Executor = subprocess.run,
    gateway_mac: str | None = None,
) -> tuple[ToolJob, list[L4Result]]:
    raw_dir = Path(run_dir) / "raw" / "zmap"
    raw_dir.mkdir(parents=True, exist_ok=True)

    target_cidrs = policy.target_cidrs()
    exclusion_cidrs = policy.exclusion_cidrs()
    vantage = cfg.vantage
    measurement = cfg.measurement

    job_id = stable_id("ZMAP", vantage.id, port, target_cidrs, exclusion_cidrs)
    allowlist_path = raw_dir / f"{job_id}-allowlist.txt"
    blocklist_path = raw_dir / f"{job_id}-blocklist.txt"
    output_path = raw_dir / f"{job_id}.csv"
    _write_lines(allowlist_path, target_cidrs)
    _write_lines(blocklist_path, exclusion_cidrs)

    command = [
        "zmap",
        # Use only the frozen policy/config, never machine-global ZMap defaults.
        "-C", "/dev/null",
        "-p", str(port),
        "-w", str(allowlist_path),
        "-b", str(blocklist_path),
        "-i", vantage.interface,
        "-S", vantage.source_ipv4,
        "-r", str(measurement.zmap_rate),
        "--max-runtime", str(measurement.zmap_max_runtime),
        "--cooldown-time", str(measurement.zmap_cooldown),
        "-O", "csv",
        # saddr stays the first column; callers may ask for extra response fields (e.g. "saddr,window,ttl").
        "-f", getattr(measurement, "zmap_output_fields", None) or "saddr",
        # zmap only applies its implicit `success = 1 && repeat = 0` output
        # filter when NO output customization is given at all; passing an
        # explicit `-f` (even just "saddr") silently disables that implicit
        # filter, so every response -- including RST/closed-port replies --
        # was being written to the CSV as if it were an open port. This
        # inflated every address to appear "open" on every scanned port
        # (confirmed with zmap 2.1.1), multiplying
        # downstream hostname-aware ZGrab2 work by the full port count.
        "--output-filter", "success = 1 && repeat = 0",
        "-o", str(output_path),
    ]
    command += list(getattr(measurement, "zmap_extra_args", ()))
    if gateway_mac:
        command += ["-G", gateway_mac]
    # ZMap 2.1.1 starts a sender thread per core unless told otherwise (measured: 17 threads, ~12 cores busy,
    # which starved the network path and stalled sending). Callers that care pass an explicit thread count.
    sender_threads = getattr(measurement, "zmap_sender_threads", None)
    if sender_threads:
        command += ["-T", str(sender_threads)]
    zmap_probes = getattr(measurement, "zmap_probes", None) or 1
    command += ["-P", str(zmap_probes)]
    max_targets = getattr(measurement, "zmap_max_targets", None)
    if max_targets:
        command += ["-n", str(max_targets)]
    # A fixed ZMap --seed makes the randomized target order deterministic across runs.
    zmap_seed = getattr(measurement, "zmap_seed", None)
    if zmap_seed is not None:
        command += ["--seed", str(zmap_seed)]
    # Optional sharding (scanner campaigns): disjoint slices of one seeded permutation, same slice on every port.
    zmap_shards = getattr(measurement, "zmap_shards", None)
    if zmap_shards and zmap_shards > 1 and zmap_seed is not None:
        command += ["--shards", str(zmap_shards), "--shard", str(getattr(measurement, "zmap_shard", 0))]

    started_at = datetime.now(UTC).isoformat()
    result = executor(command, capture_output=True, text=True, check=False)
    finished_at = datetime.now(UTC).isoformat()

    raw_bytes = output_path.read_bytes() if output_path.exists() else b""
    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    found_ips: list[str] = []
    if raw_bytes:
        # zmap's `-O csv -f saddr` output is a bare list of addresses with no header row
        # (4.4.0 is run with --no-header-row; 2.1.x never writes one).
        reader = csv.reader(io.StringIO(raw_bytes.decode("utf-8", "replace")))
        for row in reader:
            if not row:
                continue
            ip = row[0].strip()
            if ip:
                found_ips.append(ip)

    l4_results: list[L4Result] = []
    observed_at = finished_at
    for ip in found_ips:
        refusal = policy.check_ip(ip, stage="zmap", context=f"zmap:port={port}")
        if refusal is not None:
            continue
        l4_results.append(L4Result(
            target_ip=ip,
            port=port,
            vantage_id=vantage.id,
            zmap_job_id=job_id,
            classification="synack",
            observed_at=observed_at,
        ))

    exit_code = getattr(result, "returncode", None)
    error = None
    if exit_code not in (0, None):
        error = (getattr(result, "stderr", "") or "").strip() or f"zmap exited {exit_code}"

    job = ToolJob(
        job_id=job_id,
        tool="zmap",
        purpose=f"l4:port={port}",
        command=tuple(command),
        input_count=len(target_cidrs),
        output_count=len(l4_results),
        exit_code=exit_code,
        raw_path=str(output_path.relative_to(run_dir)),
        raw_sha256=raw_sha256,
        started_at=started_at,
        finished_at=finished_at,
        error=error,
    )
    return job, l4_results


__all__ = ["run_zmap"]
