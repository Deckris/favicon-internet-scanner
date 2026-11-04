"""Read-only summary of a campaign directory: shards per state and stage, queues, workers, disk and memory.

Reads ``campaign.json`` as written by ``campaign`` (``shard_states``: shard index -> entry). An entry may also carry
``stages``: ``{stage: {"status", "attempts", "owner_pid", "heartbeat"}}``; it is optional and so is every field in
it. ``stages`` may also be a list of such entries with a ``stage`` or ``name`` key; anything malformed is skipped.
``heartbeat`` is epoch seconds (milliseconds when above 1e11) or an ISO 8601 time. The ZMap send rate is shown when the state records one
(``zmap.send_rate_pps`` or a shard entry's ``send_rate_pps``). Process figures come from ``/proc`` and are left out
where there is none.
"""
from __future__ import annotations

import json
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROC_NAMES = ("zmap", "zgrab2", "zdns")
QUEUED = ("pending", "queued", "ready")
ACTIVE = ("running", "active", "in_progress", "started")


def _epoch(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1000.0 if v > 1e11 else v  # milliseconds
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).timestamp()
    return None


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _mask_confirm(args: list[str]) -> list[str]:
    out, hide = [], False
    for a in args:
        if hide:
            out.append("***")
            hide = False
        elif a == "--confirm":
            out.append(a)
            hide = True
        elif a.startswith("--confirm="):
            out.append("--confirm=***")
        else:
            out.append(a)
    return out


def _is_scanner_process(args: list[str]) -> bool:
    if not args:
        return False
    name = args[0].replace("\\", "/").rsplit("/", 1)[-1]
    if name in PROC_NAMES:
        return True
    return name.startswith("python") and "scanner.internet" in args[1:4]


def process_rss(proc_root: Path | str = "/proc") -> list[dict[str, Any]] | None:
    """RSS in MiB of the scanner processes (zmap, zgrab2, zdns by argv[0]; python -m scanner.internet).

    None when there is no readable proc. The token after ``--confirm`` is masked in the command shown."""
    root = Path(proc_root)
    try:
        entries = [p for p in root.iterdir() if p.name.isdigit()]
    except OSError:
        return None
    out = []
    for p in entries:
        raw = _read_text(p / "cmdline")
        if not raw:
            continue
        args = [a for a in raw.split("\0") if a]
        if not _is_scanner_process(args):
            continue
        cmd = " ".join(_mask_confirm(args))
        rss = None
        for line in (_read_text(p / "status") or "").splitlines():
            parts = line.split()
            if parts[:1] == ["VmRSS:"] and len(parts) >= 2 and parts[1].isdigit():
                rss = round(int(parts[1]) / 1024, 1)
        out.append({"pid": int(p.name), "rss_mib": rss, "cmd": cmd[:120]})
    return sorted(out, key=lambda d: d["pid"])


def collect(campaign_dir: Path | str, *, proc_root: Path | str = "/proc", now: float | None = None) -> dict[str, Any]:
    cdir = Path(campaign_dir)
    now = time.time() if now is None else now
    path = cdir / "campaign.json"
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    shard_states = state.get("shard_states")
    if isinstance(shard_states, list):
        shard_states = {str(i): e for i, e in enumerate(shard_states)}
    elif not isinstance(shard_states, dict):
        shard_states = {}
    total = state.get("shards") if isinstance(state.get("shards"), int) else None
    by_state: dict[str, int] = {}
    by_stage: dict[str, dict[str, int]] = {}
    workers: dict[str, dict[str, Any]] = {}
    zmap = state.get("zmap")
    send_rate = zmap.get("send_rate_pps") if isinstance(zmap, dict) else None
    for key, entry in shard_states.items():
        if not isinstance(entry, dict):
            continue
        st = str(entry.get("status", "unknown"))
        by_state[st] = by_state.get(st, 0) + 1
        if entry.get("send_rate_pps") is not None:
            send_rate = entry["send_rate_pps"]
        stages = entry.get("stages")
        if isinstance(stages, list):
            stages = {str(i.get("stage") or i.get("name")): i for i in stages
                      if isinstance(i, dict) and (i.get("stage") or i.get("name"))}
        for stage, info in (stages.items() if isinstance(stages, dict) else ()):
            info = info if isinstance(info, dict) else {}
            sst = str(info.get("status", "unknown"))
            counts = by_stage.setdefault(stage, {})
            counts[sst] = counts.get(sst, 0) + 1
            beat = _epoch(info.get("heartbeat"))
            if beat is None or sst not in ACTIVE:
                continue
            pid = info.get("owner_pid")
            w = workers.setdefault(f"{stage}:{pid}", {"stage": stage, "pid": pid, "last_progress": beat, "shard": key})
            if beat >= w["last_progress"]:
                w.update(last_progress=beat, shard=key)
    if total is not None and sum(by_state.values()) < total:
        by_state["not_started"] = total - sum(by_state.values())
    queues = {s: sum(c.get(q, 0) for q in QUEUED) for s, c in by_stage.items()}
    for w in workers.values():
        w["age_seconds"] = max(0, int(now - w["last_progress"]))
        w["last_progress"] = datetime.fromtimestamp(w["last_progress"], UTC).isoformat(timespec="seconds")
    try:
        disk_free_gb = round(shutil.disk_usage(cdir).free / 2**30, 1)
    except OSError:
        disk_free_gb = None
    return {"campaign_dir": str(cdir), "shards_total": total, "complete": bool(state.get("complete")),
            "shards_by_state": dict(sorted(by_state.items())),
            "shards_by_stage": {s: dict(sorted(c.items())) for s, c in sorted(by_stage.items())},
            "queue_depth": dict(sorted(queues.items())),
            "workers": sorted(workers.values(), key=lambda w: (w["stage"], str(w["pid"]))),
            "zmap_send_rate_pps": send_rate, "disk_free_gb": disk_free_gb,
            "drain": (cdir / "DRAIN").exists(), "processes": process_rss(proc_root)}


def render(s: dict[str, Any]) -> str:
    head = f"campaign {s['campaign_dir']}" + (" (complete)" if s["complete"] else "") + (" [DRAIN set]" if s["drain"] else "")
    states = ", ".join(f"{k} {v}" for k, v in s["shards_by_state"].items()) or "none"
    lines = [head, f"shards ({s['shards_total'] if s['shards_total'] is not None else '?'}): {states}"]
    for stage, counts in s["shards_by_stage"].items():
        lines.append(f"  {stage}: " + ", ".join(f"{k} {v}" for k, v in counts.items()) + f"  (queue {s['queue_depth'].get(stage, 0)})")
    for w in s["workers"]:
        lines.append(f"  worker {w['stage']} pid {w['pid']}: shard {w['shard']}, last progress {w['age_seconds']} s ago")
    rate = s["zmap_send_rate_pps"]
    lines.append("zmap send rate: " + (f"{rate} pps" if rate is not None else "not recorded"))
    lines.append("disk free: " + (f"{s['disk_free_gb']} GiB" if s["disk_free_gb"] is not None else "unknown"))
    procs = s["processes"]
    if procs is None:
        lines.append("processes: /proc not available")
    else:
        lines.append(f"processes: {len(procs)}, RSS {sum(p['rss_mib'] or 0 for p in procs):.0f} MiB")
        lines.extend(f"  {p['pid']}  {p['rss_mib']} MiB  {p['cmd']}" for p in procs)
    return "\n".join(lines)
