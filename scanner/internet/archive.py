"""Move a finished shard to another disk without losing track of it.

``export_shard`` copies a finished (or compacted) run directory, reads every copy back and checks it against the
manifest (``output_checksums``) and against the ``raw_sha256`` the tool jobs recorded, and writes a verification record
next to the copy. Only with ``remove_source`` set, and only when every check passed, are the files of the source
removed. A small stub stays (the manifest, ``report/`` and ``archive_record.json``): the campaign state keeps the shard
as ``complete``, a repeated campaign still adopts it, and the merged totals still find its summary.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any, Callable

from scanner.internet import outputs
from scanner.internet.split import BLOCK, _copy, _write_json, sha256_of

RECORD = "archive_record.json"
VERIFICATION = "export_verification.json"
KEEP = ("manifest.json", "report", RECORD)         # what stays in the source directory after the files were removed


class ArchiveRefused(RuntimeError):
    """The run is not in a state that may be exported, or the copy did not verify. Nothing was removed."""


def _files(run_dir: Path) -> list[str]:
    out = []
    for root, _dirs, names in os.walk(run_dir):
        for name in names:
            rel = (Path(root) / name).relative_to(run_dir).as_posix()
            if rel.split("/")[0] == "work" or rel == RECORD or name.endswith((".tmp", ".part")):
                continue
            out.append(rel)
    return sorted(out)


def _content_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with (outputs.open_zstd(path) if outputs.is_compressed(path) else open(path, "rb")) as fh:
        for block in iter(lambda: fh.read(BLOCK), b""):
            digest.update(block)
    return digest.hexdigest()


def _raw_problems(dest: Path, shas: dict[str, str]) -> list[str]:
    """Raw tool batches whose checksum differs from the ``raw_sha256`` the tool job recorded for them."""
    jobs = dest / "normalized" / "tool_jobs.jsonl"
    if not outputs.exists(jobs):
        return ["normalized/tool_jobs.jsonl is missing"]
    problems = []
    for line in outputs.iter_lines(outputs.resolve(jobs)):
        if not line.strip():
            continue
        job = json.loads(line)
        rel, want = job.get("raw_path"), job.get("raw_sha256")
        if not rel or not want:
            continue
        if not (dest / rel).is_file():
            if not (dest / "raw").exists():
                continue                                   # raw/ was pruned: raw_pruned.json holds what was removed
            problems.append(f"{rel} is missing")
            continue
        got = shas.get(rel) or sha256_of(dest / rel)
        if got != want and (not outputs.is_compressed(rel) or _content_sha(dest / rel) != want):
            problems.append(f"{rel} does not match raw_sha256 of its tool job")
    return problems


def verify_copy(src: Path, dest: Path, copied: dict[str, str]) -> list[str]:
    """Every problem found between the manifest, the source and the copy (empty when the copy can be trusted)."""
    try:
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"manifest.json: {exc}"]
    problems = []
    for rel, want in sorted((manifest.get("output_checksums") or {}).items()):
        if rel in copied:
            if copied[rel] != want:
                problems.append(f"{rel} does not match output_checksums")
        elif not (rel.startswith("raw/") and (src / "raw_pruned.json").exists()):
            problems.append(f"{rel} is listed in output_checksums but is not in the run")
    return problems + _raw_problems(dest, copied)


def _read(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _remove(run_dir: Path) -> None:
    for child in sorted(run_dir.iterdir()):
        if child.name in KEEP:
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def export_shard(run_dir: Path, dest_root: Path, *, remove_source: bool = False,
                 log: Callable[[str], None] = lambda *_: None) -> dict[str, Any]:
    """Copy ``run_dir`` to ``dest_root/<run name>``, verify it, and with ``remove_source`` free the space it took.

    Raises ``ArchiveRefused`` (having removed nothing) when the run did not finish cleanly or any check fails.
    """
    run_dir, dest_root = Path(run_dir).resolve(), Path(dest_root)
    try:
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ArchiveRefused(f"{run_dir} has no readable manifest ({exc})") from exc
    if not manifest.get("complete") or manifest.get("stage_errors") or manifest.get("status") != "finished":
        raise ArchiveRefused("the manifest does not say the run finished cleanly")
    if (run_dir / "work").exists():
        raise ArchiveRefused("the run still has a work/ directory")
    prior = _read(run_dir / RECORD)
    if prior.get("verified") and prior.get("removed_source") and not (run_dir / "normalized").exists():
        return {**prior, "status": "unchanged"}             # already exported and emptied
    dest = dest_root / run_dir.name
    if dest.resolve() == run_dir or run_dir in dest.resolve().parents:
        raise ArchiveRefused("the destination is inside the run directory")
    dest.mkdir(parents=True, exist_ok=True)
    copied: dict[str, str] = {}
    sizes: dict[str, int] = {}
    for rel in _files(run_dir):
        src, target = run_dir / rel, dest / rel
        if target.is_file() and target.stat().st_size == src.stat().st_size and sha256_of(target) == sha256_of(src):
            copied[rel], sizes[rel] = sha256_of(target), target.stat().st_size      # a repeated export keeps what is already there
            continue
        copied[rel], sizes[rel] = _copy(src, target)
    problems = verify_copy(run_dir, dest, copied)
    for rel, sha in sorted(copied.items()):      # one more read of the copy, independent of the copy step
        if sha256_of(dest / rel) != sha:
            problems.append(f"{rel} changed on the destination after it was copied")
    record = {"verified": not problems, "problems": problems[:50], "run_id": manifest.get("run_id"), "source": str(run_dir),
              "destination": str(dest), "files": len(copied), "bytes": sum(sizes.values()), "verified_at": time.time(),
              "checked": "output_checksums, raw_sha256 of the tool jobs, and a second read of every copied file"}
    _write_json(dest / VERIFICATION, {**record, "sha256": dict(sorted(copied.items()))})
    if problems:
        raise ArchiveRefused(f"{len(problems)} problem(s), nothing was removed: " + "; ".join(problems[:3]))
    record["removed_source"] = False
    _write_json(run_dir / RECORD, record)
    if remove_source:
        _remove(run_dir)
        record["removed_source"] = True
        _write_json(run_dir / RECORD, record)
        log(f"[archive] {run_dir.name}: {record['bytes']} bytes moved to {dest}")
    return {**record, "status": "exported"}
