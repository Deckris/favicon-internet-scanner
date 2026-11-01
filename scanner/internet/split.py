"""Hand a network-only shard to another machine for its favicon stage, and take the favicon outputs back.

``export_network`` copies what the favicon stage needs (the fact store, the stored HTTP pages, the tool job list, the
manifest and the config snapshot) into a directory that is itself a run directory, with a SHA-256 for every file.
``pipeline.run_favicon_only`` runs there. ``import_favicons`` verifies the favicon outputs of that run against its
manifest and copies them into the original run directory, which then finishes with the same favicon-stage command and
no request to any server: every lookup is already in the imported record file.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from scanner.internet import outputs
from scanner.internet.config import ConfigError

EXPORT_MANIFEST = "export_manifest.json"
IMPORT_RECORD = "favicon_import.json"
RECORDS = "raw/favicon_records.jsonl"
BLOCK = 1 << 20


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(BLOCK), b""):
            digest.update(block)
    return digest.hexdigest()


def _copy(src: Path, dst: Path) -> tuple[str, int]:
    """Copy through a temporary name; returns the SHA-256 and size of what was read. The copy is renamed into place only
    after it has been read back and hashes the same."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(dst.name + ".part")
    digest, size = hashlib.sha256(), 0
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            for block in iter(lambda: fin.read(BLOCK), b""):
                digest.update(block)
                size += len(block)
                fout.write(block)
            fout.flush()
            os.fsync(fout.fileno())
        if sha256_of(tmp) != digest.hexdigest():
            raise OSError(f"{dst.name} differs from {src} after the copy")
        os.replace(tmp, dst)
    finally:
        tmp.unlink(missing_ok=True)
    return digest.hexdigest(), size


def _write_json(path: Path, data: Any) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True, default=str), encoding="utf-8")
    os.replace(tmp, path)


# ------------------------------------------------------------------ network stage out

def export_network(run_dir: Path, out_dir: Path) -> dict[str, Any]:
    """Copy a network-only shard into ``out_dir`` (new or empty) and write ``export_manifest.json`` with the checksums."""
    from scanner.internet import pipeline        # imported here: pipeline is heavy and this module is also used for verification
    run_dir, out_dir = Path(run_dir), Path(out_dir)
    manifest = pipeline.read_network_manifest(run_dir)
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ConfigError(f"{out_dir} is not empty")
    wanted = ["manifest.json", "config.snapshot.json", "scanned_ips.txt", "work/facts.sqlite",
              "normalized/tool_jobs.jsonl", "normalized/http_documents.jsonl"]
    files: dict[str, dict[str, Any]] = {}
    for rel in wanted:
        src = outputs.resolve(run_dir / rel)
        if not src.is_file():
            if rel in ("manifest.json", "config.snapshot.json", "work/facts.sqlite"):
                raise ConfigError(f"{run_dir / rel} is missing")
            continue                                   # no listing of targets, or no HTTP page was stored
        stored = src.relative_to(run_dir).as_posix()
        sha, size = _copy(src, out_dir / stored)
        files[stored] = {"sha256": sha, "bytes": size}
    record = {"exported_at": time.time(), "run_id": manifest.get("run_id"), "config_checksum": manifest.get("config_checksum"),
              "shard": manifest.get("shard"), "files": files}
    _write_json(out_dir / EXPORT_MANIFEST, record)
    return record


def verify_export(run_dir: Path) -> list[str]:
    """Problems found in an exported directory (none when it has no export manifest: it was not exported)."""
    path = Path(run_dir) / EXPORT_MANIFEST
    if not path.is_file():
        return []
    problems = []
    for rel, rec in sorted(json.loads(path.read_text(encoding="utf-8"))["files"].items()):
        target = Path(run_dir) / rel
        if not target.is_file():
            problems.append(f"{rel} is missing")
        elif sha256_of(target) != rec["sha256"]:
            problems.append(f"{rel} does not match its checksum in {EXPORT_MANIFEST}")
    return problems


# ------------------------------------------------------------------ favicon outputs back

def _declared(manifest: dict[str, Any]) -> dict[str, str]:
    """Checksums the favicon run's manifest holds for the files that come back: the record log and the icon store."""
    sums = manifest.get("output_checksums") or {}
    return {rel: sha for rel, sha in sums.items() if rel in (RECORDS, RECORDS + ".zst") or rel.startswith("favicons/")}


def import_favicons(run_dir: Path, source: Path) -> dict[str, Any]:
    """Verify the favicon outputs of ``source`` against its manifest and copy them into ``run_dir`` (a network-only shard).

    Nothing is copied unless every file listed matches its checksum. A record log already present in ``run_dir`` that
    differs from the incoming one is never replaced. Returns the record that is also written to ``favicon_import.json``.
    """
    from scanner.internet import pipeline
    run_dir, source = Path(run_dir), Path(source)
    target = pipeline.read_network_manifest(run_dir)
    try:
        theirs = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"{source} has no readable manifest ({exc})") from exc
    if theirs.get("run_id") != target.get("run_id") or (theirs.get("shard") or {}).get("index") != (target.get("shard") or {}).get("index"):
        raise ConfigError("the favicon run belongs to a different shard run than the directory it is imported into")
    declared = _declared(theirs)
    if not any(rel.startswith("raw/favicon_records") for rel in declared):
        raise ConfigError(f"the manifest of {source} lists no favicon record file")
    problems = []
    for rel, sha in sorted(declared.items()):
        path = source / rel
        if not path.is_file():
            problems.append(f"{rel} is missing")
        elif sha256_of(path) != sha:
            problems.append(f"{rel} does not match the checksum in the manifest")
    if problems:
        raise ConfigError("nothing was imported: " + "; ".join(problems[:5]))

    imported: dict[str, dict[str, Any]] = {}
    for rel, sha in sorted(declared.items()):
        src = source / rel
        if rel == RECORDS + ".zst":
            dest_rel, content_sha = RECORDS, ((theirs.get("compaction") or {}).get("files") or {}).get(rel, {}).get("content_sha256")
            _unpack(src, run_dir / dest_rel, content_sha)
            imported[dest_rel] = {"sha256": content_sha or sha256_of(run_dir / dest_rel), "from": rel}
            continue
        dest = run_dir / rel
        if rel == RECORDS and dest.is_file() and sha256_of(dest) != sha:
            raise ConfigError(f"{dest} already exists and differs from the incoming record file")
        if dest.is_file() and sha256_of(dest) == sha:
            imported[rel] = {"sha256": sha, "from": rel}
            continue
        _copy(src, dest)
        if sha256_of(dest) != sha:
            raise OSError(f"{rel} does not match its checksum after the copy")
        imported[rel] = {"sha256": sha, "from": rel}
    record = {"imported_at": time.time(), "source_run": str(source), "run_id": theirs.get("run_id"),
              "files": dict(sorted(imported.items())), "verified_against": "output_checksums of the source manifest"}
    _write_json(run_dir / IMPORT_RECORD, record)
    return record


def _unpack(packed: Path, dest: Path, content_sha: str | None) -> None:
    """Decompress a compacted record log to ``dest``; it must hash to ``content_sha`` when the manifest gives one."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    digest = hashlib.sha256()
    try:
        with outputs.open_zstd(packed) as fin, open(tmp, "wb") as fout:
            for block in iter(lambda: fin.read(BLOCK), b""):
                digest.update(block)
                fout.write(block)
        if content_sha is not None and digest.hexdigest() != content_sha:
            raise ConfigError(f"{packed.name} does not decompress to the content the manifest recorded")
        if dest.is_file() and sha256_of(dest) != digest.hexdigest():
            raise ConfigError(f"{dest} already exists and differs from the incoming record file")
        os.replace(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)

