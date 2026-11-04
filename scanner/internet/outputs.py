"""Stored form of a run's outputs, and readers that hide it.

Output schema 2 (``output_schema`` in the manifest; absent means 1) changes two things:

* ``normalized/hostname_resolution.jsonl`` no longer repeats the endpoint columns. A row holds the key
  (``target_ip``, ``port``, ``hostname``) and the hostname-level fields listed in ``HOSTNAME_FIELDS``; everything
  else on a schema 1 row is the endpoint's own record in ``normalized/endpoints.jsonl`` (all of its fields except
  ``hostnames``) and is joined back on ``(target_ip, port)``. ``hostname_resolution.csv`` is no longer written;
  ``export_csv`` (``python -m scanner.internet export-csv RUN_DIR``) produces it from the rows.
* The raw ZGrab2 and ZDNS batch files are stored as ``<job>.jsonl.zst`` (zstd, level 3) when the ``zstandard``
  package is available, and as plain ``<job>.jsonl`` otherwise; the manifest says which (``compression``).
  The checksums of those files in the manifest and in the tool jobs are over the stored bytes, i.e. the compressed
  file. The compressed bytes of a batch depend on how the tool's output was cut into reads, so they are not
  reproducible between runs; the decompressed content is. A batch is compressed while the tool's output
  arrives, so a run that dies mid-batch leaves a frame cut short, which still reads up to the cut.
* When a shard has finished cleanly its record files (``normalized/*.jsonl``, ``raw/favicon_records.jsonl`` and
  ``ip_results.csv``) are compacted to ``<name>.zst`` (``compact_run``; ``output.compact`` in the configuration turns
  it off). The readers here and ``RecordLog`` open a path through ``resolve``, so they read the plain or the compressed
  file alike. The manifest keeps the checksum of the stored bytes in ``output_checksums`` and, under ``compaction``,
  the checksum and size of the content as well. The original is removed only after the compressed copy has been
  written, flushed, read back and found identical, so a crash leaves one of the two intact.
* ``prune_raw`` (``python -m scanner.internet prune-raw RUN_DIR``) deletes the ``raw/`` directory of a compacted run
  once the files of its manifest have been re-hashed and the tables the analysis reads are there. The manifest is left
  as it is; ``raw_pruned.json`` records what was removed.

Output schema 3 only adds fields: the time each stage's request was made (``l4_seen_at``, ``tls_at``, ``http_at``,
``direct_favicon_at``, ``direct_document_captured_at`` on endpoint rows; ``dns_at``, ``sni_at``, ``hostname_favicon_at``,
``hostname_document_captured_at`` on hostname rows), per-batch ``stats`` on the tool jobs, and the resolver and
``epoch_id`` in the manifest. Rows of a schema 1 or 2 run lack them; the readers here accept those runs unchanged
and ``export_csv`` leaves the cells empty.

``iter_endpoint_rows`` and ``iter_hostname_rows`` yield the rows of any schema in the schema 1 shape.
Both files are written in the same ``(ip, port)`` order, so the join is a single streaming merge.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterator

try:
    import zstandard
except ImportError:         # the run then stores plain files and the manifest says so
    zstandard = None

OUTPUT_SCHEMA = 3
ZSTD_LEVEL = 3
COMPACT_LEVEL = 12          # about 20 times faster than level 19 for a few percent more bytes (measured); paid once per shard
COMPRESSION = "zstd" if zstandard is not None else "none"
RAW_SUFFIX = ".jsonl.zst" if zstandard is not None else ".jsonl"
COMPRESSION_NOTE = None if zstandard is not None else "zstandard is not installed; raw batch files are stored uncompressed"

KEY_FIELDS = ("target_ip", "port")

# The fields of a hostname row that describe the name, not the endpoint it was found on.
HOSTNAME_FIELDS = frozenset({
    "hostname", "hostname_sources", "dns_status", "cname_chain", "a_answers", "aaaa_answers", "maps_to_scanned_ip",
    "sni_skipped_reason", "sni_confirmation_attempted", "sni_confirmation_result", "sni_confirmation_outcome",
    "sni_certificate_sha256", "sni_certificate_hostname_match",
    "hostname_favicon_outcome", "hostname_favicon_is_image", "hostname_favicon_sha256", "hostname_favicon_file",
    "hostname_favicon_mmh3", "hostname_favicon_md5", "hostname_favicon_url", "hostname_document_title",
    "hostname_icon_offhost_hosts", "hostname_icon_embedded_images", "final_hostname_status", "icon_scope",
    "dns_at", "sni_at", "hostname_favicon_at", "hostname_document_captured_at",
})

# Fields added by output schema 3; rows of an older run do not have them.
CONTEXT_FIELDS = frozenset({
    "l4_seen_at", "tls_at", "http_at", "direct_favicon_at", "direct_document_captured_at",
    "dns_at", "sni_at", "hostname_favicon_at", "hostname_document_captured_at",
})

# Column order of hostname_resolution.csv. The columns up to ``direct_document_captured_at`` are the endpoint's;
# the rest follow in the order of the first row, which differs between an address with names and one without
# (``sni_skipped_reason`` sits before or after the other SNI columns), so the first row picks the layout.
_ENDPOINT_COLUMNS = (
    "target_ip", "port", "zmap_result", "asn", "asn_prefix", "cloud_cdn_flag", "cloud_cdn_class", "protocol",
    "tarpit_suspect", "tarpit_confidence", "tarpit_signals", "tarpit_reason", "open_port_count",
    "synack_window", "synack_ttl", "tls_status", "tls_outcome", "tls_failure_reason", "tls_version", "tls_cipher",
    "certificate_present", "certificate_sha256", "certificate_cn", "certificate_sans", "certificate_san_count",
    "certificate_not_before", "certificate_not_after", "certificate_self_signed", "certificate_expired",
    "certificate_not_yet_valid", "certificate_parse_error", "certificate_wildcards",
    "http_zgrab_status", "http_status", "http_location", "http_error", "ptr_status", "ptr_names", "ptr_name_count",
    "run_incomplete", "candidate_names_total", "candidate_names_truncated", "dropped_names",
    "direct_favicon_outcome", "direct_favicon_is_image", "direct_favicon_sha256", "direct_favicon_file",
    "direct_favicon_mmh3", "direct_favicon_md5", "direct_favicon_url", "direct_document_outcome",
    "direct_document_status", "direct_document_title", "direct_document_body_sha256", "direct_icon_declared_count",
    "direct_icon_offhost_hosts", "direct_icon_embedded_images",
    "l4_seen_at", "tls_at", "http_at", "direct_favicon_at", "direct_document_captured_at",
)
_NAME_HEAD = ("hostname", "hostname_sources", "dns_status", "cname_chain", "a_answers", "aaaa_answers", "maps_to_scanned_ip")
_NAME_TAIL = (
    "sni_certificate_sha256", "sni_certificate_hostname_match",
    "hostname_favicon_outcome", "hostname_favicon_is_image", "hostname_favicon_sha256", "hostname_favicon_file",
    "hostname_favicon_mmh3", "hostname_favicon_md5", "hostname_favicon_url", "hostname_document_title",
    "hostname_icon_offhost_hosts", "hostname_icon_embedded_images", "final_hostname_status", "icon_scope",
    "dns_at", "sni_at", "hostname_favicon_at", "hostname_document_captured_at",
)
CSV_COLUMNS_NAMED = (_ENDPOINT_COLUMNS + _NAME_HEAD
                     + ("sni_skipped_reason", "sni_confirmation_attempted", "sni_confirmation_result", "sni_confirmation_outcome")
                     + _NAME_TAIL)
CSV_COLUMNS_UNNAMED = (_ENDPOINT_COLUMNS + _NAME_HEAD
                       + ("sni_confirmation_attempted", "sni_confirmation_result", "sni_confirmation_outcome", "sni_skipped_reason")
                       + _NAME_TAIL)


# ---------------------------------------------------------------- stored files

def raw_name(job_id: str) -> str:
    """File name of a raw tool batch in this environment."""
    return f"{job_id}{RAW_SUFFIX}"


def is_compressed(path: Any) -> bool:
    return str(path).endswith(".zst")


def new_compressor() -> Any:
    return zstandard.ZstdCompressor(level=ZSTD_LEVEL).compressobj()


def compress_bytes(data: bytes) -> bytes:
    return zstandard.ZstdCompressor(level=ZSTD_LEVEL).compress(data)


def resolve(path: Any) -> Path:
    """The stored file behind ``path``: the plain file when it exists, else its ``.zst`` twin, else ``path`` itself.

    The plain file wins while both exist: that is a compaction that stopped before the original was removed, and
    the original is the complete one.
    """
    path = Path(path)
    if path.exists() or is_compressed(path):
        return path
    packed = path.with_name(path.name + ".zst")
    return packed if packed.exists() else path


def exists(path: Any) -> bool:
    return resolve(path).exists()


def open_binary(path: Any) -> Any:
    """The decompressed byte stream of a stored file (the file itself when it is not compressed).

    A plain name whose file has been compacted opens its ``.zst`` twin.
    """
    path = resolve(path)
    return open_zstd(path) if is_compressed(path) else open(path, "rb")


def open_zstd(path: Path) -> Any:
    """The decompressed stream of a zstd file, whatever its name."""
    if zstandard is None:
        raise RuntimeError(f"{path.name} is zstd-compressed but the zstandard package is not installed")
    fh = open(path, "rb")
    try:
        return zstandard.ZstdDecompressor().stream_reader(fh, read_across_frames=True, closefd=True)
    except BaseException:
        fh.close()
        raise


def open_text(path: Any) -> Any:
    """UTF-8 text stream over a stored file, split on newline only."""
    return io.TextIOWrapper(open_binary(path), encoding="utf-8", newline="\n")


def read_text(path: Any) -> str:
    with open_text(path) as fh:
        return fh.read()


def iter_lines(path: Any) -> Iterator[str]:
    """Lines of a stored file, one at a time, split on newline only (like ``str.split``)."""
    with open_text(path) as fh:
        for line in fh:
            yield line[:-1] if line.endswith("\n") else line


# ---------------------------------------------------------------- rows

def output_schema(run_dir: Path) -> int:
    try:
        manifest = json.loads((Path(run_dir) / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 1
    return int(manifest.get("output_schema") or 1) if isinstance(manifest, dict) else 1


def _jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with open_text(path) as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def iter_endpoint_rows(run_dir: Any) -> Iterator[dict[str, Any]]:
    """The rows of normalized/endpoints.jsonl."""
    yield from _jsonl(Path(run_dir) / "normalized" / "endpoints.jsonl")


def slim_hostname_row(row: dict[str, Any]) -> dict[str, Any]:
    """The schema 2 form of a (full) hostname row."""
    return {k: v for k, v in row.items() if k in KEY_FIELDS or k in HOSTNAME_FIELDS}


def iter_hostname_rows(run_dir: Any) -> Iterator[dict[str, Any]]:
    """The rows of normalized/hostname_resolution.jsonl in their full (schema 1) shape, for either schema."""
    run_dir = Path(run_dir)
    rows = _jsonl(run_dir / "normalized" / "hostname_resolution.jsonl")
    if output_schema(run_dir) < 2:
        yield from rows
        return
    endpoints = iter_endpoint_rows(run_dir)
    key: tuple[Any, Any] | None = None
    base: dict[str, Any] = {}
    for row in rows:
        want = (row["target_ip"], row["port"])
        while key != want:
            ep = next(endpoints, None)
            if ep is None:
                raise ValueError(f"hostname row {want[0]}:{want[1]} has no endpoint row in endpoints.jsonl")
            key = (ep["target_ip"], ep["port"])
            base = {k: v for k, v in ep.items() if k != "hostnames"}
        yield {**base, **row}


# ---------------------------------------------------------------- csv

def csv_cell(v: Any) -> Any:
    if isinstance(v, (list, dict, bool)):
        return json.dumps(v)
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", chr(9), chr(13)):
        return "'" + v        # neutralize spreadsheet formula injection from hostile certificate/PTR text
    return v


class CsvSink:
    """CSV rows written one by one; the header is the keys of the first row, and no row leaves an empty file."""

    def __init__(self, out: Any) -> None:
        self._out = out
        self._writer: csv.DictWriter | None = None

    def write(self, row: dict[str, Any]) -> None:
        if self._writer is None:
            self._writer = csv.DictWriter(self._out, fieldnames=list(row.keys()))
            self._writer.writeheader()
        self._writer.writerow({k: csv_cell(v) for k, v in row.items()})


def export_csv(run_dir: Any, out_path: Any | None = None) -> Path:
    """Write the hostname_resolution.csv of a run (default: next to the JSONL file); returns its path."""
    run_dir = Path(run_dir)
    out_path = Path(out_path) if out_path else run_dir / "normalized" / "hostname_resolution.csv"
    columns: tuple[str, ...] | None = None
    with open(out_path, "w", encoding="utf-8", newline="") as out:
        sink = CsvSink(out)
        for row in iter_hostname_rows(run_dir):
            if columns is None:
                columns = CSV_COLUMNS_UNNAMED if row["hostname"] is None else CSV_COLUMNS_NAMED
            sink.write({c: row.get(c) if c in CONTEXT_FIELDS else row[c] for c in columns})
    return out_path


# ---------------------------------------------------------------- compaction

COMPACT_GLOBS = ("normalized/*.jsonl", "raw/favicon_records.jsonl", "ip_results.csv")


def _sha256_stream(path: Path, *, compressed: bool) -> tuple[str, int]:
    """SHA-256 and length of a file's content (decompressed when ``compressed``)."""
    digest, size = hashlib.sha256(), 0
    with (open_zstd(path) if compressed else open(path, "rb")) as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def _sha256_file(path: Path) -> str:
    return _sha256_stream(path, compressed=False)[0]


class _HashingReader:
    """Read side of ``copy_stream`` that hashes what passes through."""

    def __init__(self, fh: Any) -> None:
        self._fh = fh
        self.digest = hashlib.sha256()
        self.size = 0

    def read(self, n: int = -1) -> bytes:
        block = self._fh.read(n)
        self.digest.update(block)
        self.size += len(block)
        return block


def _fsync_dir(path: Path) -> None:
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _compact_file(plain: Path, expected: str | None, level: int) -> dict[str, Any]:
    """Replace ``plain`` by ``plain.zst``; returns the manifest record. ``plain`` stays unless the copy is verified.

    The copy is written under a temporary name, flushed to disk and decompressed again; only when its content hashes
    to what was read from ``plain`` (and to ``expected``, the checksum the manifest holds, if it holds one) is it
    renamed into place and the original removed.
    """
    packed = plain.with_name(plain.name + ".zst")
    tmp = plain.with_name(plain.name + ".zst.tmp")
    try:
        with open(plain, "rb") as src, open(tmp, "wb") as dst:
            reader = _HashingReader(src)
            zstandard.ZstdCompressor(level=level).copy_stream(reader, dst, read_size=1 << 20, write_size=1 << 20)
            dst.flush()
            os.fsync(dst.fileno())
        content, length = reader.digest.hexdigest(), reader.size
        if expected is not None and expected != content:
            raise ValueError(f"{plain.name} does not match the checksum in the manifest")
        back, back_len = _sha256_stream(tmp, compressed=True)
        if (back, back_len) != (content, length):
            raise ValueError(f"{tmp.name} does not decompress to {plain.name}")
        stored = _sha256_file(tmp)
        stored_len = tmp.stat().st_size
        os.replace(tmp, packed)
        _fsync_dir(packed.parent)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    plain.unlink()
    _fsync_dir(packed.parent)
    return {"sha256": stored, "content_sha256": content, "bytes": stored_len, "content_bytes": length}


def _verify_packed(packed: Path, expected: str | None) -> dict[str, Any]:
    """The manifest record of a ``.zst`` whose original is already gone (a compaction that stopped before the manifest was written)."""
    content, length = _sha256_stream(packed, compressed=True)
    if expected is not None and expected != content:
        raise ValueError(f"{packed.name} does not match the checksum in the manifest")
    return {"sha256": _sha256_file(packed), "content_sha256": content, "bytes": packed.stat().st_size, "content_bytes": length}


def _write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(manifest, indent=2, default=str))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def compact_eligible(manifest: Any) -> bool:
    """A shard whose manifest says it finished cleanly. An incomplete, aborted or empty-handed one keeps its plain files."""
    return (isinstance(manifest, dict) and manifest.get("status") == "finished" and bool(manifest.get("complete"))
            and not manifest.get("zero_responsive") and not manifest.get("abort_reason"))


def compact_run(run_dir: Any, *, level: int = COMPACT_LEVEL, log: Callable[[str], None] | None = None) -> dict[str, Any]:
    """Compress the record files of a finished run in place and record them in its manifest.

    Safe to repeat and to call after a crash: a file already compacted is skipped, a ``.zst`` whose original was
    removed but which the manifest does not list yet is verified and listed, a leftover temporary file is replaced.
    Returns ``{"status": ..., "files": {name: record}}``; ``status`` is ``compacted`` when anything changed.
    """
    run_dir = Path(run_dir)
    say = log or (lambda text: print(text, file=sys.stderr, flush=True))
    if zstandard is None:
        return {"status": "unavailable", "files": {}}
    manifest_path = run_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"status": "skipped", "files": {}, "reason": "no readable manifest"}
    if not compact_eligible(manifest):
        return {"status": "skipped", "files": {}, "reason": "the run did not finish cleanly"}
    checksums = manifest.setdefault("output_checksums", {})
    section = manifest.get("compaction") if isinstance(manifest.get("compaction"), dict) else {}
    done: dict[str, Any] = dict(section.get("files") or {})
    found = {p.relative_to(run_dir).as_posix() for pattern in COMPACT_GLOBS for p in run_dir.glob(pattern)}
    found |= {p.relative_to(run_dir).as_posix()[:-4] for pattern in COMPACT_GLOBS for p in run_dir.glob(pattern + ".zst")}
    changed: dict[str, Any] = {}
    failed: dict[str, str] = {}
    for rel in sorted(found):
        plain, key = run_dir / rel, rel + ".zst"
        if key in done and not plain.exists():
            continue
        expected = checksums.get(rel) or (done.get(key) or {}).get("content_sha256")
        try:
            record = _compact_file(plain, expected, level) if plain.exists() else _verify_packed(run_dir / key, expected)
        except Exception as exc:        # the plain file stays: the run keeps working, and the next attempt tries again
            failed[rel] = f"{type(exc).__name__}: {exc}"[:300]
            say(f"[scanner] could not compact {rel}: {failed[rel]}")
            continue
        changed[key] = record
    if changed:
        done.update(changed)
        for key, record in changed.items():
            checksums.pop(key[:-4], None)
            checksums[key] = record["sha256"]
        manifest["compaction"] = {"zstd_level": level, "files": dict(sorted(done.items()))}
        manifest["output_checksums"] = dict(sorted(checksums.items()))
        _write_manifest(manifest_path, manifest)
    result: dict[str, Any] = {"status": "compacted" if changed else "unchanged", "files": changed}
    if failed:
        result["failed"] = failed
    return result


# ---------------------------------------------------------------- pruning raw/

# Written by every run that finishes cleanly, plain or compacted; the analysis reads them (the matcher needs the first three).
PRUNE_REQUIRES = ("ip_results.csv", "normalized/endpoints.jsonl", "normalized/hostname_resolution.jsonl",
                  "normalized/tool_jobs.jsonl", "normalized/policy_refusals.jsonl")


def _prune_refusal(run_dir: Path, manifest: Any) -> str | None:
    """Why ``raw/`` of this run may not be deleted, or None when it may."""
    if not isinstance(manifest, dict):
        return "no readable manifest"
    if not manifest.get("complete"):
        return "the manifest does not say the run is complete"
    if manifest.get("stage_errors"):
        return "the manifest lists stage errors"
    section = manifest.get("compaction")
    files = section.get("files") if isinstance(section, dict) else None
    if not isinstance(files, dict) or not files:
        return "the run has not been compacted (no compaction block in the manifest)"
    for rel, record in sorted(files.items()):
        target = (run_dir / rel).resolve()
        if run_dir.resolve() not in target.parents:
            return f"{rel} in the compaction block points outside the run"
        if not target.is_file():
            return f"{rel} from the compaction block is missing"
        if not isinstance(record, dict) or not record.get("sha256"):
            return f"{rel} has no recorded checksum"
        if _sha256_file(target) != record["sha256"]:
            return f"{rel} does not match its checksum in the manifest"
    for rel in PRUNE_REQUIRES:
        if not exists(run_dir / rel):
            return f"{rel} is missing"
    return None


def _atomic_json(path: Path, data: Any) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(data, indent=2, default=str))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def prune_raw(run_dir: Any) -> dict[str, Any]:
    """Delete ``raw/`` of a run whose outputs are complete, compacted and still match their checksums.

    Nothing is deleted unless the manifest says the run is complete without stage errors, every file of its
    ``compaction`` block is on disk with the recorded SHA-256, and the tables listed in ``PRUNE_REQUIRES`` exist.
    The manifest is not touched; ``raw_pruned.json`` holds the time, the bytes and file count removed and the raw
    files with the checksums the manifest recorded for them. ``raw/`` is renamed to ``raw.pruning`` before it is
    removed, so an interruption leaves a directory that a repeated call (it needs no further checks) finishes off.
    Returns ``{"status": "pruned" | "unchanged" | "refused" | "failed", ...}``; ``reason`` explains the last two.
    """
    run_dir = Path(run_dir)
    raw, pending, record_path = run_dir / "raw", run_dir / "raw.pruning", run_dir / "raw_pruned.json"
    if pending.exists():
        if raw.exists():
            return {"status": "refused", "reason": "raw and raw.pruning both exist"}
        resumed = True
    elif raw.is_dir():
        try:
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            manifest = None
        reason = _prune_refusal(run_dir, manifest)
        if reason is not None:
            return {"status": "refused", "reason": reason}
        os.replace(raw, pending)
        _fsync_dir(run_dir)
        resumed = False
    elif record_path.exists():
        return {"status": "unchanged", "reason": "raw/ was removed earlier"}
    else:
        return {"status": "refused", "reason": "there is no raw/ directory"}
    if not record_path.exists():
        recorded = _read_json(run_dir / "manifest.json").get("output_checksums") or {}
        listed = []
        for root, _dirs, names in os.walk(pending):
            for name in sorted(names):
                path = Path(root) / name
                rel = "raw/" + path.relative_to(pending).as_posix()
                listed.append({"file": rel, "bytes": path.lstat().st_size, "sha256": recorded.get(rel)})
        listed.sort(key=lambda item: item["file"])
        _atomic_json(record_path, {"pruned_at": time.time(), "files_removed": len(listed),
                                   "bytes_removed": sum(item["bytes"] for item in listed), "resumed": resumed, "files": listed})
    try:
        shutil.rmtree(pending)
    except OSError as exc:
        return {"status": "failed", "reason": f"raw.pruning could not be removed ({exc})"}
    _fsync_dir(run_dir)
    return {"status": "pruned", **{k: v for k, v in _read_json(record_path).items() if k != "files"}}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def tree_bytes(path: Any) -> int:
    """Bytes the files under ``path`` occupy (file sizes added up)."""
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                continue
    return total
