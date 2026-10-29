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

``iter_endpoint_rows`` and ``iter_hostname_rows`` yield the rows of either schema in the schema 1 shape.
Both files are written in the same ``(ip, port)`` order, so the join is a single streaming merge.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Iterator

try:
    import zstandard
except ImportError:         # the run then stores plain files and the manifest says so
    zstandard = None

OUTPUT_SCHEMA = 2
ZSTD_LEVEL = 3
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
})

# Column order of hostname_resolution.csv. The columns up to ``direct_icon_embedded_images`` are the endpoint's;
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
)
_NAME_HEAD = ("hostname", "hostname_sources", "dns_status", "cname_chain", "a_answers", "aaaa_answers", "maps_to_scanned_ip")
_NAME_TAIL = (
    "sni_certificate_sha256", "sni_certificate_hostname_match",
    "hostname_favicon_outcome", "hostname_favicon_is_image", "hostname_favicon_sha256", "hostname_favicon_file",
    "hostname_favicon_mmh3", "hostname_favicon_md5", "hostname_favicon_url", "hostname_document_title",
    "hostname_icon_offhost_hosts", "hostname_icon_embedded_images", "final_hostname_status", "icon_scope",
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


def open_binary(path: Any) -> Any:
    """The decompressed byte stream of a stored file (the file itself when it is not compressed)."""
    path = Path(path)
    if not is_compressed(path):
        return open(path, "rb")
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
    with path.open(encoding="utf-8") as fh:
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
            sink.write({c: row[c] for c in columns})
    return out_path
