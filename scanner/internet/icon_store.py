"""Content-addressed store for favicon images that decoded successfully.

Each distinct image is written once as ``<sha256>.<ext>`` under ``favicons/``;
``index.jsonl`` then lists where every image was observed. Bodies that did not
decode as an image (HTML catch-all pages, error pages) are never stored.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

# SVG is stored as text so opening the file in a browser cannot run script it may contain.
_MAGIC = (
    (b"\x00\x00\x01\x00", "ico"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"\xff\xd8\xff", "jpg"),
    (b"BM", "bmp"),
)


def _scrub(value: Any) -> Any:
    """Replace lone surrogates (they cannot be encoded as UTF-8), the way the run outputs do."""
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    return value


def image_extension(body: bytes) -> str:
    for prefix, ext in _MAGIC:
        if body.startswith(prefix):
            return ext
    if body[:4] == b"RIFF" and body[8:12] == b"WEBP":
        return "webp"
    head = body[:512].lstrip().lower()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in body[:2048].lower()):
        return "svg.txt"
    return "bin"


class IconStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._lock = threading.Lock()
        self._files: dict[str, str] = {}

    def save(self, sha256: str, body: bytes) -> str:
        """Write ``body`` once and return its path relative to the run directory (``favicons/<sha>.<ext>``)."""
        with self._lock:
            known = self._files.get(sha256)
            if known is not None:
                return known
            name = f"{sha256}.{image_extension(body)}"
            self.root.mkdir(parents=True, exist_ok=True)
            target = self.root / name
            if not target.exists():
                tmp = target.with_name(target.name + ".tmp")
                tmp.write_bytes(body)
                os.replace(tmp, target)
            rel = f"{self.root.name}/{name}"
            self._files[sha256] = rel
            return rel

    def path_for(self, sha256: str | None) -> str | None:
        if not sha256:
            return None
        with self._lock:
            return self._files.get(sha256)

    def __len__(self) -> int:
        with self._lock:
            return len(self._files)

    def write_index(self, records: Iterable[dict[str, Any]], *, spool: Path | None = None) -> int:
        """One line per stored image, with every endpoint/name it was observed on. Returns the line count.

        ``records`` may be an iterator. Without ``spool`` the observations are grouped in memory; with it they are
        collected in a temporary SQLite file at that path, so the memory held does not grow with the number of
        observations. The file is removed afterwards. Both give the same index.
        """
        if spool is None:
            return self._write_index_memory(records)
        return self._write_index_spooled(records, Path(spool))

    def _entry(self, rec: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]] | None:
        sha = rec.get("favicon_sha256")
        rel = self.path_for(sha)
        if not rec.get("favicon_is_image") or rel is None:
            return None
        head = {
            "sha256": sha, "file": rel, "bytes": rec.get("favicon_bytes"), "mmh3": rec.get("favicon_mmh3"), "md5": rec.get("favicon_md5"),
            "content_type_claimed": rec.get("favicon_content_type"),
        }
        seen = {
            "ip": rec.get("ip"), "port": rec.get("port"), "scheme": rec.get("scheme"), "hostname": rec.get("hostname"),
            "page_url": rec.get("url"), "page_title": rec.get("document_title"), "icon_url": rec.get("favicon_url"),
        }
        return sha, _scrub(head), _scrub(seen)

    def _write_index_memory(self, records: Iterable[dict[str, Any]]) -> int:
        by_sha: dict[str, dict[str, Any]] = {}
        for rec in records:
            found = self._entry(rec)
            if found is None:
                continue
            sha, head, seen = found
            entry = by_sha.setdefault(sha, {**head, "observations": []})
            entry["observations"].append(seen)
        self.root.mkdir(parents=True, exist_ok=True)
        with (self.root / "index.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
            for entry in sorted(by_sha.values(), key=lambda e: (-len(e["observations"]), e["sha256"])):
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return len(by_sha)

    def _write_index_spooled(self, records: Iterable[dict[str, Any]], spool: Path) -> int:
        spool.parent.mkdir(parents=True, exist_ok=True)
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                os.remove(str(spool) + suffix)
            except FileNotFoundError:
                pass
        db = sqlite3.connect(str(spool), isolation_level=None)
        try:
            db.execute("PRAGMA journal_mode=OFF")
            db.execute("PRAGMA synchronous=OFF")
            db.execute("PRAGMA temp_store=FILE")
            db.execute("CREATE TABLE images (sha TEXT PRIMARY KEY, head TEXT NOT NULL, n INTEGER NOT NULL) WITHOUT ROWID")
            db.execute("CREATE TABLE seen (sha TEXT NOT NULL, seq INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY (sha, seq)) WITHOUT ROWID")
            pending_heads: list[tuple[str, str]] = []
            pending_seen: list[tuple[str, int, str]] = []
            counts: dict[str, int] = {}

            def flush() -> None:
                db.execute("BEGIN")
                db.executemany("INSERT OR IGNORE INTO images (sha, head, n) VALUES (?,?,0)", pending_heads)
                db.executemany("INSERT INTO seen (sha, seq, data) VALUES (?,?,?)", pending_seen)
                db.executemany("UPDATE images SET n = n + ? WHERE sha = ?", [(n, sha) for sha, n in counts.items()])
                db.execute("COMMIT")
                pending_heads.clear()
                pending_seen.clear()
                counts.clear()

            seq = 0
            for rec in records:
                found = self._entry(rec)
                if found is None:
                    continue
                sha, head, seen = found
                pending_heads.append((sha, json.dumps(head, ensure_ascii=False)))
                pending_seen.append((sha, seq, json.dumps(seen, ensure_ascii=False)))
                counts[sha] = counts.get(sha, 0) + 1
                seq += 1
                if len(pending_seen) >= 1000:
                    flush()
            flush()
            self.root.mkdir(parents=True, exist_ok=True)
            total = 0
            with (self.root / "index.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
                for sha, head in db.execute("SELECT sha, head FROM images ORDER BY n DESC, sha").fetchall():
                    fh.write(head[:-1] + ', "observations": [')
                    first = True
                    last = -1
                    while True:
                        rows = db.execute("SELECT seq, data FROM seen WHERE sha = ? AND seq > ? ORDER BY seq LIMIT 500", (sha, last)).fetchall()
                        if not rows:
                            break
                        for last, data in rows:
                            fh.write(data if first else ", " + data)
                            first = False
                    fh.write("]}\n")
                    total += 1
            return total
        finally:
            db.close()
            for suffix in ("", "-wal", "-shm", "-journal"):
                try:
                    os.remove(str(spool) + suffix)
                except FileNotFoundError:
                    pass
