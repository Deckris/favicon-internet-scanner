"""Content-addressed store for favicon images that decoded successfully.

Each distinct image is written once as ``<sha256>.<ext>`` under ``favicons/``;
``index.jsonl`` then lists where every image was observed. Bodies that did not
decode as an image (HTML catch-all pages, error pages) are never stored.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

# SVG is stored as text so opening the file in a browser cannot run script it may contain.
_MAGIC = (
    (b"\x00\x00\x01\x00", "ico"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"\xff\xd8\xff", "jpg"),
    (b"BM", "bmp"),
)


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

    def write_index(self, records: list[dict[str, Any]]) -> int:
        """One line per stored image, with every endpoint/name it was observed on. Returns the line count."""
        by_sha: dict[str, dict[str, Any]] = {}
        for rec in records:
            sha = rec.get("favicon_sha256")
            rel = self.path_for(sha)
            if not rec.get("favicon_is_image") or rel is None:
                continue
            entry = by_sha.setdefault(sha, {
                "sha256": sha, "file": rel, "bytes": rec.get("favicon_bytes"), "mmh3": rec.get("favicon_mmh3"),
                "content_type_claimed": rec.get("favicon_content_type"), "observations": [],
            })
            entry["observations"].append({
                "ip": rec.get("ip"), "port": rec.get("port"), "scheme": rec.get("scheme"), "hostname": rec.get("hostname"),
                "page_url": rec.get("url"), "page_title": rec.get("document_title"), "icon_url": rec.get("favicon_url"),
            })
        self.root.mkdir(parents=True, exist_ok=True)
        with (self.root / "index.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
            for entry in sorted(by_sha.values(), key=lambda e: (-len(e["observations"]), e["sha256"])):
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return len(by_sha)
