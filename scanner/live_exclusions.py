"""Live exclusions overlay: opt-outs that take effect while a campaign runs.

The base exclusions file is part of the config checksum, so changing it starts a new campaign. The overlay is a
second, optional file of CIDRs (one per line, ``#`` starts a comment) that is read again whenever its modification
time or size changes. It never enters the checksum. Every request path asks the target policy, and the policy asks
the overlay, so an address listed here is dropped before anything is sent to it.

A file with a malformed line is rejected as a whole: the last good overlay stays in force and the rejection is
logged. Write the file by renaming a finished copy into place so that a reader never sees half a file.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scanner.safety import _NetSet

log = logging.getLogger(__name__)

MIN_CHECK_INTERVAL = 1.0        # seconds between stat calls made by per-address checks; batches and sweeps force a check


class OverlayError(ValueError):
    """The overlay file cannot be used (unreadable or a malformed line)."""


def parse_overlay(text: str) -> list[ipaddress.IPv4Network]:
    """IPv4 networks of an overlay file. Any malformed line raises ``OverlayError`` naming the line number.

    IPv6 entries are accepted and ignored, as in the base exclusions file. A bare address is a /32."""
    nets: list[ipaddress.IPv4Network] = []
    bad: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            bad.append(f"line {number}: {entry[:80]!r}")
            continue
        if net.version == 4:
            nets.append(net)
    if bad:
        raise OverlayError("malformed overlay " + ("entry " if len(bad) == 1 else "entries ") + "; ".join(bad[:5])
                           + (f" (and {len(bad) - 5} more)" if len(bad) > 5 else ""))
    return nets


def _now() -> str:
    return datetime.now(UTC).isoformat()


class LiveExclusions:
    """Watches one overlay file. Thread safe; shared by every policy of a process that names the same file."""

    def __init__(self, path: str | os.PathLike[str], *, min_interval: float = MIN_CHECK_INTERVAL,
                 clock: Any = time.monotonic) -> None:
        self.path = Path(path)
        self._min_interval = min_interval
        self._clock = clock
        self._lock = threading.RLock()
        self._index = _NetSet(())
        self._cidrs: list[str] = []
        self._sha256 = ""
        self._stamp: tuple[int, int] | None = None      # (mtime_ns, size) of the last file state looked at
        self._checked_at = float("-inf")
        self.events: list[dict[str, Any]] = []          # reloads and rejections, in order
        self.batches: list[dict[str, Any]] = []         # per batch or sweep: stage, size, dropped, overlay sha256
        self.dropped: Counter[str] = Counter()          # addresses refused by the overlay, by stage
        self.refresh(force=True, initial=True)

    # ------------------------------------------------------------------ reading

    def refresh(self, *, force: bool = False, initial: bool = False) -> bool:
        """Re-read the file when it changed. Returns True when a new overlay is in force. ``force`` skips the
        rate limit on stat calls (used before each batch and sweep)."""
        with self._lock:
            now = self._clock()
            if not force and now - self._checked_at < self._min_interval:
                return False
            self._checked_at = now
            try:
                st = self.path.stat()
            except FileNotFoundError:
                if self._stamp is not None or initial:     # removed after being read, or absent at start
                    self._stamp = None
                    self._event("missing", error="overlay file does not exist; the last good overlay (if any) stays in force")
                return False
            except OSError as exc:
                self._event("rejected", error=f"cannot stat overlay: {exc}")
                return False
            stamp = (st.st_mtime_ns, st.st_size)
            if stamp == self._stamp:
                return False
            self._stamp = stamp
            data = b""
            try:
                data = self.path.read_bytes()
                nets = parse_overlay(data.decode("utf-8"))
            except (OSError, UnicodeDecodeError, OverlayError) as exc:
                self._event("rejected", error=str(exc), sha256=hashlib.sha256(data).hexdigest() if data else "")
                if initial:
                    raise OverlayError(f"exclusions overlay {self.path}: {exc}") from exc
                return False
            collapsed = list(ipaddress.collapse_addresses(nets))
            self._index = _NetSet(collapsed)
            self._cidrs = sorted(str(n) for n in collapsed)
            self._sha256 = hashlib.sha256(data).hexdigest()
            self._event("loaded", sha256=self._sha256, entries=len(self._cidrs))
            return True

    def _event(self, kind: str, **fields: Any) -> None:
        rec = {"event": kind, "at": _now(), "path": str(self.path), **fields}
        self.events.append(rec)
        if kind == "loaded":
            log.info("exclusions overlay loaded: %s entries, sha256 %s", fields.get("entries"), fields.get("sha256"))
        else:
            log.error("exclusions overlay %s: %s", kind, fields.get("error"))

    # ------------------------------------------------------------------ queries

    def contains(self, address: ipaddress.IPv4Address) -> bool:
        self.refresh()
        return address in self._index

    def cidrs(self) -> list[str]:
        with self._lock:
            return list(self._cidrs)

    @property
    def sha256(self) -> str:
        return self._sha256

    # ------------------------------------------------------------------ records

    def begin_run(self) -> None:
        """Start the records of a new run in a process that outlives runs: the overlay in force is logged first."""
        with self._lock:
            self.events.clear()
            self.batches.clear()
            self.dropped.clear()
            if self._sha256:
                self._event("loaded", sha256=self._sha256, entries=len(self._cidrs), reason="in force at start of run")

    def count_drop(self, stage: str) -> None:
        with self._lock:
            self.dropped[stage] += 1

    def note_batch(self, stage: str, label: str, size: int, dropped: int) -> None:
        with self._lock:
            self.batches.append({"at": _now(), "stage": stage, "label": label, "size": size, "dropped": dropped,
                                 "overlay_sha256": self._sha256, "overlay_entries": len(self._cidrs)})

    def records(self) -> list[dict[str, Any]]:
        """Reloads, rejections and batches in time order, one JSON object each."""
        with self._lock:
            rows = [{"record": "event", **e} for e in self.events] + [{"record": "batch", **b} for b in self.batches]
        return sorted(rows, key=lambda r: r["at"])

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return {"path": str(self.path), "sha256": self._sha256, "entries": len(self._cidrs),
                    "reloads": sum(1 for e in self.events if e["event"] == "loaded"),
                    "rejected": sum(1 for e in self.events if e["event"] == "rejected"),
                    "dropped_by_stage": dict(self.dropped), "dropped_total": sum(self.dropped.values()),
                    "batches_with_drops": sum(1 for b in self.batches if b["dropped"])}


_SHARED: dict[str, LiveExclusions] = {}
_SHARED_LOCK = threading.Lock()


def overlay_for(path: str | os.PathLike[str] | None) -> LiveExclusions | None:
    """The process-wide watcher of ``path`` (None when no overlay is configured)."""
    if not path:
        return None
    key = os.path.abspath(os.fspath(path))
    with _SHARED_LOCK:
        found = _SHARED.get(key)
        if found is None:
            found = _SHARED[key] = LiveExclusions(key)
        return found
