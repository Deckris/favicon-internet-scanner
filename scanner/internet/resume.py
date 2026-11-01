"""Resume of the network stages at their natural units.

A unit is one finished ZMap port sweep, one ZGrab2 batch (direct TLS, HTTP fallback, SNI confirmation), one PTR batch
or one DNS batch. When a unit is complete, the fact store (``work/facts.sqlite``) holds a record of it, written after
all the rows of the unit and as a commit of its own. The record's key is a hash over the identity of the run (config
checksum, shard, seed, ports), the stage and the unit's target list, so a unit can only be reused by an attempt that
would have run exactly the same thing. An attempt that continues an earlier one takes over that attempt's store, skips
the units on record, and runs every other unit from scratch: a unit that did not finish is never continued half way,
and its rows are replaced, not added to.

Nothing here talks to the network. Whether a reused unit is allowed to count as contact is the pipeline's business:
it waits one full pause before it contacts any address again, because the last contacts of the lost attempt are unknown.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Iterable

from scanner.internet import outputs
from scanner.models import ToolJob, canonical_json

SCHEMA = 1
STORE_SUFFIXES = ("", "-wal", "-shm", "-journal")
LISTED_UNITS = 500             # unit keys listed in the manifest; the counts per stage are always complete


def run_identity(cfg: Any) -> dict[str, Any]:
    """What a stored unit must have been produced under to be reused here."""
    m = cfg.measurement
    return {"resume_schema": SCHEMA, "config_checksum": cfg.checksum, "shard": cfg.shard, "shards": cfg.shards,
            "sample_seed": cfg.sample_seed, "zmap_seed": getattr(m, "zmap_seed", None), "ports": list(m.ports)}


def job_from_dict(d: dict[str, Any]) -> ToolJob:
    return ToolJob(**{**d, "command": tuple(d.get("command") or ())})


def adopt_store(source: Path, run_dir: Path, identity: dict[str, Any]) -> str | None:
    """Move the fact store of the unfinished attempt in ``source`` into ``run_dir/work``.

    Returns None when the store was taken over, else the reason it was left alone (it stays where it is).
    """
    src = Path(source) / "work" / "facts.sqlite"
    if not src.is_file():
        return "no fact store in the earlier attempt"
    try:
        db = sqlite3.connect(str(src), timeout=5)
        try:
            row = db.execute("SELECT value FROM meta WHERE key = 'identity'").fetchone()
        finally:
            db.close()
    except sqlite3.Error as exc:
        return f"the earlier fact store is unreadable ({type(exc).__name__})"
    if row is None:
        return "the earlier fact store carries no run identity"
    try:
        stored = json.loads(row[0])
    except ValueError:
        return "the earlier fact store carries an unreadable run identity"
    if stored != identity:
        differing = sorted(k for k in set(stored) | set(identity) if stored.get(k) != identity.get(k))
        return "the earlier attempt ran under a different " + ", ".join(differing)
    dst_dir = Path(run_dir) / "work"
    dst_dir.mkdir(parents=True, exist_ok=True)
    for suffix in STORE_SUFFIXES:
        part = Path(str(src) + suffix)
        if part.exists():
            target = dst_dir / ("facts.sqlite" + suffix)
            try:
                os.replace(part, target)
            except OSError:
                shutil.move(str(part), str(target))
    return None


class UnitBook:
    """The record of finished units in one attempt's fact store, and what this attempt reused from the earlier one."""

    def __init__(self, store: Any, identity: dict[str, Any], *, enabled: bool = True, source: Path | None = None,
                 run_dir: Path | None = None) -> None:
        self.store = store
        self.enabled = enabled
        self.source = Path(source) if source is not None else None
        self.run_dir = Path(run_dir) if run_dir is not None else None
        self._identity = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
        self._lock = threading.Lock()
        self.reused: list[str] = []
        self.reused_by_stage: dict[str, int] = {}
        self.run_by_stage: dict[str, int] = {}
        self.unlinked = 0

    def unit_id(self, stage: str, *parts: Any, items: Iterable[Any] = (), key: Callable[[Any], Any] | None = None) -> str:
        h = hashlib.sha256()
        h.update(self._identity.encode("ascii"))
        h.update(canonical_json([stage, *parts]).encode("utf-8"))
        for item in items:
            h.update(b"\n")
            h.update(repr(key(item) if key else item).encode("utf-8", "surrogatepass"))
        return f"{stage}:{h.hexdigest()[:40]}"

    def reuse(self, unit: str) -> list[ToolJob] | None:
        """The tool jobs of a finished unit (their raw files linked into this run), or None when it has to run."""
        if not self.enabled:
            return None
        row = self.store.get_unit(unit)
        if row is None:
            return None
        stage, _port, _size, text = row
        jobs = [job_from_dict(d) for d in json.loads(text)]
        if not all(self._take_raw(j) for j in jobs):
            self.store.forget_unit(unit)           # its raw files are gone: the unit runs again
            self.unlinked += 1
            return None
        with self._lock:
            self.reused.append(unit)
            self.reused_by_stage[stage] = self.reused_by_stage.get(stage, 0) + 1
        return jobs

    def commit(self, unit: str, stage: str, jobs: list[ToolJob], *, port: int | None = None, size: int = 0) -> bool:
        """Record a finished unit. A unit whose tools reported an error is not finished and is not recorded."""
        if not self.enabled or any(j.error for j in jobs):
            return False
        ok = self.store.put_unit(unit, stage, port, size, json.dumps([j.as_dict() for j in jobs], separators=(",", ":")))
        if ok:
            with self._lock:
                self.run_by_stage[stage] = self.run_by_stage.get(stage, 0) + 1
        return ok

    def _take_raw(self, job: ToolJob) -> bool:
        """Hard-link (else copy) the raw files of a reused job from the earlier attempt, unless this run already has them."""
        if self.run_dir is None:
            return True
        rel = Path(job.raw_path)
        mine = outputs.resolve(self.run_dir / rel)
        if mine.is_file():
            return True
        if self.source is None:
            return False
        there = outputs.resolve(self.source / rel)
        if not there.is_file():
            return False
        names = [there]
        stem = rel.name.rsplit(".", 1)[0]
        if rel.parent.name == "zmap":                # the allow and block lists the sweep was started with
            names += [p for p in there.parent.glob(f"{stem}-*") if p.is_file()]
        for src in names:
            dst = self.run_dir / rel.parent / src.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                continue
            try:
                os.link(src, dst)
            except OSError:
                shutil.copy2(src, dst)
        return True

    def summary(self, *, source: Path | None = None, refused: str | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {"enabled": self.enabled}
        if source is not None:
            out["continued_from"] = Path(source).name
        if refused:
            out["not_reused"] = refused
        out["units_reused"] = dict(sorted(self.reused_by_stage.items()))
        out["units_run"] = dict(sorted(self.run_by_stage.items()))
        if self.unlinked:
            out["units_rerun_for_missing_raw_files"] = self.unlinked
        out["reused_unit_keys"] = sorted(self.reused)[:LISTED_UNITS]
        return out
