"""Observations of a hostname in a certificate source, and a table that holds them without duplicates."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Iterable, Iterator

SOURCES = ("crtsh", "certstream", "zonestream", "import")


@dataclass(frozen=True)
class Observation:
    """One hostname seen in one certificate by one source.

    ``source`` is one of ``SOURCES``; ``seen_at`` is an ISO-8601 UTC timestamp.
    """

    name: str
    source: str
    seen_at: str
    cert_id: str | None = None
    issuer: str | None = None
    log: str | None = None

    def dedup_key(self) -> tuple[str, str, str | None]:
        return (self.name, self.source, self.cert_id)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Observation":
        known = {field.name for field in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known})


class ObservationTable:
    """Observations in insertion order, one per ``dedup_key``."""

    def __init__(self) -> None:
        self._rows: list[Observation] = []
        self._seen: set[tuple[str, str, str | None]] = set()

    def add(self, obs: Observation) -> bool:
        """Add ``obs``; ``False`` if an observation with the same key is already there."""
        key = obs.dedup_key()
        if key in self._seen:
            return False
        self._seen.add(key)
        self._rows.append(obs)
        return True

    def extend(self, observations: Iterable[Observation]) -> int:
        """Add every observation; returns how many were new."""
        return sum(1 for obs in observations if self.add(obs))

    def __len__(self) -> int:
        return len(self._rows)

    def __iter__(self) -> Iterator[Observation]:
        return iter(self._rows)

    def names(self) -> list[str]:
        """Sorted unique names."""
        return sorted({obs.name for obs in self._rows})

    def to_jsonl(self, path: str | os.PathLike) -> None:
        """Write one JSON object per line (sorted keys, UTF-8, LF); the file appears whole or not at all."""
        target = Path(path)
        tmp = target.with_name(target.name + ".tmp")
        with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
            for obs in self._rows:
                handle.write(json.dumps(obs.to_dict(), sort_keys=True, ensure_ascii=False) + "\n")
        os.replace(tmp, target)

    @classmethod
    def from_jsonl(cls, path: str | os.PathLike) -> "ObservationTable":
        table = cls()
        with open(path, "r", encoding="utf-8", newline="") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    table.add(Observation.from_dict(json.loads(line)))
        return table
