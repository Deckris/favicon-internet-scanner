"""Hostname normalisation, name files and registrable domains for certificate sources.

Public suffixes come from ``public_suffix_list.dat`` next to this module, a snapshot of 2026-11-05 of the list
published at https://publicsuffix.org/list/public_suffix_list.dat (MPL-2.0, header kept in the file). Both the ICANN
and the private sections are used, so a name under a hosting suffix such as ``github.io`` has that suffix as its
public suffix. Refresh the file by downloading the list again.
"""
from __future__ import annotations

import json
import os
from functools import cache
from pathlib import Path
from typing import Iterable, Iterator

from scanner.certificates import normalize_hostname

def normalize_name(raw: str) -> str | None:
    """Lower-cased A-label hostname, or ``None`` if ``raw`` is not a usable name.

    Wildcard names (any ``*``) are rejected: a certificate for ``*.example.com`` says nothing about ``example.com``
    itself. Use ``wildcard_base`` to get the base of a wildcard for registrable-domain linkage. IP literals, empty or
    over-long labels and names of a single label are rejected.
    """
    if not isinstance(raw, str) or "*" in raw:
        return None
    return normalize_hostname(raw)


def wildcard_base(raw: str) -> str | None:
    """Normalised base of a ``*.`` wildcard name (``*.a.example.com`` gives ``a.example.com``), else ``None``.

    The base is not a name the certificate covers; use it only to link the wildcard to a registrable domain.
    """
    if not isinstance(raw, str):
        return None
    candidate = raw.strip()
    if not candidate.startswith("*."):
        return None
    return normalize_name(candidate[2:])


def write_names(path: str | os.PathLike, names: Iterable[str]) -> int:
    """Write the normalised, unique, sorted names one per line (UTF-8, LF); returns how many."""
    unique = sorted({name for name in map(normalize_name, names) if name is not None})
    target = Path(path)
    tmp = target.with_name(target.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        for name in unique:
            handle.write(name + "\n")
    os.replace(tmp, target)
    return len(unique)


def _raw_names(path: str | os.PathLike) -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        if str(path).lower().endswith(".jsonl"):
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict) and isinstance(row.get("name"), str):
                    yield row["name"]
        else:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    yield line


def iter_names(path: str | os.PathLike, dedupe: bool = True) -> Iterator[str]:
    """Normalised names from a ``.jsonl`` file (key ``name``) or a text file (one per line).

    With ``dedupe`` (the default) each name is yielded once, which keeps a set of every name in memory; pass
    ``dedupe=False`` for large files and deduplicate downstream.
    """
    seen: set[str] = set()
    for raw in _raw_names(path):
        name = normalize_name(raw)
        if name is None:
            continue
        if dedupe:
            if name in seen:
                continue
            seen.add(name)
        yield name


_PSL_PATH = Path(__file__).parent / "public_suffix_list.dat"


def _a_label(label: str) -> str | None:
    label = label.lower()
    if label.isascii():
        return label
    try:
        return label.encode("idna").decode("ascii")
    except UnicodeError:
        return None


@cache
def _rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """Normal rules, wildcard parents (``*.a.b`` stored as ``a.b``) and exception rules, all as A-labels."""
    normal: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    with open(_PSL_PATH, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0]
            target = normal
            if rule.startswith("!"):
                target, rule = exception, rule[1:]
            labels = [_a_label(label) for label in rule.split(".")]
            if None in labels:
                continue
            if labels[0] == "*":
                target, labels = wildcard, labels[1:]
            target.add(".".join(labels))
    return frozenset(normal), frozenset(wildcard), frozenset(exception)


def _suffix_length(labels: list[str]) -> int:
    """Number of trailing labels of ``labels`` that form the public suffix (Public Suffix List algorithm)."""
    normal, wildcard, exception = _rules()
    count = len(labels)
    best = 1                                                    # default rule "*"
    for start in range(count):
        candidate = ".".join(labels[start:])
        if candidate in exception:
            return count - start - 1
        if candidate in normal or (start + 1 < count and ".".join(labels[start + 1:]) in wildcard):
            best = max(best, count - start)
    return best


def public_suffix(name: str) -> str | None:
    """The public suffix of ``name`` (ICANN and private sections), or ``None`` if ``name`` is not a usable name."""
    normalized = normalize_name(name)
    if normalized is None:
        return None
    labels = normalized.split(".")
    return ".".join(labels[-_suffix_length(labels):])


def registrable_domain(name: str) -> str | None:
    """The registrable domain (public suffix plus one label) of ``name``, or ``None``.

    ``None`` is returned for an unusable name and for a name that is itself a public suffix. A wildcard name has
    no registrable domain here; pass ``wildcard_base(name)`` instead.
    """
    normalized = normalize_name(name)
    if normalized is None:
        return None
    labels = normalized.split(".")
    size = _suffix_length(labels)
    if size >= len(labels):
        return None
    return ".".join(labels[-(size + 1):])
