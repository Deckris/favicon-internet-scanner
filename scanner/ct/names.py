"""Hostname normalisation, name files and registrable domains for certificate sources."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable, Iterator

from scanner.certificates import normalize_hostname

# Public suffixes of more than one label that are common in certificates. This is a compact embedded list, not the
# full Public Suffix List: a suffix missing here is treated as a single-label suffix, so the registrable domain of
# a name under it comes out one label too short (the suffix itself). Add entries as needed.
MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "ne.kr", "go.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.hk", "org.hk", "edu.hk", "gov.hk",
    "com.tw", "org.tw", "net.tw", "edu.tw",
    "com.sg", "org.sg", "edu.sg", "gov.sg",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.mx", "org.mx", "gob.mx", "edu.mx",
    "com.ar", "org.ar", "gob.ar",
    "com.co", "net.co", "org.co",
    "co.za", "org.za", "web.za", "gov.za", "ac.za",
    "com.tr", "org.tr", "net.tr", "gov.tr", "edu.tr",
    "com.ua", "org.ua", "net.ua", "gov.ua",
    "com.pl", "net.pl", "org.pl",
    "co.il", "org.il", "ac.il", "gov.il",
    "com.my", "org.my", "net.my", "gov.my",
    "co.id", "or.id", "web.id", "go.id", "ac.id",
    "co.th", "or.th", "ac.th", "go.th", "in.th",
    "com.vn", "net.vn", "org.vn", "gov.vn",
    "com.ph", "org.ph", "net.ph", "gov.ph",
    "com.pk", "org.pk", "net.pk", "gov.pk",
    "com.eg", "org.eg", "gov.eg",
    "com.ng", "org.ng", "gov.ng",
    "co.ke", "or.ke", "go.ke",
    "com.sa", "org.sa", "gov.sa",
    "com.pt", "org.pt", "gov.pt",
    "com.es", "org.es", "gob.es",
    "com.ru", "org.ru", "net.ru",
})
_MAX_SUFFIX_LABELS = max(suffix.count(".") + 1 for suffix in MULTI_LABEL_SUFFIXES)


def normalize_name(raw: str) -> str | None:
    """Lower-cased A-label hostname, or ``None`` if ``raw`` is not a usable name.

    A leading ``*.`` is stripped, so a wildcard name yields its base name. IP literals, empty or over-long
    labels and names of a single label are rejected.
    """
    if not isinstance(raw, str):
        return None
    candidate = raw.strip()
    if candidate.startswith("*."):
        candidate = candidate[2:]
    normalized = normalize_hostname(candidate)
    if normalized is None or normalized.startswith("*."):
        return None
    return normalized


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


def iter_names(path: str | os.PathLike) -> Iterator[str]:
    """Normalised names from a ``.jsonl`` file (key ``name``) or a text file (one per line); each name once."""
    seen: set[str] = set()
    for raw in _raw_names(path):
        name = normalize_name(raw)
        if name is not None and name not in seen:
            seen.add(name)
            yield name


def registrable_domain(name: str) -> str | None:
    """The registrable domain (public suffix plus one label) of ``name``, or ``None``.

    Works offline with no dependency: the suffix is looked up in ``MULTI_LABEL_SUFFIXES`` and otherwise taken to be
    the last label. Names under a multi-label suffix missing from that list get the suffix itself back as their
    registrable domain. A name that is itself a listed suffix has none.
    """
    normalized = normalize_name(name)
    if normalized is None:
        return None
    labels = normalized.split(".")
    for count in range(min(_MAX_SUFFIX_LABELS, len(labels)), 1, -1):
        if ".".join(labels[-count:]) in MULTI_LABEL_SUFFIXES:
            if len(labels) == count:
                return None
            return ".".join(labels[-(count + 1):])
    return ".".join(labels[-2:])
