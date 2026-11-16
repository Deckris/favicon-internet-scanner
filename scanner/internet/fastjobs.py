"""Favicon jobs of a shard read from the fact store without rebuilding the result objects.

``pipeline.favicon_jobs`` walks every address through ``ShardStore.iter_ips``, which decodes the complete TLS, HTTP,
SNI and resolution documents of each endpoint into dataclasses. The job list only depends on a few of their fields,
and most of those are also kept in plain columns next to the documents (the TLS outcome, the SNI success flag, the
resolution status). This reader takes those columns, lets SQLite look at ``http_status`` inside the HTTP document, and
decodes only the candidate names and the address list of resolved names. It returns the same jobs in the same order
as ``favicon_jobs``.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from scanner.internet import candidates as cand
from scanner.internet import tls as tlsmod

_PROVEN = frozenset({tlsmod.ALERT_UNRECOGNIZED_NAME, tlsmod.ALERT_OTHER, tlsmod.VERSION, tlsmod.NO_CIPHER})
_IN_CHUNK = 400
_PAGE = 512


def _hs(raw: Any) -> str:
    return bytes(raw).decode("utf-8", "surrogatepass")


def _hb(host: str) -> bytes:
    return host.encode("utf-8", "surrogatepass")


def _http_answered(store: Any, lo: str, hi: str) -> set[tuple[str, int]]:
    """Endpoints in the address range whose plain HTTP document carries a status code (and that have a TLS row)."""
    marks = ",".join("?" * (len(_PROVEN) + 1))
    skip = [tlsmod.OK, *sorted(_PROVEN)]
    try:
        rows = store._query(
            "SELECT h.ip, h.port FROM http_res h JOIN tls_direct t ON t.ip = h.ip AND t.port = h.port "
            f"WHERE h.ip >= ? AND h.ip <= ? AND t.outcome NOT IN ({marks}) "
            "AND json_extract(h.data, '$.http_status') IS NOT NULL", [lo, hi, *skip])
        return {(r[0], r[1]) for r in rows}
    except sqlite3.OperationalError:
        rows = store._query("SELECT h.ip, h.port, h.data FROM http_res h JOIN tls_direct t ON t.ip = h.ip AND t.port = h.port "
                            f"WHERE h.ip >= ? AND h.ip <= ? AND t.outcome NOT IN ({marks})", [lo, hi, *skip])
        return {(r[0], r[1]) for r in rows if json.loads(r[2]).get("http_status") is not None}


def _addresses_of(store: Any, hosts: set[str]) -> dict[str, tuple[str, ...]]:
    """Address lists of the resolved names among ``hosts`` (names with any other status, or none, are absent)."""
    out: dict[str, tuple[str, ...]] = {}
    keys = sorted(_hb(h) for h in hosts)
    for i in range(0, len(keys), _IN_CHUNK):
        chunk = keys[i:i + _IN_CHUNK]
        rows = store._query("SELECT host, data FROM resolutions WHERE status = 'resolved' AND host IN (%s)"
                            % ",".join("?" * len(chunk)), chunk)
        for host, data in rows:
            out[_hs(host)] = tuple(json.loads(data).get("a") or ())
    return out


def favicon_jobs_fast(store: Any, cfg: Any, counts: dict[str, Any]) -> tuple[list[dict[str, Any]], set[str], set[tuple[str, int]]]:
    """Same result as ``pipeline.favicon_jobs(store, cfg, counts)``."""
    max_names = cfg.favicon.max_hostnames_per_endpoint
    max_unverified = cfg.favicon.max_unverified_names_per_endpoint
    fjobs: list[dict[str, Any]] = []
    job_ips: set[str] = set()
    job_endpoints: set[tuple[str, int]] = set()
    unverified_total = 0
    last = ""
    while True:
        ips = [r[0] for r in store._query("SELECT DISTINCT ip FROM endpoints WHERE ip > ? ORDER BY ip LIMIT ?", (last, _PAGE))]
        if not ips:
            break
        last = ips[-1]
        lo, hi = ips[0], ips[-1]
        wanted = set(ips)
        endpoints = [(r[0], r[1]) for r in store._query(
            "SELECT ip, port FROM endpoints WHERE ip >= ? AND ip <= ? ORDER BY ip, port", (lo, hi))]
        outcome = {(r[0], r[1]): r[2] for r in store._query(
            "SELECT ip, port, outcome FROM tls_direct WHERE ip >= ? AND ip <= ?", (lo, hi))}
        answered = _http_answered(store, lo, hi)
        sni_ok: set[tuple[str, int]] = set()
        sni_hosts: dict[tuple[str, int], dict[str, bool]] = {}
        for ip, port, host, ok in store._query("SELECT ip, port, host, ok FROM sni_res WHERE ip >= ? AND ip <= ?", (lo, hi)):
            sni_hosts.setdefault((ip, port), {})[_hs(host)] = bool(ok)
            if ok:
                sni_ok.add((ip, port))
        names: dict[tuple[str, int], list[tuple[str, set[str]]]] = {}
        hosts: set[str] = set()
        for ip, port, data in store._query("SELECT ip, port, data FROM names WHERE ip >= ? AND ip <= ?", (lo, hi)):
            pairs = [(h, set(s)) for h, s in json.loads(data)["n"]]
            names[(ip, port)] = pairs
            hosts.update(h for h, _ in pairs)
        addrs = _addresses_of(store, hosts) if hosts else {}

        for ip, port in endpoints:
            if ip not in wanted:
                continue
            key = (ip, port)
            out = outcome.get(key)
            if out is None:
                proto = "not_attempted"
            elif out == tlsmod.OK or key in sni_ok:
                proto = "https"
            elif out in _PROVEN:
                proto = "tls_unestablished"
            elif key in answered:
                proto = "http"
            else:
                proto = "tcp_only"
            tls_ok = out == tlsmod.OK
            first = len(fjobs)
            if proto == "http" or (proto == "https" and tls_ok):
                fjobs.append({"scheme": proto, "ip": ip, "port": port, "hostname": None})
            pairs = names.get(key)
            if pairs:
                verified: list[tuple[str, set[str]]] = []
                unverified: list[tuple[str, set[str]]] = []
                for h, src in pairs:
                    a = addrs.get(h)
                    (verified if a and ip in a else unverified).append((h, src))
                sni = sni_hosts.get(key, {})
                if max_names > 0 and proto != "not_attempted":
                    verified.sort(key=lambda p: cand.name_rank(p[0], p[1]))
                    for h, _src in verified[:max_names]:
                        if proto == "http":
                            scheme = "http"
                        elif proto == "https" and (tls_ok or sni.get(h, False)):
                            scheme = "https"
                        else:
                            continue
                        fjobs.append({"scheme": scheme, "ip": ip, "port": port, "hostname": h})
                if max_unverified > 0 and proto in ("http", "https", "tls_unestablished"):
                    unverified.sort(key=lambda p: cand.name_rank(p[0], p[1]))
                    scheme = "http" if proto == "http" else "https"
                    for h, _src in unverified[:max_unverified]:
                        fjobs.append({"scheme": scheme, "ip": ip, "port": port, "hostname": h})
                        unverified_total += 1
            if len(fjobs) > first:
                job_ips.add(ip)
                job_endpoints.add(key)
    if unverified_total:
        counts["favicon_jobs_unverified_names"] = counts.get("favicon_jobs_unverified_names", 0) + unverified_total
    return fjobs, job_ips, job_endpoints
