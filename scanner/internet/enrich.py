"""Extra facts derived from data the pipeline already holds. Nothing here sends traffic.

* ``tarpit_assessment`` flags addresses that look like tarpits, shielding firewalls or pseudo-services
  (SYN-ACK window, silence above TCP on many ports, identical content on several ports).
* ``document_facts`` / ``icon_declaration_facts`` summarise the page behind a favicon attempt,
  including icons the page declares on *other* hosts. Those are recorded, never fetched.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlsplit

APPLICATION_PROTOCOLS = {"https", "http", "tls_unestablished"}   # a service answered above TCP

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


def parse_synack_csv(text: str) -> dict[str, dict[str, int | None]]:
    """ZMap rows ``saddr,window,ttl`` -> first row per address. Missing or malformed columns become None."""
    out: dict[str, dict[str, int | None]] = {}
    for line in text.splitlines():
        cols = [c.strip() for c in line.split(",")]
        if not cols or not cols[0] or cols[0] in out:
            continue
        def num(i: int) -> int | None:
            try:
                return int(cols[i])
            except (IndexError, ValueError):
                return None
        out[cols[0]] = {"window": num(1), "ttl": num(2)}
    return out


def tarpit_assessment(endpoints: list[dict[str, Any]], scanned_port_count: int, min_open_ports: int,
                      tiny_window_below: int = 246) -> dict[str, Any]:
    """Judge ONE address from what we already hold for each of its open endpoints.

    ``endpoints``: dicts with ``protocol``, ``window`` (SYN-ACK TCP window or None), ``doc_sha256`` and
    ``doc_status`` (the page fetched for the favicon attempt, or None).

    Signals, strongest first:
    * ``zero_window`` / ``tiny_window``: the SYN-ACK advertises a window of 0 or below ``tiny_window_below``.
      Tarpits hold the connection with a closed window (LZR: a zero window on one port means all ports in
      99% of hosts; Degreaser: LaBrea and Netfilter tarpits advertise tiny windows). High confidence.
    * ``silent_open_many``: open on at least ``min_open_ports`` ports and none shows a TLS or HTTP answer
      (LZR's middlebox / pseudo-service class). Medium confidence. Not judged when fewer ports were scanned
      than the threshold.
    * ``identical_content``: three or more ports return the same status and body (GPS/Censys pseudo-service
      test, applied to far fewer ports). Low confidence: it alone never sets ``tarpit_suspect``.
    """
    n = len(endpoints)
    signals: list[str] = []
    reasons: list[str] = []
    windows = [e["window"] for e in endpoints if e.get("window") is not None]
    if any(w == 0 for w in windows):
        signals.append("zero_window")
        reasons.append("SYN-ACK advertised a zero TCP window")
    if any(0 < w < tiny_window_below for w in windows):
        signals.append("tiny_window")
        reasons.append(f"SYN-ACK window below {tiny_window_below} bytes")
    threshold = max(3, min_open_ports)
    if scanned_port_count >= threshold and n >= threshold and all(e["protocol"] == "tcp_only" for e in endpoints):
        signals.append("silent_open_many")
        reasons.append(f"open on {n}/{scanned_port_count} scanned ports, no TLS or HTTP answer on any")
    same: dict[tuple[Any, Any], int] = {}
    for e in endpoints:
        if e.get("doc_sha256"):
            key = (e.get("doc_status"), e["doc_sha256"])
            same[key] = same.get(key, 0) + 1
    if same and max(same.values()) >= 3:
        signals.append("identical_content")
        reasons.append(f"{max(same.values())} ports return the same page")
    confidence = ("high" if {"zero_window", "tiny_window"} & set(signals) else
                  "medium" if "silent_open_many" in signals else
                  "low" if signals else None)
    return {"tarpit_suspect": confidence in ("high", "medium"), "tarpit_confidence": confidence,
            "tarpit_signals": signals, "tarpit_reason": "; ".join(reasons) or None, "open_port_count": n}


UNKNOWN_DNS = {"servfail", "timeout", "tool_error"}


def dns_unknown_share(statuses: list[str]) -> float:
    """Share of lookups that said nothing (resolver trouble or rate limiting) rather than yes or no."""
    return sum(1 for s in statuses if s in UNKNOWN_DNS) / len(statuses) if statuses else 0.0


def clean_text(text: str | None, limit: int = 120) -> str | None:
    if not text:
        return None
    out = _CONTROL.sub(" ", " ".join(text.split())).strip()
    return out[:limit] or None


def document_facts(html: str | None, body: bytes | None) -> dict[str, Any]:
    """Title and body hash of the page fetched for the favicon attempt (the hash clusters identical default pages)."""
    title = None
    if html:
        m = _TITLE.search(html)
        title = clean_text(m.group(1)) if m else None
    return {"document_title": title, "document_body_sha256": hashlib.sha256(body).hexdigest() if body else None}


def _host_port(url: str) -> tuple[str, int | None]:
    parts = urlsplit(url)
    default = 443 if parts.scheme == "https" else 80
    try:
        return (parts.hostname or "").lower(), parts.port or default
    except ValueError:
        return "", None


def icon_declaration_facts(page_url: str, declarations: list[Any], resources: list[Any]) -> dict[str, Any]:
    """What the page said about its icons, and where it said they live.

    ``icon_offhost_hosts`` lists hosts other than the page's own that the page points at; the
    run never contacts them. Embedded ``data:`` icons are decoded locally and counted separately.
    """
    page_host, page_port = _host_port(page_url)
    offhost: set[str] = set()
    kinds: dict[str, int] = {}
    for d in declarations:
        kinds[d.kind] = kinds.get(d.kind, 0) + 1
        if d.kind in ("data", "fallback") or not d.resolved_url:
            continue
        host, port = _host_port(d.resolved_url)
        if host and (host != page_host or port != page_port):
            offhost.add(host if port in (80, 443) else f"{host}:{port}")
    embedded_ok = sum(1 for r in resources if r.fetch is None and r.fingerprint and r.fingerprint.get("image_ok"))
    return {
        "icon_declared_count": sum(1 for d in declarations if d.kind != "fallback"),
        "icon_declared_kinds": dict(sorted(kinds.items())),
        "icon_offhost_hosts": sorted(clean_text(h, 120) or "" for h in offhost)[:10],
        "icon_embedded_images": embedded_ok,
    }
