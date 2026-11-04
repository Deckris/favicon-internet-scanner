"""Certificate-transparency and newly-observed-domain websocket feeds, parsed into observations."""
from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any

from scanner.ct.models import Observation
from scanner.ct.names import normalize_name

CLOSE_ERRORS = {"ConnectionClosed", "ConnectionClosedError", "ConnectionClosedOK", "InvalidMessage",
                "InvalidStatus", "InvalidHandshake"}
MAX_BACKOFF_S = 300.0


def _iso(epoch: Any) -> str | None:
    if isinstance(epoch, bool) or not isinstance(epoch, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _as_dict(msg: Any) -> dict | None:
    if isinstance(msg, (str, bytes, bytearray)):
        try:
            msg = json.loads(msg)
        except ValueError:
            return None
    return msg if isinstance(msg, dict) else None


def _issuer(value: Any) -> str | None:
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        for key in ("CN", "O", "aggregated"):
            if isinstance(value.get(key), str) and value[key]:
                return value[key]
    return None


def _dedupe(names: list[Any]) -> list[str]:
    out: dict[str, None] = {}
    for raw in names:
        name = normalize_name(raw) if isinstance(raw, str) else None
        if name:
            out.setdefault(name)
    return list(out)


def parse_certstream(msg: dict | str) -> list[Observation]:
    """certstream-server-go ``certificate_update`` message -> one observation per normalized name."""
    message = _as_dict(msg)
    if message is None or message.get("message_type") != "certificate_update":
        return []
    data = message.get("data")
    data = data if isinstance(data, dict) else {}
    leaf = data.get("leaf_cert")
    leaf = leaf if isinstance(leaf, dict) else {}
    cert_id = (leaf.get("sha256") or (f"sha1:{leaf['sha1']}" if leaf.get("sha1") else None)
               or leaf.get("fingerprint") or leaf.get("serial_number") or None)
    source = data.get("source")
    source = source if isinstance(source, dict) else {}
    log = source.get("url") or source.get("name") or None
    seen = _iso(data.get("seen"))
    issuer = _issuer(leaf.get("issuer"))
    names = leaf.get("all_domains")
    return [Observation(n, "certstream", seen, cert_id, issuer, log)
            for n in _dedupe(names if isinstance(names, list) else [])]


def parse_zonestream(msg: dict | str) -> list[Observation]:
    """Newly-observed-domain feed message; the FQDN variant carries ``fqdn`` instead of ``domain``."""
    message = _as_dict(msg)
    if message is None:
        return []
    raw = message.get("domain") or message.get("fqdn")
    name = normalize_name(raw) if isinstance(raw, str) else None
    if not name:
        return []
    cert_id = None
    if message.get("cert_index") is not None:
        cert_id = f"zonestream:{message.get('ct_name')}:{message.get('cert_index')}"
    return [Observation(name, "zonestream", _iso(message.get("timestamp")), cert_id)]


def _default_connect(url: str):
    from websockets.sync.client import connect
    return connect(url, open_timeout=30, max_size=2 ** 22)


def stream_websocket(url: str, *, parse: Callable[[Any], list[Observation]], connect: Callable | None = None,
                     max_messages: int | None = None, reconnect_backoff_s: float = 5.0, max_reconnects: int = 10,
                     sleep: Callable[[float], None] = time.sleep) -> Iterator[Observation]:
    """Yield observations parsed from every message; reconnect with doubling back-off after a connection error.

    ``max_messages`` counts received messages. After ``max_reconnects`` consecutive failed connections the last
    error is raised. A connection that delivered a message resets the failure count and the delay.
    """
    connect = connect or _default_connect
    received = 0
    failures = 0
    delay = reconnect_backoff_s
    while max_messages is None or received < max_messages:
        try:
            with connect(url) as ws:
                while max_messages is None or received < max_messages:
                    raw = ws.recv()
                    received += 1
                    failures, delay = 0, reconnect_backoff_s
                    yield from parse(raw)
            if max_messages is not None and received >= max_messages:
                return
            raise ConnectionError("connection closed")
        except Exception as exc:
            if not isinstance(exc, OSError) and type(exc).__name__ not in CLOSE_ERRORS:
                raise
            failures += 1
            if failures > max_reconnects:
                raise
            sleep(delay)
            delay = min(delay * 2, MAX_BACKOFF_S)
