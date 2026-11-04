"""Compare the CT logs a monitor watches with the published CT log list (v3 JSON format)."""
from __future__ import annotations

import json
import urllib.request
from collections.abc import Iterable
from pathlib import Path

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
ACTIVE_STATES = ("usable", "qualified")


def normalize_url(url: str) -> str:
    """Drop the scheme and any trailing slash and lower-case the host, so equivalent spellings compare equal."""
    text = url.strip()
    for prefix in ("https://", "http://", "wss://", "ws://"):
        if text.lower().startswith(prefix):
            text = text[len(prefix):]
            break
    host, sep, rest = text.partition("/")
    return (host.lower() + sep + rest).rstrip("/")


def load_log_list(source: str | Path | dict) -> dict:
    if isinstance(source, dict):
        return source
    return json.loads(Path(source).read_text(encoding="utf-8"))


def fetch_log_list(url: str = LOG_LIST_URL, timeout: float = 30.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def _entries(log_list: dict) -> list[dict]:
    out = []
    for operator in log_list.get("operators", []):
        for kind, key, field in (("rfc6962", "logs", "url"), ("tiled", "tiled_logs", "monitoring_url")):
            for log in operator.get(key, []):
                if not isinstance(log.get(field), str):
                    continue
                state = next(iter(log.get("state") or {}), None)
                out.append({"url": log[field], "key": normalize_url(log[field]), "type": kind, "state": state})
    return out


def compare(watched: Iterable[str], log_list: dict) -> dict:
    watched_keys = {normalize_url(u) for u in watched}
    entries = _entries(log_list)
    active = [e for e in entries if e["state"] in ACTIVE_STATES]
    covered = sorted(e["url"] for e in active if e["key"] in watched_keys)
    missing = [{"url": e["url"], "type": e["type"]} for e in active if e["key"] not in watched_keys]
    known = {e["key"] for e in entries}
    unknown = sorted(watched_keys - known)
    return {"covered": covered, "missing": sorted(missing, key=lambda m: m["url"]), "unknown": unknown}
