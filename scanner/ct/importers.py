"""Load crt.sh JSON and CSV exports into an ``ObservationTable``."""
from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from pathlib import Path

from scanner.ct.models import Observation, ObservationTable
from scanner.ct.names import normalize_name

_NAME_KEYS = ("name_value", "matching_identities")
_TIME_KEYS = ("entry_timestamp", "logged_at", "not_before")
_ID_KEYS = ("id", "min_cert_id", "crt.sh_id")
_ISSUER_KEYS = ("issuer_name", "issuer")


def _fold(row: dict) -> dict:
    """Row keyed by lower-cased names with runs of whitespace as ``_`` (``Logged At`` becomes ``logged_at``)."""
    return {"_".join(str(k).lower().split()): v for k, v in row.items()}


def _pick(folded: dict, keys: tuple[str, ...]):
    for key in keys:
        value = folded.get(key)
        if value not in (None, ""):
            return value
    return None


def _stamp(value) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    parsed = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _records(text: str) -> list:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        data = json.loads(stripped)
        if not isinstance(data, list):
            raise ValueError("expected a JSON array")
        return data
    return list(csv.DictReader(io.StringIO(text)))


def load_crtsh_export(path) -> ObservationTable:
    text = Path(path).read_text(encoding="utf-8-sig")
    table = ObservationTable()
    for row in _records(text):
        if not isinstance(row, dict):
            continue
        folded = _fold(row)
        raw_names = _pick(folded, _NAME_KEYS)
        if not isinstance(raw_names, str):
            continue
        seen_at = _stamp(_pick(folded, _TIME_KEYS))
        ident = _pick(folded, _ID_KEYS)
        cert_id = None if ident is None else str(ident)
        issuer = _pick(folded, _ISSUER_KEYS)
        issuer = None if issuer is None else str(issuer)
        for part in raw_names.splitlines():
            name = normalize_name(part)
            if name is not None:
                table.add(Observation(name=name, source="import", seen_at=seen_at, cert_id=cert_id, issuer=issuer))
    return table
