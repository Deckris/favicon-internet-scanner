"""Deny-by-default validation for machine-readable measurement approvals.

An approval file is evidence consumed by tooling, never a decision made by it.
Markdown notes and the existence of an arbitrary path are intentionally insufficient.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml


class ApprovalError(ValueError):
    """The supplied approval does not authorize the requested operation."""


@dataclass(frozen=True)
class Approval:
    schema_version: int
    status: str
    approval_reference: str
    operations: frozenset[str]
    approved_domains: frozenset[str]
    target_population: str
    exclusions_checksum: str
    ports: tuple[int, ...]
    protocols: tuple[str, ...]
    max_rate_per_second: float
    source_addresses: tuple[str, ...]
    transparency_url: str
    opt_out_contact: str
    data_handling_reference: str
    incident_contact: str
    valid_until: datetime


REQUIRED_FIELDS = {
    "schema_version", "status", "approval_reference", "operations",
    "approved_domains", "target_population", "exclusions_checksum", "ports",
    "protocols", "max_rate_per_second", "source_addresses", "transparency_url",
    "opt_out_contact", "data_handling_reference", "incident_contact", "valid_until",
}


def _nonempty(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ApprovalError(f"approval field {field!r} must be a non-empty string")
    return value.strip()


def _sequence(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list) or not value:
        raise ApprovalError(f"approval field {field!r} must be a non-empty list")
    return value


def load_approval(path: Path, *, now: datetime | None = None) -> Approval:
    """Load an approved JSON/YAML record and reject incomplete or expired records."""
    if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
        raise ApprovalError("approval must be a machine-readable JSON or YAML record")
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw) if path.suffix.lower() == ".json" else yaml.safe_load(raw)
    except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ApprovalError("approval record could not be read") from exc
    if not isinstance(data, dict):
        raise ApprovalError("approval record must be an object")
    missing = sorted(REQUIRED_FIELDS - data.keys())
    if missing:
        raise ApprovalError(f"approval record missing fields: {', '.join(missing)}")
    if data["schema_version"] != 1 or data["status"] != "approved":
        raise ApprovalError("approval record is not approved: approval.status in settings.yaml is not `approved` (set it only after sign-off)")
    try:
        valid_until = datetime.fromisoformat(_nonempty(data["valid_until"], "valid_until").replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalError("approval valid_until must be an ISO-8601 timestamp") from exc
    if valid_until.tzinfo is None:
        raise ApprovalError("approval valid_until must include a timezone")
    current = now or datetime.now(UTC)
    if current >= valid_until:
        raise ApprovalError("approval record has expired")
    try:
        rate = float(data["max_rate_per_second"])
        ports = tuple(int(port) for port in _sequence(data["ports"], "ports"))
    except (TypeError, ValueError) as exc:
        raise ApprovalError("approval rate and ports must be numeric") from exc
    if rate <= 0 or any(port < 1 or port > 65535 for port in ports):
        raise ApprovalError("approval rate must be positive and ports must be valid")
    return Approval(
        schema_version=1,
        status="approved",
        approval_reference=_nonempty(data["approval_reference"], "approval_reference"),
        operations=frozenset(_nonempty(v, "operations") for v in _sequence(data["operations"], "operations")),
        approved_domains=frozenset(_nonempty(v, "approved_domains").lower().rstrip(".") for v in _sequence(data["approved_domains"], "approved_domains")),
        target_population=_nonempty(data["target_population"], "target_population"),
        exclusions_checksum=_nonempty(data["exclusions_checksum"], "exclusions_checksum"),
        ports=ports,
        protocols=tuple(_nonempty(v, "protocols").lower() for v in _sequence(data["protocols"], "protocols")),
        max_rate_per_second=rate,
        source_addresses=tuple(_nonempty(v, "source_addresses") for v in _sequence(data["source_addresses"], "source_addresses")),
        transparency_url=_nonempty(data["transparency_url"], "transparency_url"),
        opt_out_contact=_nonempty(data["opt_out_contact"], "opt_out_contact"),
        data_handling_reference=_nonempty(data["data_handling_reference"], "data_handling_reference"),
        incident_contact=_nonempty(data["incident_contact"], "incident_contact"),
        valid_until=valid_until,
    )


def require_operation(approval: Approval, operation: str, *, domains: set[str] | None = None) -> None:
    """Require an operation and optional exact domain subset from an approval."""
    if operation not in approval.operations:
        raise ApprovalError(f"operation {operation!r} is not approved")
    requested = {domain.lower().rstrip(".") for domain in domains or set()}
    outside = sorted(requested - approval.approved_domains)
    if outside:
        raise ApprovalError(f"domains outside approved scope: {', '.join(outside)}")
