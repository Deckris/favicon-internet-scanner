"""Hostname candidates: PTR names plus certificate SAN/CN, nothing else.

Rules (scanner scope):
* wildcard names are recorded as evidence and are never queried -- neither the
  literal ``*.x`` nor its base ``x`` (a wildcard does not imply the base name);
* IP-literal SANs and malformed names are dropped;
* a hostname seen via several sources is one candidate with merged provenance;
* every name passes ``TargetPolicy.check_hostname`` before it can be queried;
* a per-IP cap keeps the work bounded and the truncation is recorded.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scanner.certificates import normalize_hostname
from scanner.models import CertificateInfo
from scanner.zdns_runner import Resolution

SRC_PTR = "ptr"
SRC_SAN = "certificate_san"
SRC_CN = "certificate_cn"
SRC_OPERATOR = "operator_supplied"      # known-targets mode only

VERIFIED = frozenset({"verified_current_mapping", "multiple_a_including_target"})
ELSEWHERE = frozenset({"resolved_elsewhere", "multiple_a_excluding_target"})


@dataclass
class EndpointNames:
    """Hostname evidence attached to one (ip, port) endpoint."""
    names: dict[str, set[str]] = field(default_factory=dict)      # hostname -> sources
    wildcards: set[str] = field(default_factory=set)               # "*.example.com" as seen, never queried
    dropped: list[str] = field(default_factory=list)               # unusable raw names (IP SANs, malformed, policy-refused)
    truncated: bool = False
    source_count: int = 0


def _add(ep: EndpointNames, raw: str, source: str, policy: Any) -> None:
    norm = normalize_hostname(raw)
    if norm is None:
        ep.dropped.append(raw)
        return
    if norm.startswith("*."):
        ep.wildcards.add(norm)
        return
    if policy.check_hostname(norm, stage="dns", context=f"candidate:{source}") is not None:
        ep.dropped.append(raw)
        return
    ep.names.setdefault(norm, set()).add(source)


def cert_raw_names(cert: CertificateInfo | None) -> list[tuple[str, str]]:
    """(raw name, source) pairs from a certificate, SAN first then CN."""
    if cert is None:
        return []
    out = [(san, SRC_SAN) for san in cert.san_dns]
    if cert.subject_cn:
        out.append((cert.subject_cn, SRC_CN))
    return out


def build_endpoint_names(
    ptr_names: list[str],
    cert: CertificateInfo | None,
    policy: Any,
    *,
    max_candidates: int,
    operator_names: tuple[str, ...] = (),
) -> EndpointNames:
    ep = EndpointNames()
    for name in operator_names:
        _add(ep, name, SRC_OPERATOR, policy)
    for name in ptr_names:
        _add(ep, name, SRC_PTR, policy)
    for raw, source in cert_raw_names(cert):
        _add(ep, raw, source, policy)
    ep.source_count = len(ep.names)
    if len(ep.names) > max_candidates:
        # Names corroborated by several sources first, then PTR names, then the rest alphabetically.
        keep = sorted(ep.names, key=lambda n: (-len(ep.names[n]), SRC_PTR not in ep.names[n], n))[:max_candidates]
        ep.names = {n: ep.names[n] for n in keep}
        ep.truncated = True
    return ep


def judge_dns(resolution: Resolution | None, ip: str) -> str:
    """Status of one hostname relative to the scanned IP."""
    if resolution is None:
        return "tool_error"
    if resolution.status != "resolved":
        return resolution.status
    if not resolution.a:
        return "no_answer"          # AAAA-only: recorded, but no IPv4 mapping exists
    multi = len(resolution.a) > 1
    if ip in resolution.a:
        return "multiple_a_including_target" if multi else "verified_current_mapping"
    return "multiple_a_excluding_target" if multi else "resolved_elsewhere"


def final_status(dns_status: str, sources: set[str]) -> str:
    """verified / resolved_elsewhere / nxdomain are definite DNS outcomes.

    ``no_answer`` (the name exists but has no IPv4 record) keeps the evidence label of its source:
    ptr_only_evidence / tls_only_evidence. Every inconclusive DNS outcome (servfail, timeout, loop,
    tool error) is ``unresolved`` whatever the source, so a resolver outage is never read as evidence.
    """
    if dns_status in VERIFIED:
        return "verified"
    if dns_status in ELSEWHERE:
        return "resolved_elsewhere"
    if dns_status == "nxdomain":
        return "nxdomain"
    if dns_status == "no_answer":
        if sources == {SRC_PTR}:
            return "ptr_only_evidence"
        if sources and sources <= {SRC_SAN, SRC_CN}:
            return "tls_only_evidence"
        if SRC_OPERATOR in sources:
            return "operator_evidence"
        if sources:
            return "multi_source_evidence"       # e.g. PTR and certificate agree on a name that has no IPv4 record
    return "unresolved"
