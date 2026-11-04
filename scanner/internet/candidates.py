"""Hostname candidates: PTR names plus certificate SAN/CN, and optionally names from a local CT list.

Rules (scanner scope):
* wildcard names are recorded as evidence and are never queried -- neither the
  literal ``*.x`` nor its base ``x`` (a wildcard does not imply the base name);
* IP-literal SANs and malformed names are dropped;
* a hostname seen via several sources is one candidate with merged provenance;
* every name passes ``TargetPolicy.check_hostname`` before it can be queried;
* a per-IP cap keeps the work bounded and the truncation is recorded;
* names from an optional Certificate Transparency list (``ct_names``) are added to an endpoint only when their
  registrable domain equals that of a PTR or certificate name already found for it; they rank below every name
  with PTR or certificate evidence and are capped per registrable domain when the list is indexed.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from scanner.certificates import normalize_hostname
from scanner.models import CertificateInfo
from scanner.zdns_runner import Resolution

SRC_PTR = "ptr"
SRC_SAN = "certificate_san"
SRC_CN = "certificate_cn"
SRC_OPERATOR = "operator_supplied"      # known-targets mode only
SRC_CT = "ct"                           # optional local Certificate Transparency name list

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


@dataclass
class CtIndex:
    """Names of a Certificate Transparency list grouped by registrable domain, at most ``max_per_domain`` each."""
    by_domain: dict[str, list[str]]
    registrable_domain: Callable[[str], str | None]
    names_loaded: int = 0           # distinct normalized names read from the file
    names_dropped_by_cap: int = 0   # names left out because their domain already had max_per_domain
    max_per_domain: int = 50

    @property
    def domains_indexed(self) -> int:
        return len(self.by_domain)


def load_ct_index(path: Path, *, max_per_domain: int) -> CtIndex:
    """Read a names file once. Per domain the alphabetically first ``max_per_domain`` names are kept."""
    from scanner.ct import names as ctnames           # imported only when the CT source is switched on
    by_domain: dict[str, list[str]] = {}
    loaded = 0
    for name in ctnames.iter_names(path):
        loaded += 1
        dom = ctnames.registrable_domain(name)
        if dom is None:
            continue
        bucket = by_domain.setdefault(dom, [])
        bisect.insort(bucket, name)
        if len(bucket) > max_per_domain:
            bucket.pop()
    kept = sum(len(v) for v in by_domain.values())
    return CtIndex(by_domain, ctnames.registrable_domain, names_loaded=loaded,
                   names_dropped_by_cap=loaded - kept, max_per_domain=max_per_domain)


def name_rank(name: str, sources: set[str]) -> tuple[bool, int, bool, str]:
    """Sort key, best first: any PTR/certificate/operator evidence before CT-only, several sources, PTR, then alphabetical."""
    return (sources == {SRC_CT}, -len(sources), SRC_PTR not in sources, name)


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
    ct_names: CtIndex | None = None,
) -> EndpointNames:
    ep = EndpointNames()
    for name in operator_names:
        _add(ep, name, SRC_OPERATOR, policy)
    for name in ptr_names:
        _add(ep, name, SRC_PTR, policy)
    for raw, source in cert_raw_names(cert):
        _add(ep, raw, source, policy)
    if ct_names is not None:
        evidence = {n for n, src in ep.names.items() if src & {SRC_PTR, SRC_SAN, SRC_CN}}
        wild = {w[2:] for w in ep.wildcards}
        for name in operator_names:
            norm = normalize_hostname(name)
            if norm is not None and norm.startswith("*."):
                wild.discard(norm[2:])           # an operator-supplied wildcard is not evidence either
        domains = {d for d in (ct_names.registrable_domain(n) for n in evidence | wild) if d}
        for dom in sorted(domains):
            for name in ct_names.by_domain.get(dom, ()):
                _add(ep, name, SRC_CT, policy)
    ep.source_count = len(ep.names)
    if len(ep.names) > max_candidates:
        # Names corroborated by several sources first, then PTR names, then the rest alphabetically; CT-only last.
        keep = sorted(ep.names, key=lambda n: name_rank(n, ep.names[n]))[:max_candidates]
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
    ptr_only_evidence / tls_only_evidence / ct_only_evidence (a name only the CT list knows). Every inconclusive DNS outcome (servfail, timeout, loop,
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
        if sources == {SRC_CT}:
            return "ct_only_evidence"
        if sources:
            return "multi_source_evidence"       # e.g. PTR and certificate agree on a name that has no IPv4 record
    return "unresolved"
