"""Hostname candidates: PTR names plus certificate SAN/CN, and optionally names from a local CT list.

Rules (scanner scope):
* wildcard names are recorded as evidence and are never queried -- neither the
  literal ``*.x`` nor its base ``x`` (a wildcard does not imply the base name);
* IP-literal SANs and malformed names are dropped;
* a hostname seen via several sources is one candidate with merged provenance;
* every name passes ``TargetPolicy.check_hostname`` before it can be queried;
* a per-IP cap keeps the work bounded and the truncation is recorded;
* names from an optional Certificate Transparency list (``ct_names``) are added to an endpoint only when their
  registrable domain equals that of a PTR or certificate name already found for it (a wildcard links through its
  base name; a public suffix links nothing). They rank below every name with PTR or certificate evidence, never
  count as corroboration, and are bounded per registrable domain, per endpoint domain count and per endpoint total
  before any of them reaches the hostname policy.
"""
from __future__ import annotations

import bisect
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from scanner.certificates import normalize_hostname
from scanner.internet.config import ConfigError
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
    ct_names_skipped: int = 0       # CT names left out by the per-endpoint caps; counted, not refused


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
    wildcard_base: Callable[[str], str | None]
    names_loaded: int = 0           # valid name lines read from the file, repeats included
    names_dropped_by_cap: int = 0   # names left out because their domain already had max_per_domain
    max_per_domain: int = 50
    sha256: str = ""                # digest of exactly the bytes that were parsed
    size_bytes: int = 0
    names_duplicate: int = 0        # repeats of a name already held for its domain
    names_without_domain: int = 0   # names with no registrable domain (public suffixes); they link nothing

    @property
    def domains_indexed(self) -> int:
        return len(self.by_domain)


def _name_lines(handle: Any, jsonl: bool, digest: Any):
    """Raw names from an open binary file; every byte read is fed to ``digest``."""
    for chunk in handle:
        digest.update(chunk)
        line = chunk.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        if jsonl:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and isinstance(row.get("name"), str):
                yield row["name"]
        elif not line.startswith("#"):
            yield line


def load_ct_index(path: Path, *, max_per_domain: int, expected_sha256: str | None = None) -> CtIndex:
    """Read a names file once, hashing the very bytes that are parsed.

    Per domain the alphabetically first ``max_per_domain`` names are kept. A digest that differs from
    ``expected_sha256``, or a list without a single name that has a registrable domain, is refused."""
    from scanner.ct import names as ctnames           # imported only when the CT source is switched on
    by_domain: dict[str, list[str]] = {}
    loaded = dropped = duplicate = no_domain = 0
    digest = hashlib.sha256()
    jsonl = str(path).lower().endswith(".jsonl")
    size = 0
    with open(path, "rb") as handle:
        for raw in _name_lines(handle, jsonl, digest):
            name = ctnames.normalize_name(raw)
            if name is None:
                continue
            loaded += 1
            dom = ctnames.registrable_domain(name)
            if dom is None:
                no_domain += 1
                continue
            bucket = by_domain.setdefault(dom, [])
            at = bisect.bisect_left(bucket, name)
            if at < len(bucket) and bucket[at] == name:
                duplicate += 1
                continue
            bucket.insert(at, name)
            if len(bucket) > max_per_domain:
                bucket.pop()
                dropped += 1
        size = handle.tell()
    sha = digest.hexdigest()
    if expected_sha256 and sha != expected_sha256.lower():
        raise ConfigError(f"ct_names.names_file does not match ct_names.names_sha256 (the file hashes to {sha})")
    if not by_domain:
        raise ConfigError("ct_names.names_file holds no usable name with a registrable domain")
    return CtIndex(by_domain, ctnames.registrable_domain, names_loaded=loaded, names_dropped_by_cap=dropped,
                   max_per_domain=max_per_domain, sha256=sha, size_bytes=size,
                   names_duplicate=duplicate, names_without_domain=no_domain,
                   wildcard_base=ctnames.wildcard_base)


def _core(sources: set[str]) -> set[str]:
    """The sources that count as evidence: a CT hit corroborates nothing."""
    return sources - {SRC_CT}


def name_rank(name: str, sources: set[str]) -> tuple[bool, int, bool, str]:
    """Sort key, best first: PTR/certificate/operator evidence before CT-only, several non-CT sources, PTR, then alphabetical."""
    core = _core(sources)
    return (not core, -len(core), SRC_PTR not in sources, name)


def cert_raw_names(cert: CertificateInfo | None) -> list[tuple[str, str]]:
    """(raw name, source) pairs from a certificate, SAN first then CN."""
    if cert is None:
        return []
    out = [(san, SRC_SAN) for san in cert.san_dns]
    if cert.subject_cn:
        out.append((cert.subject_cn, SRC_CN))
    return out


def _add_ct_names(ep: EndpointNames, index: CtIndex, policy: Any, operator_names: tuple[str, ...],
                  max_candidates: int, max_domains: int) -> None:
    """Link CT names through the registrable domains of the endpoint's PTR/certificate names.

    At most ``max_domains`` domains are used (alphabetically first) and at most as many new names as still fit under
    ``max_candidates``. Both limits are applied before a name reaches the policy; what they leave out is counted in
    ``ct_names_skipped`` and produces no refusal records."""
    evidence = {n for n, src in ep.names.items() if src & {SRC_PTR, SRC_SAN, SRC_CN}}
    wild = set(ep.wildcards)
    for name in operator_names:
        norm = normalize_hostname(name)
        if norm is not None and norm.startswith("*."):
            wild.discard(norm)                   # an operator-supplied wildcard is not evidence either
    bases = {b for b in (index.wildcard_base(w) for w in wild) if b}
    domains = sorted({d for d in (index.registrable_domain(n) for n in evidence | bases) if d})
    room = max(0, max_candidates - len(ep.names))
    for pos, dom in enumerate(domains):
        names = index.by_domain.get(dom, ())
        if pos >= max_domains:
            ep.ct_names_skipped += sum(1 for n in names if n not in ep.names)
            continue
        for name in names:
            if name in ep.names:
                ep.names[name].add(SRC_CT)       # already a candidate: only its provenance grows
            elif room > 0:
                room -= 1
                _add(ep, name, SRC_CT, policy)
            else:
                ep.ct_names_skipped += 1


def build_endpoint_names(
    ptr_names: list[str],
    cert: CertificateInfo | None,
    policy: Any,
    *,
    max_candidates: int,
    operator_names: tuple[str, ...] = (),
    ct_names: CtIndex | None = None,
    max_domains_per_endpoint: int = 8,
) -> EndpointNames:
    ep = EndpointNames()
    for name in operator_names:
        _add(ep, name, SRC_OPERATOR, policy)
    for name in ptr_names:
        _add(ep, name, SRC_PTR, policy)
    for raw, source in cert_raw_names(cert):
        _add(ep, raw, source, policy)
    if ct_names is not None:
        _add_ct_names(ep, ct_names, policy, operator_names, max_candidates, max_domains_per_endpoint)
    ep.source_count = len(ep.names) + ep.ct_names_skipped
    if len(ep.names) > max_candidates:
        # Names corroborated by several sources first, then PTR names, then the rest alphabetically; CT-only last.
        keep = sorted(ep.names, key=lambda n: name_rank(n, ep.names[n]))[:max_candidates]
        ep.names = {n: ep.names[n] for n in keep}
        ep.truncated = True
    if ep.ct_names_skipped:
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
    ptr_only_evidence / tls_only_evidence / ct_only_evidence (a name only the CT list knows). A CT hit next to other
    sources changes nothing: it is not corroboration. Every inconclusive DNS outcome (servfail, timeout, loop,
    tool error) is ``unresolved`` whatever the source, so a resolver outage is never read as evidence.
    """
    if dns_status in VERIFIED:
        return "verified"
    if dns_status in ELSEWHERE:
        return "resolved_elsewhere"
    if dns_status == "nxdomain":
        return "nxdomain"
    if dns_status == "no_answer":
        core = _core(sources)
        if core == {SRC_PTR}:
            return "ptr_only_evidence"
        if core and core <= {SRC_SAN, SRC_CN}:
            return "tls_only_evidence"
        if SRC_OPERATOR in core:
            return "operator_evidence"
        if sources == {SRC_CT}:
            return "ct_only_evidence"
        if core:
            return "multi_source_evidence"       # e.g. PTR and certificate agree on a name that has no IPv4 record
    return "unresolved"
