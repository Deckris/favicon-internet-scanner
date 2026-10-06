"""Schema-v2 measurement records shared by every scanner stage.

Records are frozen dataclasses with deterministic ``as_dict`` output. Every
stage writes them as sorted JSONL so that two runs with the same seed,
configuration and epoch are byte-identical once ``VOLATILE_FIELDS`` are removed.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Iterable, Literal

SCHEMA_VERSION = 2

# Fields that legitimately differ between otherwise identical runs.
VOLATILE_FIELDS = frozenset({
    "run_id", "observed_at", "query_timestamp", "queried_at", "timing_ms",
    "started_at", "finished_at", "elapsed_seconds", "raw_ref", "zgrab_job_id",
    "zmap_job_id", "raw_line_sha256",
})

Source = Literal["passive_dns", "rdns", "certificate_san", "certificate_cn", "ct"]
HOSTNAME_SOURCES: tuple[str, ...] = ("passive_dns", "rdns", "certificate_san", "certificate_cn", "ct")

AcquisitionMode = Literal["direct_ip", "hostname_aware"]
Scheme = Literal["http", "https"]

ProtocolClass = Literal["http", "https", "both", "non_web", "unknown_error"]

DNSStatus = Literal[
    "verified_current_mapping", "resolved_elsewhere", "nxdomain", "servfail",
    "timeout", "cname_loop", "too_many_cnames", "multiple_a_including_target",
    "multiple_a_excluding_target", "no_answer", "policy_refused",
]
# Statuses under which (hostname, target_ip) is a current mapping.
CURRENT_DNS_STATUSES = frozenset({"verified_current_mapping", "multiple_a_including_target"})

FailureStage = Literal[
    "policy", "l4", "protocol", "tls", "dns", "http", "redirect",
    "favicon_discovery", "favicon_fetch", "favicon_decode", "match",
]


def _plain(value: Any) -> Any:
    if isinstance(value, (frozenset, set)):
        return sorted(_plain(item) for item in value)
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    return value


class Record:
    """Mixin: deterministic serialisation for frozen dataclass records."""

    def as_dict(self) -> dict[str, Any]:
        return {key: _plain(value) for key, value in asdict(self).items()}  # type: ignore[arg-type]

    def stable_dict(self) -> dict[str, Any]:
        """``as_dict`` without volatile fields, recursively."""
        return strip_volatile(self.as_dict())


def strip_volatile(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: strip_volatile(item) for key, item in value.items() if key not in VOLATILE_FIELDS}
    if isinstance(value, list):
        return [strip_volatile(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_id(prefix: str, *parts: Any) -> str:
    """Deterministic identifier derived from content, never from wall time."""
    digest = hashlib.sha256(canonical_json([_plain(part) for part in parts]).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:16]}"


def write_jsonl(path: Any, records: Iterable[Record | dict[str, Any]], *, sort_key: str | None = None) -> str:
    """Write records as canonical JSONL and return the file SHA-256."""
    rows = [record.as_dict() if isinstance(record, Record) else record for record in records]
    if sort_key:
        rows.sort(key=lambda row: canonical_json(row.get(sort_key)))
    data = "".join(canonical_json(row) + "\n" for row in rows).encode("utf-8")
    with open(path, "wb") as handle:
        handle.write(data)
    return hashlib.sha256(data).hexdigest()


def read_jsonl(path: Any) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


# --------------------------------------------------------------------------- policy

@dataclass(frozen=True)
class PolicyRefusal(Record):
    """A destination refused by the central TargetPolicy (outcome ``policy_refused``)."""
    stage: str            # zmap | zgrab | dns | document | document_redirect | favicon | favicon_redirect | enrichment
    subject: str          # IP, hostname or URL that was refused
    reason: str           # e.g. outside_population, loopback, link_local, private, excluded_prefix, unsafe_scheme
    context: str = ""     # identity key or URL that led to the subject
    observed_at: str = ""


# --------------------------------------------------------------------------- L4 / ZMap

@dataclass(frozen=True)
class L4Result(Record):
    target_ip: str
    port: int
    vantage_id: str
    zmap_job_id: str
    transport: str = "tcp"
    classification: str = "synack"   # ZMap success classification
    observed_at: str = ""


@dataclass(frozen=True)
class ToolJob(Record):
    """One external tool invocation (ZMap or ZGrab2). Counted for gate S1."""
    job_id: str
    tool: str               # zmap | zgrab2
    purpose: str            # e.g. l4:port=443, direct:http:port=80, hostname:https:port=443
    command: tuple[str, ...]
    input_count: int
    output_count: int
    exit_code: int | None
    raw_path: str           # path relative to the run directory
    raw_sha256: str
    started_at: str = ""
    finished_at: str = ""
    error: str | None = None


# --------------------------------------------------------------------------- TLS

@dataclass(frozen=True)
class CertificateInfo(Record):
    sha256: str
    subject_cn: str | None
    san_dns: tuple[str, ...]
    issuer: str | None
    serial: str | None
    not_before: str | None          # ISO-8601 UTC
    not_after: str | None
    signature_algorithm: str | None
    public_key_algorithm: str | None
    public_key_bits: int | None
    chain_sha256: tuple[str, ...]
    handshake_mode: AcquisitionMode
    sni_sent: str | None
    self_signed: bool | None
    expired_at_observation: bool | None
    not_yet_valid_at_observation: bool | None
    hostname_matches: bool | None   # SNI/Host vs SAN/CN; None for direct-IP handshakes
    target_ip: str = ""
    port: int = 0


# --------------------------------------------------------------------------- ZGrab2

@dataclass(frozen=True)
class ZGrabResult(Record):
    """One normalized ZGrab2 HTTP-module result line."""
    zgrab_job_id: str
    target_ip: str
    port: int
    scheme_attempted: Scheme
    acquisition_mode: AcquisitionMode
    request_hostname: str | None
    sni_hostname: str | None
    status: str                     # zgrab2 status: success, connection-timeout, io-timeout, protocol-error, application-error, unknown-error, parse_error
    http_status: int | None
    content_type: str | None
    content_encoding: str | None
    location: str | None
    body_sha256: str | None
    body_bytes: int | None
    tls_handshake_ok: bool | None
    tls_error: str | None
    certificate: CertificateInfo | None
    error: str | None
    raw_line_sha256: str


@dataclass(frozen=True)
class ProtocolClassification(Record):
    target_ip: str
    port: int
    classification: ProtocolClass
    http_status: str                # zgrab status of plaintext attempt
    https_status: str               # zgrab status of TLS attempt
    failure_category: str | None    # e.g. tls_handshake_timeout, tls_alert, connection_timeout


# --------------------------------------------------------------------------- hostname discovery

@dataclass(frozen=True)
class HostnameEvidence(Record):
    evidence_id: str                # stable_id("HEV", source, provider, queried_value, hostname, discovered_via_ip)
    hostname: str                   # normalized: lower-case, no trailing dot, IDNA A-label
    source: Source
    provider: str
    queried_value: str              # IP, domain or certificate SHA-256 used in the query
    discovered_via_ip: str          # L4-positive IP that led to this evidence
    query_timestamp: str = ""
    first_seen: str | None = None
    last_seen: str | None = None
    record_type: str | None = None
    confidence: str | None = None
    wildcard: bool = False          # source name was a wildcard (*.x); stored normalized, never probed literally
    raw_ref: str = ""


@dataclass(frozen=True)
class HostnameCandidate(Record):
    """Deduplicated hostname with every piece of evidence retained."""
    hostname: str
    sources: tuple[str, ...]        # sorted unique sources
    evidence_ids: tuple[str, ...]   # sorted
    discovered_via_ips: tuple[str, ...]


@dataclass(frozen=True)
class TruncationRecord(Record):
    target_ip: str
    source: str
    source_count: int
    retained_count: int
    selection_policy: str
    truncated: bool


@dataclass(frozen=True)
class DNSVerification(Record):
    hostname: str
    status: DNSStatus
    answers: tuple[str, ...]        # final A-record set, sorted
    cname_chain: tuple[str, ...]    # names traversed after the queried name
    resolver: str
    attempts: int
    wildcard_parent: str | None     # parent zone detected as wildcard, if any
    error: str | None = None
    queried_at: str = ""


@dataclass(frozen=True)
class HostnameMapping(Record):
    """(hostname, ip) mapping judgement used for identity construction and oracle F8."""
    hostname: str
    target_ip: str                  # IP the mapping is judged against
    status: DNSStatus               # relative to target_ip
    mapping_current: bool
    evidence_ids: tuple[str, ...]
    sources: tuple[str, ...]


# --------------------------------------------------------------------------- identities

@dataclass(frozen=True)
class ProbePlan(Record):
    """A hostname-aware probe to run in stage F (scheme decided by the probe)."""
    target_ip: str
    port: int
    hostname: str
    schemes: tuple[Scheme, ...]


@dataclass(frozen=True)
class WebIdentity(Record):
    """Primary oracle unit: (target_ip, port, scheme, request_hostname)."""
    identity_id: str                # stable_id("WID", target_ip, port, scheme, request_hostname)
    target_ip: str
    port: int
    scheme: Scheme
    acquisition_mode: AcquisitionMode
    request_hostname: str | None
    sni_hostname: str | None
    hostname_sources: tuple[str, ...] = ()
    hostname_evidence_ids: tuple[str, ...] = ()
    dns_status: str | None = None
    dns_answers: tuple[str, ...] = ()
    cname_chain: tuple[str, ...] = ()
    mapping_current: bool | None = None

    @property
    def key(self) -> str:
        return identity_key(self.target_ip, self.port, self.scheme, self.request_hostname)


def identity_key(target_ip: str, port: int, scheme: str | None, hostname: str | None) -> str:
    return f"{target_ip}|{port}|{scheme or '-'}|{hostname or '-'}"


# --------------------------------------------------------------------------- web acquisition

@dataclass(frozen=True)
class RedirectHop(Record):
    from_url: str
    status: int
    location: str
    to_url: str | None              # resolved absolute URL, None if unparsable
    connect_ip: str | None          # IP the next hop would connect to
    decision: str                   # followed | policy_refused | loop | limit | unsupported_scheme | dns_failure


@dataclass(frozen=True)
class FetchResult(Record):
    """Outcome of one document or favicon GET via scanner.web_fetch."""
    kind: str                       # document | favicon
    requested_url: str
    connect_ip: str | None
    host_header: str | None
    sni: str | None
    outcome: str                    # ok | http_status | policy_refused | timeout | connect_error | tls_error | protocol_error | reset | body_too_large | decoded_too_large | too_many_redirects | redirect_loop | unsupported_encoding | dns_failure
    failure_category: str | None
    http_status: int | None
    content_type: str | None
    content_encoding: str | None
    retry_after: str | None
    body_sha256: str | None
    body_bytes: int
    redirect_chain: tuple[RedirectHop, ...]
    final_url: str | None
    certificate: CertificateInfo | None
    retries: int = 0
    timing_ms: float = 0.0


@dataclass(frozen=True)
class FaviconDeclaration(Record):
    page_url: str
    order: int
    rel: str | None                 # normalized rel token string, None for fallback
    kind: str                       # icon | apple-touch-icon | fallback | manifest | data
    sizes: str | None
    type: str | None
    media: str | None
    declared_href: str
    resolved_url: str | None        # None when unresolvable/unsupported
    policy_status: str              # selected | duplicate | over_limit | unsupported_scheme | not_in_policy


@dataclass(frozen=True)
class FaviconResource(Record):
    resolved_url: str
    final_url: str | None
    declaration_orders: tuple[int, ...]   # provenance: every declaration that referenced it
    fetch: FetchResult | None             # None for data: URIs decoded locally
    content_type_claimed: str | None
    favicon_bytes: int
    favicon_sha256: str | None
    decode_status: str | None
    fingerprint: dict[str, Any] | None
    shared_default_cluster: bool = False


@dataclass(frozen=True)
class ObservationRecordV2(Record):
    observation_id: str
    run_id: str
    vantage_id: str
    epoch: str
    identity_id: str
    target_ip: str
    port: int
    transport_result: str
    scheme: str | None
    acquisition_mode: AcquisitionMode
    request_hostname: str | None
    sni_hostname: str | None
    hostname_sources: tuple[str, ...]
    hostname_evidence_ids: tuple[str, ...]
    dns_status: str | None
    dns_answers: tuple[str, ...]
    cname_chain: tuple[str, ...]
    source_record_timestamp: str | None
    mapping_current: bool | None
    zgrab_job_id: str | None
    zgrab_status: str | None
    http_status: int | None
    input_url: str | None
    redirect_chain: tuple[RedirectHop, ...]
    final_url: str | None
    content_type: str | None
    content_encoding: str | None
    page_bytes: int | None
    page_sha256: str | None
    same_as_direct_ip: bool | None        # VH-04 catch-all similarity
    favicon_declarations: tuple[FaviconDeclaration, ...]
    favicons: tuple[FaviconResource, ...]
    favicon_url: str | None               # first acquired icon (compatibility/ablation)
    favicon_final_url: str | None
    favicon_content_type: str | None
    favicon_bytes: int | None
    favicon_sha256: str | None
    fingerprint: dict[str, Any] | None
    certificate_sha256: str | None
    certificate_sans: tuple[str, ...]
    certificate_not_before: str | None
    certificate_not_after: str | None
    asn: int | None
    asn_prefix: str | None
    asn_org: str | None
    outcome: str                          # ok | no_favicon | failure
    failure_stage: str | None
    failure_category: str | None
    retries: int
    schema_version: int = SCHEMA_VERSION
    timing_ms: float = 0.0
    observed_at: str = ""


@dataclass(frozen=True)
class ASNInfo(Record):
    target_ip: str
    prefix: str
    asn: int
    organization: str
    source: str
    shared_hosting: bool            # a shared/cloud ASN is context, never ownership evidence
    query_timestamp: str = ""


@dataclass(frozen=True)
class CandidateRecordV2(Record):
    candidate_id: str               # stable_id("CAN", observation_id, favicon_sha256, reference_id)
    observation_id: str
    identity_id: str
    favicon_sha256: str
    reference_id: str
    brand_id: str
    match_type: str                 # content_exact | pixel_exact | dhash | phash
    match_distance: int
    allowlist_decision: str         # candidate | allowed | unresolved
    allowlist_rule_kind: str | None
    allowlist_evidence: str | None
    allowlist_reason: str
    validation_label: str = "candidate"
    schema_version: int = SCHEMA_VERSION


def record_fields(cls: type) -> list[str]:
    return [item.name for item in fields(cls)]


__all__ = [name for name in dir() if not name.startswith("_")]
_ = field  # re-exported for convenience in stage modules
