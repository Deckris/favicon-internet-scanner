"""Central target/safety policy shared by every network stage.

No network stage (ZMap, ZGrab2, DNS-derived identities, document/favicon
fetches, redirects, enrichment follow-ups) may touch an address or hostname
without first clearing this policy. The default profile refuses everything.
"""
from __future__ import annotations

import ipaddress
import re
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Iterable
from urllib.parse import urlsplit

from scanner.models import PolicyRefusal

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_LAB_TEST_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

# Always refused, in every profile, before any population check.
_ALWAYS_DENY: tuple[tuple[str, ipaddress.IPv4Network], ...] = (
    ("unspecified", ipaddress.ip_network("0.0.0.0/32")),
    ("reserved", ipaddress.ip_network("0.0.0.0/8")),
    ("loopback", ipaddress.ip_network("127.0.0.0/8")),
    ("link_local", ipaddress.ip_network("169.254.0.0/16")),
    ("private", ipaddress.ip_network("10.0.0.0/8")),
    ("private", ipaddress.ip_network("172.16.0.0/12")),
    ("private", ipaddress.ip_network("192.168.0.0/16")),
    ("cgnat", ipaddress.ip_network("100.64.0.0/10")),
    ("multicast", ipaddress.ip_network("224.0.0.0/4")),
    ("broadcast", ipaddress.ip_network("255.255.255.255/32")),
    ("reserved", ipaddress.ip_network("240.0.0.0/4")),
)

_HOSTNAME_RE = re.compile(
    r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)

# Max value for the trailing component of an N-part dotted-numeric address,
# BSD/inet_aton style (e.g. "127.1" == 127.0.0.1, "0x7f000001" == 127.0.0.1).
_DOTTED_NUMERIC_LAST_MAX = {1: 0xFFFFFFFF, 2: 0xFFFFFF, 3: 0xFFFF, 4: 0xFF}


def _as_ip(value: str) -> IpAddress | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _parse_dotted_numeric_component(part: str) -> int | None:
    if not part:
        return None
    lowered = part.lower()
    try:
        if lowered.startswith("0x"):
            return int(part, 16)
        if len(part) > 1 and part[0] == "0" and part.isdigit():
            return int(part, 8)
        if part.isdigit():
            return int(part, 10)
    except ValueError:
        return None
    return None


def _is_ambiguous_ip_literal(candidate: str) -> bool:
    """True for hostnames that are actually numeric/alt-base IPv4 literals.

    Covers pure-decimal (``2130706433``), hex (``0x7f000001``), octal
    (``0177.0.0.1``) and short BSD-style forms (``127.1``) that
    ``ipaddress.ip_address`` refuses to parse but that many HTTP clients and
    OS resolvers still treat as IP addresses.
    """
    parts = candidate.split(".")
    if not (1 <= len(parts) <= 4):
        return False
    values: list[int] = []
    for part in parts:
        value = _parse_dotted_numeric_component(part)
        if value is None:
            return False
        values.append(value)
    last_max = _DOTTED_NUMERIC_LAST_MAX[len(values)]
    for index, value in enumerate(values):
        limit = 0xFF if index < len(values) - 1 else last_max
        if not (0 <= value <= limit):
            return False
    return True


class PolicyRefused(Exception):
    """Raised by ``require_ip`` when the central policy refuses a destination."""

    def __init__(self, refusal: PolicyRefusal) -> None:
        super().__init__(f"{refusal.stage}: refused {refusal.subject} ({refusal.reason})")
        self.refusal = refusal


@dataclass
class TargetPolicy:
    profile: str
    _population: tuple[ipaddress.IPv4Network, ...] = field(default_factory=tuple)
    _exclusions: tuple[ipaddress.IPv4Network, ...] = field(default_factory=tuple)
    _allow_special_use: bool = False
    _hostname_suffixes: tuple[str, ...] = ()
    _deny_all: bool = False
    refusals: list[PolicyRefusal] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # ---------------------------------------------------------------- factories

    @classmethod
    def lab(cls, *, population: list[str], exclusions: list[str] = ()) -> "TargetPolicy":
        pop_nets = tuple(ipaddress.ip_network(cidr, strict=True) for cidr in population)
        for net in pop_nets:
            if not any(net.subnet_of(test_net) for test_net in _LAB_TEST_NETS):
                raise ValueError(f"lab population {net} is outside the TEST-NET ranges")
        return cls(
            profile="lab",
            _population=pop_nets,
            _exclusions=tuple(ipaddress.ip_network(cidr, strict=True) for cidr in exclusions),
            _allow_special_use=True,
            _hostname_suffixes=(".test",),
        )

    @classmethod
    def production(cls, cfg: "ProductionPolicyInput") -> "TargetPolicy":
        if not cfg.approval_reference or not cfg.approval_reference.strip():
            raise ValueError("production policy requires a non-empty approval_reference")
        if not cfg.population:
            raise ValueError("production policy requires an approved target population")
        if cfg.hostname_policy is None:
            raise ValueError("production policy requires an explicit hostname_policy")
        if cfg.hostname_policy.mode not in ("any_public", "suffix_allowlist"):
            raise ValueError(f"unknown hostname_policy mode: {cfg.hostname_policy.mode!r}")
        if cfg.hostname_policy.mode == "suffix_allowlist" and not cfg.hostname_policy.suffixes:
            raise ValueError("hostname_policy mode suffix_allowlist requires at least one suffix")
        pop_nets = tuple(ipaddress.ip_network(cidr, strict=True) for cidr in cfg.population)
        for net in pop_nets:
            if any(net.overlaps(test_net) for test_net in _LAB_TEST_NETS):
                raise ValueError(f"production population {net} overlaps a TEST-NET range")
        hostname_suffixes = (
            tuple(cfg.hostname_policy.suffixes) if cfg.hostname_policy.mode == "suffix_allowlist" else ()
        )
        return cls(
            profile="production",
            _population=pop_nets,
            _exclusions=tuple(ipaddress.ip_network(cidr, strict=True) for cidr in cfg.exclusions),
            _allow_special_use=False,
            _hostname_suffixes=hostname_suffixes,
        )

    @classmethod
    def disabled(cls) -> "TargetPolicy":
        return cls(profile="disabled", _deny_all=True)

    @classmethod
    def for_tests(cls, networks: list[str], exclusions: Iterable[str] = ()) -> "TargetPolicy":
        """Python-only test helper. Never reachable from a YAML config.

        Unlike every other profile, this one accepts arbitrary (including
        loopback/private) networks for the caller's convenience in unit
        tests. The always-deny table still applies, except for the specific
        networks the caller explicitly lists in ``networks`` -- those are
        carved out of the deny table, not exempted wholesale. Everything
        else on the deny table (and anything in ``exclusions``) stays
        refused.
        """
        return cls(
            profile="test",
            _population=tuple(ipaddress.ip_network(cidr, strict=True) for cidr in networks),
            _exclusions=tuple(ipaddress.ip_network(cidr, strict=True) for cidr in exclusions),
            _allow_special_use=True,
            _hostname_suffixes=(),
        )

    # ---------------------------------------------------------------- checks

    def _record(self, stage: str, subject: str, reason: str, context: str) -> PolicyRefusal:
        refusal = PolicyRefusal(
            stage=stage,
            subject=subject,
            reason=reason,
            context=context,
            observed_at=datetime.now(UTC).isoformat(),
        )
        with self._lock:
            self.refusals.append(refusal)
        return refusal

    def check_ip(self, ip: str, *, stage: str, context: str = "") -> PolicyRefusal | None:
        if self._deny_all:
            return self._record(stage, ip, "disabled_profile", context)
        parsed = _as_ip(ip)
        if parsed is None:
            return self._record(stage, ip, "invalid_hostname", context)
        if isinstance(parsed, ipaddress.IPv6Address):
            return self._record(stage, ip, "ipv6", context)
        v4 = parsed
        for reason, net in _ALWAYS_DENY:
            if v4 in net:
                carved_out = self.profile == "test" and any(
                    pop.subnet_of(net) for pop in self._population
                )
                if not carved_out:
                    return self._record(stage, ip, reason, context)
        for net in self._exclusions:
            if v4 in net:
                return self._record(stage, ip, "excluded_prefix", context)
        if not self._allow_special_use:
            for net in _LAB_TEST_NETS:
                if v4 in net:
                    return self._record(stage, ip, "documentation_range", context)
        if not any(v4 in net for net in self._population):
            return self._record(stage, ip, "outside_population", context)
        return None

    def check_hostname(self, name: str, *, stage: str, context: str = "") -> PolicyRefusal | None:
        if self._deny_all:
            return self._record(stage, name, "disabled_profile", context)
        if any(c.isspace() or ord(c) < 32 for c in name):
            return self._record(stage, name, "invalid_hostname", context)
        candidate = name.strip().lower().rstrip(".")
        if candidate == "localhost" or candidate.endswith(".localhost"):
            return self._record(stage, name, "reserved_hostname", context)
        if not candidate or len(candidate) > 253 or not _HOSTNAME_RE.fullmatch(candidate):
            return self._record(stage, name, "invalid_hostname", context)
        if "*" in candidate:
            return self._record(stage, name, "invalid_hostname", context)
        if _is_ambiguous_ip_literal(candidate):
            return self._record(stage, name, "ambiguous_ip_literal", context)
        if "." not in candidate:
            return self._record(stage, name, "single_label_hostname", context)
        if self._hostname_suffixes and not any(
                candidate == suffix.lstrip(".") or candidate.endswith("." + suffix.lstrip(".")) for suffix in self._hostname_suffixes):
            return self._record(stage, name, "hostname_suffix", context)
        return None

    def check_url(self, url: str, *, stage: str, context: str = "") -> PolicyRefusal | None:
        if self._deny_all:
            return self._record(stage, url, "disabled_profile", context)
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return self._record(stage, url, "unsafe_scheme", context)
        if parts.username or parts.password:
            return self._record(stage, url, "userinfo", context)
        host = parts.hostname
        if not host:
            return self._record(stage, url, "invalid_hostname", context)
        if _as_ip(host) is not None:
            return self.check_ip(host, stage=stage, context=context)
        return self.check_hostname(host, stage=stage, context=context)

    def require_ip(self, ip: str, *, stage: str, context: str = "") -> None:
        refusal = self.check_ip(ip, stage=stage, context=context)
        if refusal is not None:
            raise PolicyRefused(refusal)

    # ---------------------------------------------------------------- ZMap helpers

    def target_cidrs(self) -> list[str]:
        return sorted(str(net) for net in self._population)

    def exclusion_cidrs(self) -> list[str]:
        return sorted(str(net) for net in self._exclusions)


@dataclass(frozen=True)
class HostnamePolicyInput:
    mode: str  # "any_public" | "suffix_allowlist"
    suffixes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProductionPolicyInput:
    approval_reference: str
    population: tuple[str, ...]
    hostname_policy: HostnamePolicyInput | None = None
    exclusions: tuple[str, ...] = ()
