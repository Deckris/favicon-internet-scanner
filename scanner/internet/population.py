"""Sample-plan arithmetic: whole IPv4 space minus reserved space minus exclusions.

The target population handed to ZMap is the complement of the reserved ranges
(as a short CIDR list); exclusions go to ZMap's blocklist. ``-n`` is the number
of targets ZMap will probe, drawn from a seeded permutation, so every port sees
the same sample.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from scanner.internet.config import RESERVED_V4


def population_cidrs(reserved: tuple[str, ...] = RESERVED_V4) -> list[str]:
    nets = [ipaddress.ip_network("0.0.0.0/0")]
    for r in sorted(ipaddress.ip_network(x) for x in reserved):
        nxt: list[ipaddress.IPv4Network] = []
        for n in nets:
            if n.overlaps(r):
                nxt.extend(n.address_exclude(r) if r.subnet_of(n) else [])
            else:
                nxt.append(n)
        nets = nxt
    return [str(n) for n in ipaddress.collapse_addresses(sorted(nets))]


def _overlap(a: ipaddress.IPv4Network, b: ipaddress.IPv4Network) -> int:
    if not a.overlaps(b):
        return 0
    return min(a.num_addresses, b.num_addresses)   # CIDR blocks nest or are disjoint


def allowed_addresses(population: list[str], exclusions: list[str]) -> int:
    pop = [ipaddress.ip_network(p) for p in population]
    nets = (ipaddress.ip_network(e) for e in exclusions)
    excl = list(ipaddress.collapse_addresses(n for n in nets if n.version == 4))
    total = sum(n.num_addresses for n in pop)
    removed = sum(_overlap(p, e) for p in pop for e in excl)
    return total - removed


@dataclass(frozen=True)
class SamplePlan:
    population: tuple[str, ...]
    allowed_addresses: int
    fraction: float
    targets_per_port: int
    ports: tuple[int, ...]
    rate: float
    probes: int
    shards: int = 1
    shard: int = 0
    total_targets: int = 0      # across all shards; targets_per_port is this shard's share

    @property
    def seconds_per_port(self) -> float:
        return self.targets_per_port * self.probes / self.rate if self.rate else 0.0

    @property
    def total_probes(self) -> int:
        return self.targets_per_port * self.probes * len(self.ports)


def plan(population: list[str], exclusions: list[str], *, fraction: float, ports: tuple[int, ...], rate: float, probes: int,
         shards: int = 1, shard: int = 0) -> SamplePlan:
    allowed = allowed_addresses(population, exclusions)
    total = int(allowed * fraction)
    if total < shards:
        raise ValueError(f"the sample has {total} targets but {shards} shards were requested; use fewer shards")
    total = max(1, total)
    share = total // shards + (1 if shard < total % shards else 0)
    return SamplePlan(tuple(population), allowed, fraction, share, tuple(ports), rate, probes, shards, shard, total)
