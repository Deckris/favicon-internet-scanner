"""Indexed population/exclusion membership gives the same answers as a linear scan."""
import ipaddress
import random
import time

from scanner import safety
from scanner.safety import (
    HostnamePolicyInput,
    ProductionPolicyInput,
    TargetPolicy,
    _ALWAYS_DENY,
    _LAB_TEST_NETS,
    _as_ip,
)


def _reference(policy: TargetPolicy, ip: str) -> str | None:
    """The linear check_ip logic, returning only the refusal reason."""
    if policy._deny_all:
        return "disabled_profile"
    parsed = _as_ip(ip)
    if parsed is None:
        return "invalid_hostname"
    if isinstance(parsed, ipaddress.IPv6Address):
        return "ipv6"
    v4 = parsed
    for reason, net in _ALWAYS_DENY:
        if v4 in net:
            carved_out = policy.profile == "test" and any(
                pop.subnet_of(net) for pop in policy._population
            )
            if not carved_out:
                return reason
    for net in policy._exclusions:
        if v4 in net:
            return "excluded_prefix"
    if not policy._allow_special_use:
        for net in _LAB_TEST_NETS:
            if v4 in net:
                return "documentation_range"
    if not any(v4 in net for net in policy._population):
        return "outside_population"
    return None


def _edges(nets) -> list[str]:
    out = {"0.0.0.0", "255.255.255.255", "127.0.0.1", "10.0.0.1", "192.0.2.1"}
    for net in nets:
        lo = int(net.network_address)
        hi = int(net.broadcast_address)
        for value in (lo - 1, lo, lo + 1, hi - 1, hi, hi + 1):
            if 0 <= value <= 0xFFFFFFFF:
                out.add(str(ipaddress.IPv4Address(value)))
    return sorted(out)


def _compare(policy: TargetPolicy, samples: list[str]) -> None:
    for ip in samples:
        expected = _reference(policy, ip)
        before = len(policy.refusals)
        got = policy.check_ip(ip, stage="s", context="c")
        if expected is None:
            assert got is None, ip
            assert len(policy.refusals) == before
        else:
            assert got is not None and got.reason == expected, (ip, expected, got)
            assert got.subject == ip and got.stage == "s" and got.context == "c"
            assert policy.refusals[-1] is got and len(policy.refusals) == before + 1


def _random_ips(rng: random.Random, count: int, nets) -> list[str]:
    out = [str(ipaddress.IPv4Address(rng.getrandbits(32))) for _ in range(count - count // 2)]
    spans = [(int(n.network_address), int(n.broadcast_address)) for n in nets]
    for _ in range(count // 2):
        lo, hi = rng.choice(spans)
        out.append(str(ipaddress.IPv4Address(rng.randint(max(lo - 3, 0), min(hi + 3, 0xFFFFFFFF)))))
    return out


ODD_INPUTS = ["", "nope", "1.2.3", "1.2.3.4.5", "::1", "2001:db8::1", "999.1.1.1", " 8.8.8.8", "08.8.8.8"]


def test_slash32_population_matches_linear_reference():
    rng = random.Random(1234)
    pop = sorted({rng.getrandbits(32) for _ in range(2000)} | {0x08080808, 0x01010101})
    cidrs = [f"{ipaddress.IPv4Address(v)}/32" for v in pop]
    excl = ["8.8.8.8/32", "1.1.1.0/24"]
    policy = TargetPolicy.for_tests(cidrs, exclusions=excl)
    nets = [ipaddress.ip_network(c) for c in cidrs + excl]
    samples = _random_ips(rng, 100_000, nets) + _edges(nets) + ODD_INPUTS
    _compare(policy, samples)


def test_mixed_prefix_population_matches_linear_reference():
    rng = random.Random(99)
    cidrs = []
    for _ in range(300):
        prefix = rng.choice([8, 12, 16, 20, 24, 28, 30, 31, 32])
        addr = rng.getrandbits(32) >> (32 - prefix) << (32 - prefix)
        cidrs.append(f"{ipaddress.IPv4Address(addr)}/{prefix}")
    cidrs += ["203.0.113.0/26", "203.0.113.64/26", "127.5.0.0/16", "100.64.0.0/10"]
    excl = ["9.0.0.0/8", "203.0.113.128/25", "50.50.50.50/32"]
    policy = TargetPolicy.for_tests(cidrs, exclusions=excl)
    nets = [ipaddress.ip_network(c) for c in cidrs + excl]
    samples = _random_ips(rng, 100_000, nets) + _edges(nets) + ODD_INPUTS
    _compare(policy, samples)


def test_exclusions_overlapping_and_adjacent_match_linear_reference():
    rng = random.Random(7)
    pop = ["20.0.0.0/8", "30.0.0.0/16"]
    excl = ["20.1.0.0/16", "20.1.5.0/24", "20.2.0.0/16", "20.3.3.3/32", "30.0.0.0/17", "30.0.128.0/17"]
    policy = TargetPolicy.for_tests(pop, exclusions=excl)
    nets = [ipaddress.ip_network(c) for c in pop + excl]
    samples = _random_ips(rng, 100_000, nets) + _edges(nets)
    _compare(policy, samples)


def test_empty_population_and_exclusions():
    rng = random.Random(3)
    policy = TargetPolicy.for_tests([])
    samples = _random_ips(rng, 5000, [ipaddress.ip_network("8.8.8.0/24")]) + ODD_INPUTS
    _compare(policy, samples)


def test_production_and_disabled_profiles_match_reference():
    rng = random.Random(5)
    cfg = ProductionPolicyInput(
        approval_reference="ref",
        population=("8.8.0.0/16", "1.1.1.1/32", "9.9.9.0/24"),
        hostname_policy=HostnamePolicyInput(mode="any_public"),
        exclusions=("8.8.8.0/24",),
    )
    policy = TargetPolicy.production(cfg)
    nets = [ipaddress.ip_network(c) for c in cfg.population + cfg.exclusions]
    samples = _random_ips(rng, 20_000, nets) + _edges(nets) + ODD_INPUTS
    _compare(policy, samples)
    _compare(TargetPolicy.disabled(), samples[:200])


def test_public_attributes_and_cidr_listings_unchanged():
    policy = TargetPolicy.for_tests(["8.8.8.8/32", "8.8.4.0/24"], exclusions=["8.8.4.4/32"])
    assert policy._population == (ipaddress.ip_network("8.8.8.8/32"), ipaddress.ip_network("8.8.4.0/24"))
    assert policy._exclusions == (ipaddress.ip_network("8.8.4.4/32"),)
    assert policy.target_cidrs() == ["8.8.4.0/24", "8.8.8.8/32"]
    assert policy.exclusion_cidrs() == ["8.8.4.4/32"]


def test_large_slash32_population_checks_are_fast():
    rng = random.Random(11)
    values = {rng.getrandbits(32) for _ in range(80_000)}
    cidrs = [f"{ipaddress.IPv4Address(v)}/32" for v in values]
    policy = TargetPolicy.for_tests(cidrs)
    members = list(values)[:5000]
    probes = [str(ipaddress.IPv4Address(v)) for v in members]
    probes += [str(ipaddress.IPv4Address(rng.getrandbits(32))) for _ in range(5000)]
    start = time.perf_counter()
    for ip in probes:
        policy.check_ip(ip, stage="s")
    assert time.perf_counter() - start < 0.5
