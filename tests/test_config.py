"""Authorization gate, config strictness and sample arithmetic."""
import ipaddress

import pytest
import yaml

from scanner.internet import population as pop
from scanner.internet.config import ConfigError, load_config
from tests.helpers import config_dict, write_approval, write_config, write_exclusions


def test_valid_config_loads_with_approval(tmp_path):
    cfg = load_config(write_config(tmp_path))
    assert cfg.approval.approval_reference == "TEST-REF-1"
    assert cfg.max_sample_fraction == 0.0001 and cfg.measurement.ports == (80, 443, 8080)


def _rewrite(tmp_path, mutate):
    p = write_config(tmp_path)
    data = yaml.safe_load(p.read_text())
    mutate(data)
    p.write_text(yaml.safe_dump(data))
    return p


def test_unknown_top_level_and_nested_keys_refused(tmp_path):
    with pytest.raises(ConfigError, match="unknown top-level"):
        load_config(_rewrite(tmp_path, lambda d: d.update(extra=1)))
    with pytest.raises(ConfigError, match="unknown keys"):
        load_config(_rewrite(tmp_path, lambda d: d["sample"].update(oops=1)))


def test_placeholders_refused(tmp_path):
    with pytest.raises(ConfigError, match="placeholder"):
        load_config(_rewrite(tmp_path, lambda d: d["vantage"].update(id="REPLACE_ME")))


def test_sample_fraction_above_approval_refused(tmp_path):
    with pytest.raises(ConfigError, match="max_sample_fraction"):
        load_config(_rewrite(tmp_path, lambda d: d["sample"].update(fraction=0.001)))


def test_rate_above_approval_refused(tmp_path):
    with pytest.raises(ConfigError, match="max_rate"):
        load_config(_rewrite(tmp_path, lambda d: d["measurement"].update(zmap_rate=5000)))


def test_port_outside_approval_refused(tmp_path):
    with pytest.raises(ConfigError, match="ports outside"):
        load_config(_rewrite(tmp_path, lambda d: d["measurement"].update(ports=[80, 22])))


def test_unapproved_public_egress_address_refused(tmp_path):
    with pytest.raises(ConfigError, match="source address"):
        load_config(_rewrite(tmp_path, lambda d: d["vantage"].update(public_egress_ip="93.184.216.1")))


def test_public_egress_must_be_public(tmp_path):
    with pytest.raises(ConfigError, match="public IPv4"):
        load_config(_rewrite(tmp_path, lambda d: d["vantage"].update(public_egress_ip="172.30.83.179")))


def test_transparency_must_match_the_approval(tmp_path):
    def mutate(d):
        d["transparency"]["contact"] = "someone-else@example.org"
        d["fetch"]["user_agent"] = "scanner (+https://example.org/scan; contact someone-else@example.org)"
    with pytest.raises(ConfigError, match="transparency"):
        load_config(_rewrite(tmp_path, mutate))


def test_private_institutional_resolver_allowed_but_loopback_refused(tmp_path):
    assert load_config(_rewrite(tmp_path, lambda d: d["dns"].update(resolvers=["10.20.30.40"]))).dns.resolvers == ("10.20.30.40",)
    with pytest.raises(ConfigError, match="routable unicast"):
        load_config(_rewrite(tmp_path, lambda d: d["dns"].update(resolvers=["127.0.0.1"])))


def test_blocked_or_expired_or_missing_approval_refused(tmp_path):
    excl = write_exclusions(tmp_path)
    for over, msg in (({"status": "blocked"}, "not authorized"), ({"valid_until": "2000-01-01T00:00:00+00:00"}, "expired")):
        approval = write_approval(tmp_path, excl, **over)
        p = tmp_path / "c.yaml"
        p.write_text(yaml.safe_dump(config_dict(tmp_path, excl, approval)))
        with pytest.raises(ConfigError, match=msg):
            load_config(p)
    p = tmp_path / "c2.yaml"
    d = config_dict(tmp_path, excl, tmp_path / "does-not-exist.yaml")
    p.write_text(yaml.safe_dump(d))
    with pytest.raises(ConfigError, match="not authorized"):
        load_config(p)


def test_missing_operations_refused_and_favicon_operation_only_when_enabled(tmp_path):
    excl = write_exclusions(tmp_path)
    approval = write_approval(tmp_path, excl, operations=["hostname_resolution"])
    d = config_dict(tmp_path, excl, approval)
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(d))
    with pytest.raises(ConfigError, match="favicon_fetch"):
        load_config(p)
    d["favicon"]["enabled"] = False
    p.write_text(yaml.safe_dump(d))
    assert load_config(p).favicon.enabled is False


def test_approval_without_max_sample_fraction_refused(tmp_path):
    excl = write_exclusions(tmp_path)
    approval = write_approval(tmp_path, excl)
    data = yaml.safe_load(approval.read_text())
    del data["max_sample_fraction"]
    approval.write_text(yaml.safe_dump(data))
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(config_dict(tmp_path, excl, approval)))
    with pytest.raises(ConfigError, match="max_sample_fraction"):
        load_config(p)


def test_exclusion_checksum_mismatch_refused(tmp_path):
    p = write_config(tmp_path)
    (tmp_path / "exclusions.txt").write_text("1.2.3.0/24\n")
    with pytest.raises(ConfigError, match="checksum"):
        load_config(p)


def test_bad_resolver_refused(tmp_path):
    with pytest.raises(ConfigError, match="IP"):
        load_config(_rewrite(tmp_path, lambda d: d["dns"].update(resolvers=["dns.google"])))


def test_user_agent_must_identify_the_scanner(tmp_path):
    with pytest.raises(ConfigError, match="user_agent"):
        load_config(_rewrite(tmp_path, lambda d: d["fetch"].update(user_agent="python-requests")))


# ------------------------------------------------------------------ population / sample math

def test_population_excludes_reserved_ranges_and_is_compact():
    cidrs = pop.population_cidrs()
    nets = [ipaddress.ip_network(c) for c in cidrs]
    for bad in ("10.1.2.3", "127.0.0.1", "192.168.1.1", "203.0.113.5", "198.51.100.5", "192.0.2.5", "224.0.0.1", "255.255.255.255", "0.1.2.3", "100.64.0.1"):
        assert not any(ipaddress.ip_address(bad) in n for n in nets), bad
    for good in ("1.1.1.1", "8.8.8.8", "93.184.216.34"):
        assert any(ipaddress.ip_address(good) in n for n in nets), good
    assert len(cidrs) < 200


def test_allowed_addresses_and_001_percent_count():
    cidrs = pop.population_cidrs()
    total = pop.allowed_addresses(cidrs, [])
    assert 3_400_000_000 < total < 3_800_000_000            # ~3.7e9 routable-looking IPv4 addresses
    with_excl = pop.allowed_addresses(cidrs, ["8.8.4.0/24", "8.8.4.0/25", "10.0.0.0/8"])   # nested + reserved ones change nothing extra
    assert with_excl == total - 256
    p = pop.plan(cidrs, [], fraction=0.0001, ports=(80, 443), rate=1000, probes=2)
    assert p.targets_per_port == int(total * 0.0001)         # 0.01% of the allowed space
    assert 300_000 < p.targets_per_port < 400_000
    assert p.total_probes == p.targets_per_port * 2 * 2


def test_unquoted_yaml_timestamp_in_approval_is_accepted(tmp_path):
    p = write_config(tmp_path)
    approval = tmp_path / "approval.yaml"
    text = approval.read_text().replace("'2099-01-01T00:00:00+00:00'", "2099-01-01T00:00:00+00:00")
    assert "'2099" not in text
    approval.write_text(text)
    assert load_config(p).approval.valid_until.year == 2099


def test_anonymous_traffic_requires_an_explicit_flag_and_a_clean_user_agent(tmp_path):
    def anon(d):
        d["transparency"] = {"info_url": "none", "contact": "none", "anonymous": True}
        d["fetch"]["user_agent"] = "scanner-research-scan (academic measurement; no contact published)"
    p = _rewrite(tmp_path, anon)
    # the approval must say the same thing, otherwise identity differs from the config
    import yaml as _y
    ap = tmp_path / "approval.yaml"
    a = _y.safe_load(ap.read_text())
    a["transparency_url"], a["opt_out_contact"] = "none", "none"
    ap.write_text(_y.safe_dump(a))
    cfg = load_config(p)
    assert cfg.transparency.anonymous is True

    # without the flag, a contact-less user agent is still refused
    def sneaky(d):
        d["fetch"]["user_agent"] = "scanner-research-scan (no contact)"
    with pytest.raises(ConfigError, match="user_agent"):
        load_config(_rewrite(tmp_path / "x", sneaky)) if (tmp_path / "x").mkdir() is None else None

    # with the flag, an identifying user agent is refused (no half-anonymous state)
    def leaky(d):
        anon(d)
        d["fetch"]["user_agent"] = "scan (+https://example.org)"
    with pytest.raises(ConfigError, match="anonymous"):
        load_config(_rewrite(tmp_path / "y", leaky)) if (tmp_path / "y").mkdir() is None else None
