"""Known-targets mode: probe exactly the listed addresses, with operator-supplied hostnames as candidates."""
import json

import pytest
import yaml

from scanner.internet import pipeline
from scanner.internet.config import ConfigError, load_config
from tests.helpers import FakeFetcher, FakeTools, config_dict, write_approval, write_exclusions
from tests.test_pipeline import IP_OK, rows_of

OWNED = "owner.example"


def _config(tmp_path, **sample):
    excl = write_exclusions(tmp_path)
    d = config_dict(tmp_path, excl, write_approval(tmp_path, excl))
    d["sample"] = {"seed": 4, **sample}
    p = tmp_path / "targets.yaml"
    p.write_text(yaml.safe_dump(d), encoding="utf-8")
    return p


def test_sample_needs_exactly_one_of_fraction_or_targets(tmp_path):
    with pytest.raises(ConfigError, match="exactly one"):
        load_config(_config(tmp_path))
    with pytest.raises(ConfigError, match="exactly one"):
        load_config(_config(tmp_path, fraction=0.0001, target_ips=[IP_OK]))
    with pytest.raises(ConfigError, match="needs sample.target_ips"):
        load_config(_config(tmp_path, fraction=0.0001, target_hostnames=[OWNED]))


@pytest.mark.parametrize("bad", ["10.0.0.5", "127.0.0.1", "not-an-ip", "2606:4700::1111"])
def test_target_ips_must_be_public_ipv4(tmp_path, bad):
    with pytest.raises(ConfigError):
        load_config(_config(tmp_path, target_ips=[bad]))


def test_known_target_run_probes_only_that_address_and_verifies_the_supplied_name(tmp_path):
    cfg = load_config(_config(tmp_path, target_ips=[IP_OK], target_hostnames=[OWNED.upper()]))
    assert cfg.target_ips == (IP_OK,) and cfg.target_hostnames == (OWNED.upper().lower(),)
    policy, splan, _ = pipeline.build_policy(cfg)
    assert splan.targets_per_port == 1 and policy.target_cidrs() == [f"{IP_OK}/32"]
    ft = FakeTools(l4={443: [IP_OK]}, tls={(IP_OK, 443): "ok"}, tls_sni={(IP_OK, OWNED): "ok"}, http={},
                   ptr={}, a={OWNED: [IP_OK], "good.test": [IP_OK]}, nxdomain=set())
    f = FakeFetcher()
    run_dir = pipeline.run(cfg, run_id="t1", executor=ft, fetcher=f, skip_preflight=True, offline_preflight=True)
    rows = rows_of(run_dir)
    owned = [r for r in rows if r["hostname"] == OWNED][0]
    assert owned["hostname_sources"] == ["operator_supplied"] and owned["final_hostname_status"] == "verified"
    assert owned["sni_confirmation_attempted"] and owned["hostname_favicon_outcome"] == "image"
    allow = next(p for p in (run_dir / "raw" / "zmap").glob("*-allowlist.txt") if "sample" not in p.name)
    assert allow.read_text().split() == [f"{IP_OK}/32"]                       # ZMap is only ever pointed at the listed address
    assert json.loads((run_dir / "manifest.json").read_text())["sample"]["target_ips"] == [IP_OK]
    assert all(ip == IP_OK for _u, ip, _k in f.calls)
