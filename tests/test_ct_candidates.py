"""Optional Certificate Transparency name source: linkage, caps, statuses, manifest and the off-by-default guarantee."""
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.internet import candidates as cand
from scanner.internet import outputs, pipeline
from scanner.internet.config import ConfigError, config_checksum, load_config, shared_config_checksum
from scanner.safety import TargetPolicy
from tests.helpers import FakeFetcher, write_config
from tests.test_pipeline import IP_OK, tools

POLICY = TargetPolicy.for_tests(["1.1.1.0/24"])


def _cert(sans=(), cn=None):
    return SimpleNamespace(san_dns=tuple(sans), subject_cn=cn)


def _names_file(tmp_path, names, suffix=".txt"):
    p = tmp_path / f"ct-names{suffix}"
    if suffix == ".jsonl":
        p.write_text("".join(json.dumps({"name": n}) + "\n" for n in names), encoding="utf-8")
    else:
        p.write_text("# synthetic\n" + "\n".join(names) + "\n", encoding="utf-8")
    return p


def _index(tmp_path, names, cap=50):
    return cand.load_ct_index(_names_file(tmp_path, names), max_per_domain=cap)


def _ct_modules():
    return [m for m in sys.modules if m == "scanner.ct" or m.startswith("scanner.ct.")]


def test_matching_domain_attaches_with_ct_provenance(tmp_path):
    idx = _index(tmp_path, ["api.example.com", "shop.example.com", "other.example.net"])
    ep = cand.build_endpoint_names(["host.example.com."], None, POLICY, max_candidates=20, ct_names=idx)
    assert ep.names["api.example.com"] == {"ct"} and ep.names["shop.example.com"] == {"ct"}
    assert ep.names["host.example.com"] == {"ptr"}
    assert "other.example.net" not in ep.names


def test_ct_name_merges_provenance_with_certificate_name(tmp_path):
    idx = _index(tmp_path, ["www.example.com"])
    ep = cand.build_endpoint_names([], _cert(["www.example.com"]), POLICY, max_candidates=20, ct_names=idx)
    assert ep.names["www.example.com"] == {"certificate_san", "ct"}


def test_non_matching_domain_and_operator_names_do_not_link(tmp_path):
    idx = _index(tmp_path, ["api.example.com", "api.example.org"])
    ep = cand.build_endpoint_names(["host.example.net"], None, POLICY, max_candidates=20,
                                   operator_names=("seed.example.org",), ct_names=idx)
    assert set(ep.names) == {"host.example.net", "seed.example.org"}


def test_no_ct_names_without_an_index():
    ep = cand.build_endpoint_names(["host.example.com"], None, POLICY, max_candidates=20)
    assert set(ep.names) == {"host.example.com"}


def test_wildcard_certificate_name_links_its_domain(tmp_path):
    idx = _index(tmp_path, ["api.example.com"])
    ep = cand.build_endpoint_names([], _cert(["*.example.com"]), POLICY, max_candidates=20, ct_names=idx)
    assert ep.wildcards == {"*.example.com"} and set(ep.names) == {"api.example.com"}


def test_policy_refused_ct_name_is_dropped(tmp_path):
    class Refuse:
        def check_hostname(self, name, **_):
            return "refused" if name.startswith("bad.") else None

    idx = _index(tmp_path, ["bad.example.com", "good.example.com"])
    ep = cand.build_endpoint_names(["host.example.com"], None, Refuse(), max_candidates=20, ct_names=idx)
    assert "bad.example.com" in ep.dropped and "bad.example.com" not in ep.names
    assert ep.names["good.example.com"] == {"ct"}


def test_per_ip_cap_holds_and_ct_only_names_go_last(tmp_path):
    idx = _index(tmp_path, [f"a{i}.example.com" for i in range(10)])
    ep = cand.build_endpoint_names(["zz.example.com"], _cert(["zzz.example.com"]), POLICY, max_candidates=4, ct_names=idx)
    assert len(ep.names) == 4 and ep.truncated and ep.source_count == 12
    assert {"zz.example.com", "zzz.example.com"} <= set(ep.names)          # PTR/SAN evidence outranks CT-only names
    assert sorted(n for n, s in ep.names.items() if s == {"ct"}) == ["a0.example.com", "a1.example.com"]


def test_per_domain_cap_holds_and_is_counted(tmp_path):
    idx = _index(tmp_path, [f"n{i:02d}.example.com" for i in range(8)] + ["x.example.net"], cap=3)
    assert idx.by_domain["example.com"] == ["n00.example.com", "n01.example.com", "n02.example.com"]
    assert idx.names_loaded == 9 and idx.names_dropped_by_cap == 5 and idx.domains_indexed == 2
    ep = cand.build_endpoint_names(["h.example.com"], None, POLICY, max_candidates=20, ct_names=idx)
    assert sorted(n for n, s in ep.names.items() if s == {"ct"}) == idx.by_domain["example.com"]


def test_jsonl_names_file_is_read(tmp_path):
    idx = cand.load_ct_index(_names_file(tmp_path, ["api.example.com"], ".jsonl"), max_per_domain=5)
    assert idx.by_domain == {"example.com": ["api.example.com"]}


def test_ct_only_evidence_status():
    f = cand.final_status
    assert f("no_answer", {"ct"}) == "ct_only_evidence"
    assert f("no_answer", {"ct", "ptr"}) == "multi_source_evidence"
    assert f("no_answer", {"ptr"}) == "ptr_only_evidence"
    assert f("verified_current_mapping", {"ct"}) == "verified"
    assert f("nxdomain", {"ct"}) == "nxdomain"
    assert f("timeout", {"ct"}) == "unresolved"


# ------------------------------------------------------------------------------------------ pipeline

def _go(cfg, ft):
    return pipeline.run(cfg, run_id="t1", executor=ft, fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)


def test_pipeline_labels_ct_names_and_records_manifest(tmp_path):
    names = _names_file(tmp_path, ["api.good.test", "mail.good.test", "unrelated.example"])
    cfg = load_config(write_config(tmp_path, ct_names={"enabled": True, "names_file": str(names)}))
    ft = tools(a={"good.test": [IP_OK], "edge.shop.example": ["1.1.1.2"], "api.good.test": [], "mail.good.test": [IP_OK]},
               nxdomain={"www.good.test"})
    run_dir = _go(cfg, ft)
    by = {r["hostname"]: r for r in outputs.iter_hostname_rows(run_dir) if r["target_ip"] == IP_OK and r["port"] == 443}
    assert by["api.good.test"]["hostname_sources"] == ["ct"] and by["api.good.test"]["final_hostname_status"] == "ct_only_evidence"
    assert by["mail.good.test"]["hostname_sources"] == ["ct"] and by["mail.good.test"]["final_hostname_status"] == "verified"
    assert by["good.test"]["hostname_sources"] == ["certificate_cn", "certificate_san", "ptr"]
    assert "unrelated.example" not in by
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    ct = manifest["ct_names"]
    assert ct["enabled"] is True and ct["names_file"] == "ct-names.txt"
    assert ct["names_loaded"] == 3 and ct["domains_indexed"] == 2 and len(ct["sha256"]) == 64
    assert str(tmp_path) not in json.dumps(ct)
    assert any("Certificate Transparency" in x for x in manifest["limitations"])


def test_disabled_run_does_not_import_ct_and_matches_a_run_without_the_section(tmp_path, monkeypatch):
    for name in _ct_modules():
        monkeypatch.delitem(sys.modules, name)
    plain, off = tmp_path / "plain", tmp_path / "off"
    plain.mkdir()
    off.mkdir()
    run_a = _go(load_config(write_config(plain)), tools())
    run_b = _go(load_config(write_config(off, ct_names={"enabled": False})), tools())
    assert not _ct_modules()

    def strip(rows):
        return [{k: v for k, v in r.items() if not k.endswith("_at") and k != "run_id"} for r in rows]

    assert strip(outputs.iter_hostname_rows(run_a)) == strip(outputs.iter_hostname_rows(run_b))
    manifest = json.loads((run_b / "manifest.json").read_text(encoding="utf-8"))
    assert "ct_names" not in manifest and "ct_names" not in manifest["stage_counts"]
    assert not any("Certificate Transparency" in x for x in manifest["limitations"])


def test_importing_the_pipeline_does_not_import_ct():
    code = ("import sys, scanner.internet.pipeline, scanner.internet.candidates; "
            "assert not any(m.startswith('scanner.ct') for m in sys.modules)")
    subprocess.run([sys.executable, "-c", code], check=True, cwd=Path(__file__).resolve().parent.parent)


# ------------------------------------------------------------------------------------------ config

def test_config_enabled_requires_names_file(tmp_path):
    with pytest.raises(ConfigError, match="names_file is required"):
        load_config(write_config(tmp_path, ct_names={"enabled": True}))


def test_config_missing_names_file_refused(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(write_config(tmp_path, ct_names={"enabled": True, "names_file": str(tmp_path / "absent.txt")}))


def test_config_unknown_key_and_bad_values_refused(tmp_path):
    with pytest.raises(ConfigError, match="unknown keys in 'ct_names'"):
        load_config(write_config(tmp_path, ct_names={"enabled": False, "oops": 1}))
    with pytest.raises(ConfigError, match="ct_names.enabled"):
        load_config(write_config(tmp_path, ct_names={"enabled": "yes"}))
    f = _names_file(tmp_path, ["a.example.com"])
    with pytest.raises(ConfigError, match="max_names_per_domain"):
        load_config(write_config(tmp_path, ct_names={"enabled": True, "names_file": str(f), "max_names_per_domain": 0}))


def test_config_defaults_and_checksum_unchanged_when_absent(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    cfg = load_config(write_config(tmp_path))
    assert cfg.ct_names.enabled is False and cfg.ct_names.names_file is None and cfg.ct_names.max_names_per_domain == 50
    f = _names_file(other, ["a.example.com"])
    on = load_config(write_config(other, ct_names={"enabled": True, "names_file": str(f)}))
    assert on.ct_names.enabled and on.ct_names.names_file == f


def test_names_file_location_does_not_change_the_checksum(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir(), second.mkdir()
    one = _names_file(first, ["www.example.org"])
    other = _names_file(second, ["www.example.org", "mail.example.org"])
    cfg_a = load_config(write_config(first, ct_names={"enabled": True, "names_file": str(one)}))
    cfg_b = load_config(write_config(first, ct_names={"enabled": True, "names_file": str(other)}))
    assert cfg_a.checksum == cfg_b.checksum
    assert shared_config_checksum(cfg_a.raw) == shared_config_checksum(cfg_b.raw)
    capped = load_config(write_config(first, ct_names={"enabled": True, "names_file": str(one), "max_names_per_domain": 5}))
    assert capped.checksum != cfg_a.checksum
    assert config_checksum(cfg_a.raw) == cfg_a.checksum
