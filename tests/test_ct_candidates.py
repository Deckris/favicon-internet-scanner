"""Optional Certificate Transparency name source: linkage, caps, statuses, manifest and the off-by-default guarantee."""
import hashlib
import json
import socket
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


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


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
    idx = _index(tmp_path, ["api.example.com", "cdn.example.com", "other.example.net"])
    ep = cand.build_endpoint_names(["host.example.com."], None, POLICY, max_candidates=20, ct_names=idx)
    assert ep.names["api.example.com"] == {"ct"} and ep.names["cdn.example.com"] == {"ct"}
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
    assert len(ep.names) == 4 and ep.truncated and ep.source_count == 12 and ep.ct_names_skipped == 8
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


def test_ct_hit_does_not_outrank_genuine_corroboration():
    ptr_ct, ptr_san = {"ptr", "ct"}, {"ptr", "certificate_san"}
    assert cand.name_rank("b.example.com", ptr_san) < cand.name_rank("a.example.com", ptr_ct)
    assert cand.name_rank("a.example.com", ptr_ct) == cand.name_rank("a.example.com", {"ptr"})
    assert cand.name_rank("a.example.com", {"ct"}) > cand.name_rank("z.example.com", {"certificate_cn"})
    ranked = sorted({"a.example.com": ptr_ct, "b.example.com": ptr_san}.items(), key=lambda kv: cand.name_rank(*kv))
    assert [n for n, _ in ranked] == ["b.example.com", "a.example.com"]


def test_ct_only_evidence_status():
    f = cand.final_status
    assert f("no_answer", {"ct"}) == "ct_only_evidence"
    assert f("no_answer", {"ct", "ptr"}) == "ptr_only_evidence"            # a CT hit is not corroboration
    assert f("no_answer", {"ct", "certificate_san"}) == "tls_only_evidence"
    assert f("no_answer", {"ptr", "certificate_san"}) == "multi_source_evidence"
    assert f("no_answer", {"ptr", "certificate_san", "ct"}) == "multi_source_evidence"
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
    ft = tools(a={"good.test": [IP_OK], "edge.cdn.example": ["1.1.1.2"], "api.good.test": [], "mail.good.test": [IP_OK]},
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
        return [{k: v for k, v in r.items() if not k.endswith("_at") and k != "run_id" and "seconds" not in k and "_ms" not in k} for r in rows]

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


# ------------------------------------------------------------------------------------------ caps and linkage

class CountingPolicy:
    def __init__(self):
        self.checked = []

    def check_hostname(self, name, **_):
        self.checked.append(name)
        return None


def test_domain_cap_per_endpoint_counts_skipped_names(tmp_path):
    idx = _index(tmp_path, [f"n{i}.d{d}.example" for d in range(5) for i in range(3)])
    policy = CountingPolicy()
    sans = [f"host.d{d}.example" for d in range(5)]
    ep = cand.build_endpoint_names([], _cert(sans), policy, max_candidates=100, ct_names=idx, max_domains_per_endpoint=2)
    ct = sorted(n for n, s in ep.names.items() if s == {"ct"})
    assert ct == sorted(f"n{i}.d{d}.example" for d in range(2) for i in range(3))
    assert ep.ct_names_skipped == 9 and ep.truncated
    assert not any(n.startswith("n") and ".d2." in n for n in policy.checked)


def test_endpoint_full_stops_before_the_policy_sees_more_ct_names(tmp_path):
    idx = _index(tmp_path, [f"n{i:02d}.example.com" for i in range(40)] + [f"n{i:02d}.example.net" for i in range(40)])
    policy = CountingPolicy()
    ep = cand.build_endpoint_names(["h.example.com", "h.example.net"], None, policy, max_candidates=5, ct_names=idx)
    ct_checked = [n for n in policy.checked if n.startswith("n")]
    assert len(ct_checked) == 3 and len(ep.names) == 5
    assert ct_checked == [f"n{i:02d}.example.com" for i in range(3)]       # sorted domain, sorted names
    assert ep.ct_names_skipped == 77 and ep.source_count == 82


def test_full_endpoint_takes_no_ct_name_and_keeps_provenance_merges(tmp_path):
    idx = _index(tmp_path, ["a.example.com", "b.example.com"])
    policy = CountingPolicy()
    ep = cand.build_endpoint_names(["a.example.com", "x.example.com"], None, policy, max_candidates=2, ct_names=idx)
    assert ep.names == {"a.example.com": {"ptr", "ct"}, "x.example.com": {"ptr"}}
    assert ep.ct_names_skipped == 1 and "b.example.com" not in policy.checked


def test_refusals_are_bounded_by_the_free_room(tmp_path):
    idx = _index(tmp_path, [f"n{i:02d}.example.com" for i in range(60)])
    policy = TargetPolicy.for_tests(["1.1.1.0/24"])
    cand.build_endpoint_names(["h.example.com"], None, policy, max_candidates=4, ct_names=idx)
    assert len(policy.refusals) <= 3


def test_public_suffix_names_link_nothing(tmp_path):
    from scanner.ct import names as ctnames
    idx = cand.CtIndex({"co.uk": ["other.example.co.uk"], "example.com": ["api.example.com"]},
                       ctnames.registrable_domain, ctnames.wildcard_base)
    ep = cand.build_endpoint_names(["co.uk"], _cert(["*.co.uk"]), POLICY, max_candidates=20, ct_names=idx)
    assert set(ep.names) == {"co.uk"} and ep.ct_names_skipped == 0
    assert _index(tmp_path, ["co.uk", "a.example.com"]).names_without_domain == 1


def test_load_refuses_empty_list_and_list_without_domains(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing\n\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="no usable name"):
        cand.load_ct_index(empty, max_per_domain=5)
    suffixes = _names_file(tmp_path, ["co.uk", "not a name"])
    with pytest.raises(ConfigError, match="no usable name"):
        cand.load_ct_index(suffixes, max_per_domain=5)


def test_load_ignores_a_utf8_byte_order_mark(tmp_path):
    plain = tmp_path / "bom.txt"
    plain.write_bytes(b"\xef\xbb\xbfapi.example.com\nmail.example.com\n")
    assert cand.load_ct_index(plain, max_per_domain=5).by_domain == {"example.com": ["api.example.com", "mail.example.com"]}
    rows = tmp_path / "bom.jsonl"
    rows.write_bytes(b'\xef\xbb\xbf{"name": "api.example.com"}\n')
    assert cand.load_ct_index(rows, max_per_domain=5).by_domain == {"example.com": ["api.example.com"]}


@pytest.mark.parametrize("content", [b"# nothing\n", b"co.uk\nnot a name\n"])
def test_run_refuses_a_bad_list_before_any_tool_job(tmp_path, content):
    names = tmp_path / "bad.txt"
    names.write_bytes(content)
    cfg = load_config(write_config(tmp_path, ct_names={"enabled": True, "names_file": str(names)}))
    ft = tools()
    with pytest.raises(ConfigError, match="nothing was sent"):
        _go(cfg, ft)
    assert ft.commands == [] and not (Path(cfg.output_dir) / "t1").exists()


def test_run_refuses_a_list_that_does_not_match_its_pin_or_vanished(tmp_path):
    names = _names_file(tmp_path, ["api.good.test"])
    cfg = load_config(write_config(tmp_path, ct_names={"enabled": True, "names_file": str(names), "names_sha256": "0" * 64}))
    ft = tools()
    with pytest.raises(ConfigError, match="nothing was sent"):
        _go(cfg, ft)
    names.unlink()
    with pytest.raises(ConfigError, match="cannot be read"):
        _go(cfg, ft)
    assert ft.commands == []


def test_load_hashes_the_parsed_bytes_and_checks_a_pinned_digest(tmp_path):
    f = _names_file(tmp_path, ["a.example.com", "a.example.com", "b.example.com"])
    idx = cand.load_ct_index(f, max_per_domain=5)
    assert idx.sha256 == hashlib.sha256(f.read_bytes()).hexdigest() and idx.size_bytes == f.stat().st_size
    assert idx.by_domain["example.com"] == ["a.example.com", "b.example.com"]
    assert idx.names_loaded == 3 and idx.names_duplicate == 1 and idx.names_dropped_by_cap == 0
    assert cand.load_ct_index(f, max_per_domain=5, expected_sha256=idx.sha256.upper()).sha256 == idx.sha256
    with pytest.raises(ConfigError, match="names_sha256"):
        cand.load_ct_index(f, max_per_domain=5, expected_sha256="0" * 64)


# ------------------------------------------------------------------------------------------ pipeline: pinning, caps, off state

def test_pipeline_refuses_a_file_that_differs_from_the_pinned_digest(tmp_path):
    f = _names_file(tmp_path, ["api.good.test"])
    cfg = load_config(write_config(tmp_path, ct_names={"enabled": True, "names_file": str(f), "names_sha256": "1" * 64}))
    with pytest.raises(ConfigError, match="names_sha256"):
        _go(cfg, tools())


def test_pipeline_accepts_the_pinned_digest_and_counts_endpoint_caps(tmp_path):
    f = _names_file(tmp_path, [f"n{i}.good.test" for i in range(30)])
    digest = hashlib.sha256(f.read_bytes()).hexdigest()
    cfg = load_config(write_config(tmp_path, hostnames={"max_candidates_per_ip": 5},
                                   ct_names={"enabled": True, "names_file": str(f), "names_sha256": digest}))
    run_dir = _go(cfg, tools())
    ct = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))["ct_names"]
    assert ct["sha256"] == digest and ct["names_sha256_pinned"] is True
    assert ct["names_skipped_endpoint_cap"] > 0 and ct["max_domains_per_endpoint"] == 8


def test_ct_limitation_text_replaces_the_base_line_only_when_enabled():
    base = pipeline.limitations(False)
    assert base is pipeline.LIMITATIONS
    on = pipeline.limitations(True)
    assert len(on) == len(base) + 1 and on[-1] == pipeline.CT_LIMITATION
    assert pipeline.CT_HOSTNAME_LIMITATION in on
    assert not any(x.startswith("Hostname evidence is PTR plus certificate SAN/CN only") for x in on)
    assert sum(x.startswith("Hostname evidence") for x in on) == 1


def _run_files(run_dir):
    """Every data file of a run as parsed rows (timestamps and run ids dropped), keyed by relative path."""
    out = {}
    for p in sorted(Path(run_dir).rglob("*")):
        if p.is_file() and p.name.startswith("ip_results.csv"):
            out[str(p.relative_to(run_dir))] = outputs.read_text(p)
            continue
        if not p.is_file() or p.name == "manifest.json" or ".jsonl" not in p.name or p.name.startswith("tool_jobs"):
            continue
        rows = [json.loads(line) for line in outputs.read_text(p).splitlines() if line.strip()]
        rows = [{k: v for k, v in r.items() if not k.endswith("_at") and k != "run_id" and "seconds" not in k and "_ms" not in k} for r in rows]
        out[str(p.relative_to(run_dir))] = sorted(rows, key=json.dumps) if p.name == "favicon_records.jsonl" else rows    # written by concurrent workers
    return out


def test_disabled_section_leaves_every_output_and_the_checksum_as_without_it(tmp_path):
    plain, off = tmp_path / "plain", tmp_path / "off"
    plain.mkdir(), off.mkdir()
    cfg_a, cfg_b = load_config(write_config(plain)), load_config(write_config(off, ct_names={"enabled": False}))
    same = tmp_path / "same"
    same.mkdir()
    baseline = load_config(write_config(same)).checksum
    assert load_config(write_config(same, ct_names={"enabled": False})).checksum == baseline
    assert load_config(write_config(same, ct_names={"enabled": False, "names_file": "x.txt", "max_names_per_domain": 7})).checksum == baseline
    assert shared_config_checksum(cfg_a.raw) == shared_config_checksum(cfg_b.raw)
    run_a, run_b = _go(cfg_a, tools()), _go(cfg_b, tools())
    files_a, files_b = _run_files(run_a), _run_files(run_b)
    assert files_a.keys() == files_b.keys()
    for needle in ("ip_results.csv", "endpoints.jsonl", "hostname_resolution.jsonl", "http_documents.jsonl"):
        assert any(needle in k for k in files_a), needle
    for key in files_a:
        assert files_a[key] == files_b[key], key
    ma = json.loads((run_a / "manifest.json").read_text(encoding="utf-8"))
    mb = json.loads((run_b / "manifest.json").read_text(encoding="utf-8"))
    assert ma["stage_counts"] == mb["stage_counts"] and ma["limitations"] == mb["limitations"]
    assert ma["limitations"] == list(pipeline.LIMITATIONS)


def test_enabled_section_changes_the_checksum(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    f = _names_file(tmp_path, ["a.example.com"])
    on = load_config(write_config(tmp_path, ct_names={"enabled": True, "names_file": str(f)}))
    assert on.checksum != load_config(write_config(other)).checksum


def test_config_bounds_digest_and_empty_file(tmp_path):
    f = _names_file(tmp_path, ["a.example.com"])
    for key, bad in (("max_names_per_domain", 1001), ("max_domains_per_endpoint", 65), ("max_domains_per_endpoint", 0)):
        with pytest.raises(ConfigError, match=key):
            load_config(write_config(tmp_path, ct_names={"enabled": True, "names_file": str(f), key: bad}))
    cfg = load_config(write_config(tmp_path, ct_names={"enabled": True, "names_file": str(f), "max_names_per_domain": 1000,
                                                        "max_domains_per_endpoint": 64}))
    assert (cfg.ct_names.max_names_per_domain, cfg.ct_names.max_domains_per_endpoint) == (1000, 64)
    dflt = load_config(write_config(tmp_path, ct_names={"enabled": True, "names_file": str(f)})).ct_names
    assert (dflt.max_names_per_domain, dflt.max_domains_per_endpoint, dflt.names_sha256) == (50, 8, None)
    with pytest.raises(ConfigError, match="64-digit"):
        load_config(write_config(tmp_path, ct_names={"enabled": True, "names_file": str(f), "names_sha256": "abc"}))
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    with pytest.raises(ConfigError, match="empty"):
        load_config(write_config(tmp_path, ct_names={"enabled": True, "names_file": str(empty)}))


def test_relative_names_file_resolves_against_the_config_folder(tmp_path):
    f = _names_file(tmp_path, ["a.example.com"])
    cfg = load_config(write_config(tmp_path, ct_names={"enabled": True, "names_file": f.name}))
    assert cfg.ct_names.names_file == tmp_path / f.name
