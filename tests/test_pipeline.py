"""End-to-end run with scripted fake zmap/zgrab2/zdns (no network, no subprocesses)."""
import json
from pathlib import Path

import pytest

from scanner.internet import pipeline, preflight
from scanner.internet.config import load_config
from tests.helpers import FakeFetcher, FakeTools, write_config

# good.test cert: SAN good.test, www.good.test, *.wild.test ; CN good.test (real zgrab2 capture)
IP_OK, IP_STRICT, IP_HTTP, IP_ELSE, IP_DEAD = "1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5"


def tools(**over):
    base = dict(
        l4={443: [IP_OK, IP_STRICT, IP_ELSE], 80: [IP_HTTP], 8080: [IP_DEAD]},
        tls={(IP_OK, 443): "ok", (IP_STRICT, 443): "strict", (IP_ELSE, 443): "ok", (IP_HTTP, 80): "plain", (IP_DEAD, 8080): "reset"},
        tls_sni={(IP_OK, "good.test"): "ok", (IP_STRICT, "edge.shop.example"): "ok"},
        http={(IP_HTTP, 80): 200},
        ptr={IP_OK: ["good.test."], IP_STRICT: ["edge.shop.example."]},
        a={"good.test": [IP_OK], "edge.shop.example": [IP_STRICT], "www.good.test": []},
        nxdomain={"www.good.test"},
    )
    base.update(over)
    return FakeTools(**base)


@pytest.fixture
def cfg(tmp_path):
    return load_config(write_config(tmp_path))


def go(cfg, ft, **kw):
    return pipeline.run(cfg, run_id="t1", executor=ft, fetcher=kw.pop("fetcher", FakeFetcher()), skip_preflight=True, offline_preflight=True, **kw)


def rows_of(run_dir: Path):
    return [json.loads(l) for l in (run_dir / "normalized" / "hostname_resolution.jsonl").read_text().splitlines()]


def row(rows, ip, host=None, port=None):
    hits = [r for r in rows if r["target_ip"] == ip and r["hostname"] == host and (port is None or r["port"] == port)]
    assert len(hits) == 1, (ip, host, hits)
    return hits[0]


def test_full_run_outputs_and_statuses(cfg):
    ft = tools()
    run_dir = go(cfg, ft)
    rows = rows_of(run_dir)

    ok = row(rows, IP_OK, "good.test")
    assert ok["protocol"] == "https" and ok["tls_status"] == "success"
    assert ok["hostname_sources"] == ["certificate_cn", "certificate_san", "ptr"]      # merged provenance
    assert ok["final_hostname_status"] == "verified" and ok["maps_to_scanned_ip"] is True
    assert ok["sni_confirmation_attempted"] and ok["sni_confirmation_result"] == "confirmed"
    assert ok["certificate_sha256"] and ok["certificate_wildcards"] == ["*.wild.test"]
    assert ok["hostname_favicon_outcome"] == "image" and ok["direct_favicon_outcome"] == "image"
    assert ok["hostname_favicon_is_image"] and ok["direct_favicon_is_image"]

    # strict-SNI edge: direct handshake fails, PTR candidate verifies, SNI confirmation succeeds
    strict = row(rows, IP_STRICT, "edge.shop.example")
    assert strict["tls_status"] == "failed" and strict["tls_outcome"] == "tls_alert_unrecognized_name"
    assert strict["certificate_present"] is False and strict["hostname_sources"] == ["ptr"]
    assert strict["final_hostname_status"] == "verified"
    # SNI gets a handshake where the bare IP did not; the fixture's cert (good.test) does not cover this name
    assert strict["sni_confirmation_outcome"] == "tls_success" and strict["sni_confirmation_result"] == "tls_ok_cert_mismatch"

    # plain HTTP path: TLS attempted first, not_tls, then HTTP; no PTR -> no hostname evidence
    http = row(rows, IP_HTTP, None)
    assert http["protocol"] == "http" and http["tls_status"] == "not_tls" and http["http_status"] == 200
    assert http["final_hostname_status"] == "no_hostname_evidence"

    # same cert on another IP: name resolves elsewhere / NXDOMAIN
    assert row(rows, IP_ELSE, "good.test")["final_hostname_status"] == "resolved_elsewhere"
    assert row(rows, IP_ELSE, "www.good.test")["final_hostname_status"] == "nxdomain"

    # reset on TLS and nothing on HTTP -> TCP only, still has a row
    dead = row(rows, IP_DEAD, None)
    assert dead["protocol"] == "tcp_only" and dead["tls_outcome"] == "tls_reset"


def test_wildcard_never_queried_and_dns_is_batched(cfg):
    ft = tools()
    go(cfg, ft)
    queried = set(ft.zdns_inputs["A"]) | set(ft.zdns_inputs["AAAA"])
    assert not any("wild" in n or "*" in n for n in queried)
    zdns_calls = [c for c in ft.commands if c[0] == "zdns"]
    assert sorted(c[1] for c in zdns_calls) == ["A", "AAAA", "PTR"]                     # one process per module, not per name
    tls_calls = [c for c in ft.commands if c[0] == "zgrab2" and c[1] == "tls"]
    assert len(tls_calls) <= 4                                                          # grouped by port / mode, never per endpoint


def test_tls_first_then_http_only_for_non_tls(cfg):
    ft = tools()
    go(cfg, ft)
    order = [(c[0], c[1]) for c in ft.commands if c[0] == "zgrab2"]
    assert order.index(("zgrab2", "tls")) < order.index(("zgrab2", "http"))
    # IP_OK completed TLS, so it must never be sent a plain HTTP probe
    http_calls = [c for c in ft.commands if c[:2] == ["zgrab2", "http"]]
    assert http_calls and all("--use-https" not in c for c in http_calls)


def test_sni_confirmation_only_for_verified_names_and_tls_capable_ports(cfg):
    ft = tools()
    go(cfg, ft)
    sni_calls = [c for c in ft.commands if c[:2] == ["zgrab2", "tls"]]
    assert len(sni_calls) >= 1
    # the plain-HTTP endpoint (not_tls) and the unverified/elsewhere names are never SNI-probed
    rows = rows_of(Path(cfg.output_dir) / "t1")
    assert all(not r["sni_confirmation_attempted"] for r in rows if r["target_ip"] == IP_HTTP)
    assert all(not r["sni_confirmation_attempted"] for r in rows if r["final_hostname_status"] in ("nxdomain", "resolved_elsewhere"))


def test_favicon_fetches_only_scanned_ips_and_respects_disable(cfg, tmp_path):
    f = FakeFetcher()
    go(cfg, tools(), fetcher=f)
    assert f.calls and all(ip in {IP_OK, IP_STRICT, IP_HTTP, IP_ELSE} for _u, ip, _k in f.calls)
    assert all(ip != IP_DEAD for _u, ip, _k in f.calls)                                 # tcp_only endpoints are not fetched


def test_favicon_disabled_makes_no_fetches(tmp_path):
    import yaml
    p = write_config(tmp_path)
    d = yaml.safe_load(p.read_text())
    d["favicon"]["enabled"] = False
    p.write_text(yaml.safe_dump(d))
    f = FakeFetcher()
    go(load_config(p), tools(), fetcher=f)
    assert f.calls == []


def test_manifest_summary_and_checksums(cfg):
    run_dir = go(cfg, tools())
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["experiment"] == "scanner" and m["approval_reference"] == "TEST-REF-1"
    assert m["sample"]["targets_per_port"] > 300_000 and m["elapsed_seconds"] >= 0
    assert m["stage_counts"]["l4_endpoints"] == 5 and not m["stage_errors"]
    assert "normalized/hostname_resolution.jsonl" in m["output_checksums"]
    assert any(k.startswith("raw/zmap/") for k in m["output_checksums"])
    s = json.loads((run_dir / "report" / "summary.json").read_text())
    assert s["ips_with_verified_hostname"] == 2 and s["tls_failed_but_sni_handshake_ok"] == 1
    assert (run_dir / "normalized" / "hostname_resolution.csv").read_text().startswith("target_ip,port,")


def test_deterministic_outputs_for_same_inputs(cfg):
    a = go(cfg, tools())
    b = pipeline.run(cfg, run_id="t2", executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)
    for name in ("hostname_resolution.jsonl", "endpoints.jsonl"):
        ra = [{k: v for k, v in json.loads(l).items()} for l in (a / "normalized" / name).read_text().splitlines()]
        rb = [{k: v for k, v in json.loads(l).items()} for l in (b / "normalized" / name).read_text().splitlines()]
        assert ra == rb


# ------------------------------------------------------------------ failure isolation

def test_zmap_failure_on_one_port_does_not_stop_the_rest(cfg):
    ft = tools()
    orig = ft._zmap

    def flaky(c):
        if c[c.index("-p") + 1] == "80":
            raise OSError("zmap exploded")
        return orig(c)
    ft._zmap = flaky
    run_dir = go(cfg, ft)
    m = json.loads((run_dir / "manifest.json").read_text())
    assert "zmap:80" in m["stage_errors"] and m["stage_counts"]["l4_endpoints"] == 4
    assert any(r["final_hostname_status"] == "verified" for r in rows_of(run_dir))


def test_zero_results_warns_and_still_writes_everything(cfg):
    run_dir = go(cfg, tools(l4={}))
    s = json.loads((run_dir / "report" / "summary.json").read_text())
    assert any("ZERO responsive" in w for w in s["warnings"])
    assert (run_dir / "manifest.json").exists() and rows_of(run_dir) == []


def test_dns_stage_crash_is_isolated(cfg):
    ft = tools()
    orig = ft._zdns

    def broken(c, stdin):
        if c[1] == "A":
            raise RuntimeError("resolver crashed")
        return orig(c, stdin)
    ft._zdns = broken
    run_dir = go(cfg, ft)
    rows = rows_of(run_dir)
    assert rows and all(r["final_hostname_status"] in ("ptr_only_evidence", "tls_only_evidence", "unresolved", "no_hostname_evidence") for r in rows)


def test_kill_switch_stops_before_next_stage_and_is_recorded(cfg):
    ft = tools()
    orig = ft._zmap

    def zmap_then_kill(c):
        out = orig(c)
        Path(cfg.kill_switch_file).write_text("stop")
        return out
    ft._zmap = zmap_then_kill
    run_dir = go(cfg, ft)
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["abort_reason"] == "kill_switch" and "tls_direct" in m["stages_skipped"] and not m["complete"]
    assert not [c for c in ft.commands if c[:2] == ["zgrab2", "tls"]]


# ------------------------------------------------------------------ preflight

def test_preflight_blocks_when_kill_switch_present_or_tools_missing(cfg, tmp_path):
    ft = tools()
    policy, splan, _ = pipeline.build_policy(cfg)
    Path(cfg.kill_switch_file).write_text("x")
    rep = preflight.run_preflight(cfg, splan, run_dir=tmp_path, executor=ft, offline=True)
    assert not rep["ok"]
    assert {c["name"] for c in rep["checks"] if c["status"] == "fail"} >= {"kill_switch_clear"}


def test_preflight_runtime_must_cover_the_sample(tmp_path):
    import yaml
    p = write_config(tmp_path)
    d = yaml.safe_load(p.read_text())
    d["measurement"]["zmap_max_runtime"] = 60
    p.write_text(yaml.safe_dump(d))
    cfg = load_config(p)
    _policy, splan, _ = pipeline.build_policy(cfg)
    rep = preflight.run_preflight(cfg, splan, run_dir=tmp_path, executor=tools(), offline=True)
    assert "zmap_runtime_covers_sample" in {c["name"] for c in rep["checks"] if c["status"] == "fail"}


def test_run_refuses_failed_preflight(cfg):
    with pytest.raises(preflight.PreflightFailed):
        pipeline.run(cfg, run_id="pf", executor=tools(), fetcher=FakeFetcher(), offline_preflight=True)


def test_confirm_token_binds_run_to_reviewed_plan(cfg, tmp_path):
    _p, splan, _ = pipeline.build_policy(cfg)
    t1 = pipeline.confirm_token(cfg, splan)
    import yaml
    p = write_config(tmp_path / "x") if (tmp_path / "x").mkdir() is None else None
    d = yaml.safe_load(p.read_text())
    d["sample"]["fraction"] = 0.00005
    p.write_text(yaml.safe_dump(d))
    cfg2 = load_config(p)
    _p2, splan2, _ = pipeline.build_policy(cfg2)
    assert pipeline.confirm_token(cfg2, splan2) != t1


def test_cli_refuses_without_token_and_plan_sends_nothing(cfg, tmp_path, capsys):
    from scanner.internet.__main__ import main
    cfgfile = Path(cfg.output_dir).parent / "scanner.yaml"
    assert main(["run", "--config", str(cfgfile)]) == 2
    assert main(["run", "--config", str(cfgfile), "--confirm", "wrong"]) == 2
    assert main(["plan", "--config", str(cfgfile)]) == 0
    out = capsys.readouterr().out
    assert "confirm_token" in out and "Nothing was sent" in out
    assert not (Path(cfg.output_dir)).exists() or not list(Path(cfg.output_dir).glob("scanner-*"))


def test_preflight_refuses_when_egress_ip_is_not_the_approved_source(cfg, tmp_path, monkeypatch):
    _plan, splan, _ = pipeline.build_policy(cfg)
    def egress(seen):
        monkeypatch.setattr(preflight, "_public_ip", lambda *a, **k: seen)
        rep = preflight.run_preflight(cfg, splan, run_dir=tmp_path, executor=tools(), offline=False)
        return next(c for c in rep["checks"] if c["name"] == "egress_matches_approved_source")
    assert egress(cfg.vantage.public_egress_ip)["status"] == "pass"
    assert egress("198.51.100.99")["status"] == "fail"            # the address moved
    assert egress(None)["status"] == "fail"                       # unknown is not good enough


def test_tarpit_address_gets_only_the_syn_and_is_flagged(cfg):
    ft = tools()
    ft.windows[(IP_OK, 443)] = 0
    run_dir = go(cfg, ft)
    assert ft.zgrab_ips and IP_OK not in ft.zgrab_ips and IP_HTTP in ft.zgrab_ips
    rows = [json.loads(l) for l in (run_dir / "normalized" / "endpoints.jsonl").read_text().splitlines()]
    tar = next(r for r in rows if r["target_ip"] == IP_OK)
    assert tar["tarpit_suspect"] and tar["tls_status"] == "not_attempted" and tar["protocol"] == "not_attempted"
    assert next(r for r in rows if r["target_ip"] == IP_HTTP)["tls_status"] != "not_attempted"
    assert json.loads((run_dir / "report" / "summary.json").read_text())["counts"]["tarpit_ips_not_probed"] == 1
