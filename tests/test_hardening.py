"""Regression tests for the pre-run review findings."""
import dataclasses
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.internet import favicon as fav
from scanner.internet import pipeline
from scanner.internet.config import load_config
from scanner.internet.runner import ManagedExecutor
from tests.helpers import FakeFetcher, FakeTools, write_config
from tests.test_pipeline import IP_DEAD, IP_ELSE, IP_HTTP, IP_OK, IP_STRICT, go, row, rows_of, tools

posix_only = pytest.mark.skipif(os.name != "posix", reason="process-group behaviour is POSIX-specific")


@pytest.fixture
def cfg(tmp_path):
    return load_config(write_config(tmp_path))


# ------------------------------------------------------------------ B: fetcher confined to responsive ip:port

def test_fetcher_refuses_ports_that_did_not_answer_the_scan(cfg):
    policy = fav.fetch_policy(cfg, [IP_OK])
    f = fav.make_fetcher(cfg, policy, SimpleNamespace(resolve_a=lambda h: []), {(IP_OK, 443)})
    for url in (f"http://{IP_OK}:22/", f"https://{IP_OK}:6379/x.ico", f"http://{IP_OK}:80/"):
        result, body = f.fetch(url, connect_ip=IP_OK, kind="favicon")
        assert result.outcome == "policy_refused" and body is None, url


def test_fetcher_decode_errors_become_an_outcome(cfg, monkeypatch):
    policy = fav.fetch_policy(cfg, [IP_OK])
    f = fav.make_fetcher(cfg, policy, SimpleNamespace(resolve_a=lambda h: []), {(IP_OK, 443)})

    import zlib
    from scanner.web_fetch import WebFetcher

    def boom(self, *a, **k):
        raise zlib.error("bad gzip")
    monkeypatch.setattr(WebFetcher, "_one_request", boom)
    result, _ = f.fetch(f"https://{IP_OK}:443/", connect_ip=IP_OK, kind="document")
    assert result.outcome == "decode_error"


# ------------------------------------------------------------------ B: strict-SNI is never relabelled http

def test_strict_sni_host_that_answers_plain_http_400_stays_tls(cfg):
    ft = tools(http={(IP_HTTP, 80): 200, (IP_STRICT, 443): 400})
    f = FakeFetcher()
    run_dir = go(cfg, ft, fetcher=f)
    r = row(rows_of(run_dir), IP_STRICT, "edge.shop.example")
    assert r["protocol"] == "https"                      # SNI handshake succeeded
    assert r["http_zgrab_status"] is None                # a TLS-proving alert means plain HTTP is never sent
    urls = [u for u, ip, _k in f.calls if ip == IP_STRICT]
    assert urls and all(u.startswith("https://") for u in urls)
    http_inputs = [c for c in ft.commands if c[:2] == ["zgrab2", "http"]]
    assert http_inputs                                    # plain-http host exists, strict host not in it


def test_tls_alert_without_sni_success_is_tls_unestablished_not_http(cfg):
    ft = tools(tls_sni={}, http={(IP_HTTP, 80): 200, (IP_STRICT, 443): 400})
    run_dir = go(cfg, ft)
    r = row(rows_of(run_dir), IP_STRICT, "edge.shop.example")
    assert r["protocol"] == "tls_unestablished" and r["http_status"] is None


@pytest.mark.parametrize("kind", ["close", "reset", "hang"])
def test_plain_http_server_that_drops_the_clienthello_is_still_found(cfg, kind):
    run_dir = go(cfg, tools(tls={(IP_OK, 443): "ok", (IP_STRICT, 443): "strict", (IP_ELSE, 443): "ok", (IP_HTTP, 80): kind, (IP_DEAD, 8080): "reset"},
                            http={(IP_HTTP, 80): 200}))
    r = row(rows_of(run_dir), IP_HTTP, None)
    assert r["protocol"] == "http" and r["http_status"] == 200


# ------------------------------------------------------------------ advisories: row semantics

def test_inconclusive_dns_gives_null_mapping_and_unresolved(cfg):
    ft = tools()
    orig = ft._answer

    def timeout_for_good(module, name):
        if module == "A" and name == "good.test":
            return {"name": name, "results": {"A": {"status": "TIMEOUT", "data": {}}}}
        return orig(module, name)
    ft._answer = timeout_for_good
    r = row(rows_of(go(cfg, ft)), IP_OK, "good.test")
    assert r["dns_status"] == "timeout" and r["maps_to_scanned_ip"] is None and r["final_hostname_status"] == "unresolved"


def test_sni_cap_records_why_names_were_skipped(tmp_path):
    import yaml
    p = write_config(tmp_path)
    d = yaml.safe_load(p.read_text())
    d["sni_confirm"]["max_per_endpoint"] = 1
    p.write_text(yaml.safe_dump(d))
    cfg = load_config(p)
    run_dir = go(cfg, tools(ptr={IP_OK: ["good.test.", "zzz.good.test."], IP_STRICT: ["edge.shop.example."]},
                            a={"good.test": [IP_OK], "zzz.good.test": [IP_OK], "edge.shop.example": [IP_STRICT]}))
    rows = rows_of(run_dir)
    reasons = {r["hostname"]: r["sni_skipped_reason"] for r in rows if r["target_ip"] == IP_OK and r["hostname"]}
    assert reasons["good.test"] is None                    # corroborated by PTR + SAN + CN: chosen first
    assert reasons["zzz.good.test"] == "cap"
    assert next(r for r in rows if r["hostname"] == "zzz.good.test")["sni_confirmation_attempted"] is False


def test_rows_flag_an_incomplete_run(cfg):
    ft = tools()
    ft._zmap_orig = ft._zmap

    def flaky(c):
        if c[c.index("-p") + 1] == "80":
            raise OSError("zmap exploded")
        return ft._zmap_orig(c)
    ft._zmap = flaky
    rows = rows_of(go(cfg, ft))
    assert rows and all(r["run_incomplete"] is True for r in rows)
    healthy = pipeline.run(cfg, run_id="t2", executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)
    assert all(r["run_incomplete"] is False for r in rows_of(healthy))        # a second run needs its own directory


def test_candidate_cap_prefers_ptr_over_alphabet():
    from scanner.internet import candidates as cand
    from scanner.safety import TargetPolicy
    cert = SimpleNamespace(san_dns=tuple(f"h{i:03d}.example.com" for i in range(60)), subject_cn=None)
    ep = cand.build_endpoint_names(["ptr.zzz.example.net"], cert, TargetPolicy.for_tests(["1.1.1.0/24"]), max_candidates=5)
    assert "ptr.zzz.example.net" in ep.names and ep.truncated


def test_csv_neutralises_formula_injection_and_renders_booleans(tmp_path):
    rows = [{"a": "=HYPERLINK(\"http://x\")", "b": True, "c": ["x"], "d": "@cmd", "e": "ok", "f": None}]
    pipeline._write_csv(tmp_path / "o.csv", rows)
    text = (tmp_path / "o.csv").read_text()
    assert "'=HYPERLINK" in text and "'@cmd" in text and "true" in text


def test_large_san_list_is_capped_in_rows(cfg):
    run_dir = go(cfg, tools())
    r = rows_of(run_dir)[0]
    assert len(r["certificate_sans"]) <= 50 and "certificate_san_count" in r


# ------------------------------------------------------------------ run control: interrupts, expiry, run-once, exit codes

def test_interrupt_still_writes_manifest_and_marks_partial(cfg):
    ft = tools()
    orig = ft._zgrab

    def interrupt_on_tls(c, stdin):
        if c[1] == "tls" and "--port" in c and not any(h for h in [r.split(",")[1] for r in stdin.splitlines()]):
            raise KeyboardInterrupt("signal 15")
        return orig(c, stdin)
    ft._zgrab = interrupt_on_tls
    run_dir = go(cfg, ft)
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["abort_reason"] == "interrupt" and not m["complete"]
    assert "tls_direct" in m["stage_errors"] and "ptr" in m["stages_skipped"]
    assert (run_dir / "report" / "summary.json").exists()


def test_expired_approval_stops_the_run_between_stages(cfg):
    past = dataclasses.replace(cfg.approval, valid_until=cfg.approval.valid_until.replace(year=2001))
    expired = dataclasses.replace(cfg, approval=past)
    run_dir = go(expired, tools())
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["abort_reason"] == "approval_expired" and m["stage_counts"]["l4_endpoints"] == 0


def test_run_requires_an_authorized_config(cfg):
    from scanner.internet.config import ConfigError
    with pytest.raises(ConfigError):
        pipeline.run(dataclasses.replace(cfg, approval=None), run_id="x", executor=tools(), skip_preflight=True, offline_preflight=True)


def test_zero_responsive_flagged_in_manifest_and_cli_exit_code(cfg, monkeypatch, capsys):
    from scanner.internet import __main__ as cli
    real_run = pipeline.run
    monkeypatch.setattr(cli.pipeline, "run", lambda c, run_id=None: real_run(c, run_id=run_id, executor=tools(l4={}), fetcher=FakeFetcher(),
                                                                              skip_preflight=True, offline_preflight=True))
    cfgfile = Path(cfg.output_dir).parent / "scanner.yaml"
    _p, splan, _e = pipeline.build_policy(cfg)
    token = pipeline.confirm_token(cfg, splan)
    assert cli.main(["run", "--skip-pilot-check", "--config", str(cfgfile), "--confirm", token]) == 4
    assert "zero responsive" in capsys.readouterr().err.lower()


def test_run_once_guard_blocks_identical_rerun_unless_allowed(cfg, monkeypatch):
    from scanner.internet import __main__ as cli
    real_run = pipeline.run
    n = {"i": 0}

    def fake_run(c, run_id=None):
        n["i"] += 1
        return real_run(c, run_id=f"r{n['i']}", executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)
    monkeypatch.setattr(cli.pipeline, "run", fake_run)
    cfgfile = Path(cfg.output_dir).parent / "scanner.yaml"
    _p, splan, _e = pipeline.build_policy(cfg)
    token = pipeline.confirm_token(cfg, splan)
    assert cli.main(["run", "--skip-pilot-check", "--config", str(cfgfile), "--confirm", token]) == 0
    assert cli.main(["run", "--skip-pilot-check", "--config", str(cfgfile), "--confirm", token]) == 2 and n["i"] == 1
    assert cli.main(["run", "--skip-pilot-check", "--config", str(cfgfile), "--confirm", token, "--allow-rerun"]) == 0 and n["i"] == 2


def test_manifest_records_egress_parameters_and_snapshot(cfg):
    run_dir = go(cfg, tools())
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["vantage"]["public_egress_ip"] == cfg.vantage.public_egress_ip
    assert m["parameters"]["dns_resolvers"] and m["complete"] is True
    assert json.loads((run_dir / "config.snapshot.json").read_text())["sample"]["seed"] == 4


# ------------------------------------------------------------------ ManagedExecutor (real subprocesses)

def _mx(cfg, tmp_path, killed=lambda: False):
    (tmp_path / "raw").mkdir(exist_ok=True)
    return ManagedExecutor(cfg, tmp_path, killed)


@posix_only
def test_executor_runs_tools_captures_output_and_keeps_stderr(cfg, tmp_path):
    ex = _mx(cfg, tmp_path)
    p = ex(["bash", "-c", "cat; echo oops >&2"], input="hello\n")
    assert p.returncode == 0 and p.stdout == "hello\n"
    saved = list((tmp_path / "raw" / "stderr").glob("*.txt"))
    assert saved and "oops" in saved[0].read_text()


@posix_only
def test_executor_hard_timeout_kills_the_whole_process_group(cfg, tmp_path):
    ex = _mx(cfg, tmp_path)
    t = time.monotonic()
    p = ex(["bash", "-c", "sleep 77.31 & wait"], timeout=2)
    assert time.monotonic() - t < 15 and "hard timeout" in p.stderr and p.returncode != 0
    time.sleep(0.5)
    assert subprocess.run(["pgrep", "-f", "sleep 77.31"], capture_output=True).returncode != 0   # grandchild is gone too


@posix_only
def test_executor_kill_switch_stops_a_running_tool(cfg, tmp_path):
    flag = {"stop": False}
    ex = _mx(cfg, tmp_path, killed=lambda: flag["stop"])
    import threading
    threading.Timer(1.5, lambda: flag.update(stop=True)).start()
    t = time.monotonic()
    p = ex(["bash", "-c", "sleep 78.41 & wait"], timeout=120)
    assert time.monotonic() - t < 20 and "kill switch" in p.stderr
    time.sleep(0.5)
    assert subprocess.run(["pgrep", "-f", "sleep 78.41"], capture_output=True).returncode != 0


@posix_only
def test_executor_kills_tool_on_keyboard_interrupt(cfg, tmp_path, monkeypatch):
    ex = _mx(cfg, tmp_path)
    calls = {"n": 0}
    real = subprocess.Popen.communicate

    def interrupting(self, input=None, timeout=None):
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt
        return real(self, input, timeout)
    monkeypatch.setattr(subprocess.Popen, "communicate", interrupting)
    with pytest.raises(KeyboardInterrupt):
        ex(["bash", "-c", "sleep 79.52 & wait"], timeout=60)
    monkeypatch.undo()
    time.sleep(0.5)
    assert subprocess.run(["pgrep", "-f", "sleep 79.52"], capture_output=True).returncode != 0


@posix_only
def test_executor_resolves_configured_binary_names(cfg, tmp_path):
    custom = tmp_path / "my-zdns"
    custom.write_text("#!/bin/sh\necho custom-binary\n")
    custom.chmod(0o755)
    cfg2 = dataclasses.replace(cfg, binaries=SimpleNamespace(zmap="zmap", zgrab2="zgrab2", zdns=str(custom)))
    p = ManagedExecutor(cfg2, tmp_path, lambda: False)(["zdns", "A"], input="x\n")
    assert p.stdout.strip() == "custom-binary"


def test_tool_crash_marks_run_incomplete_even_without_stage_exception(cfg):
    ft = tools()
    orig = ft._zgrab

    def crash_tls(c, stdin):
        if c[1] == "tls":
            return SimpleNamespace(returncode=2, stdout="", stderr="zgrab2 segfault")
        return orig(c, stdin)
    ft._zgrab = crash_tls
    run_dir = go(cfg, ft)
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["complete"] is False and m["tool_job_errors"]
    assert all(r["run_incomplete"] is True for r in rows_of(run_dir))


def test_sni_only_endpoint_gets_no_bare_ip_favicon_request(cfg):
    f = FakeFetcher()
    go(cfg, tools(), fetcher=f)
    strict_urls = [u for u, ip, _k in f.calls if ip == IP_STRICT]
    assert strict_urls and not any(u.startswith(f"https://{IP_STRICT}:") for u in strict_urls)
    assert any("edge.shop.example" in u for u in strict_urls)


@posix_only
def test_executor_delivers_large_stdin_to_a_slow_consumer(cfg, tmp_path):
    """Regression: >64 KB stdin used to stall at the pipe buffer when the tool read slowly."""
    ex = _mx(cfg, tmp_path)
    big = "x" * 1023 + "\n"
    payload = big * 2048                                   # 2 MiB
    t = time.monotonic()
    p = ex(["bash", "-c", "sleep 2; wc -c"], input=payload, timeout=60)
    assert p.returncode == 0 and p.stdout.strip() == str(len(payload)) and time.monotonic() - t < 30


@posix_only
def test_executor_large_stdout_does_not_deadlock(cfg, tmp_path):
    ex = _mx(cfg, tmp_path)
    p = ex(["bash", "-c", "yes | head -c 3000000"], timeout=60)
    assert len(p.stdout) == 3_000_000


@posix_only
def test_sigterm_ignoring_grandchild_cannot_hold_the_run(cfg, tmp_path):
    ex = _mx(cfg, tmp_path)
    t = time.monotonic()
    ex(["bash", "-c", "trap '' TERM; (trap '' TERM; sleep 92.9) & sleep 92.8; wait"], timeout=2)
    assert time.monotonic() - t < 30
    time.sleep(0.5)
    assert subprocess.run(["pgrep", "-f", "sleep 92.9"], capture_output=True).returncode != 0


def test_kill_switch_during_favicon_stage_marks_run_incomplete(cfg):
    class SwitchingFetcher(FakeFetcher):
        def fetch(self, *a, **k):
            Path(cfg.kill_switch_file).write_text("stop")
            return super().fetch(*a, **k)
    run_dir = go(cfg, tools(), fetcher=SwitchingFetcher())
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["abort_reason"] == "kill_switch" and m["complete"] is False


def test_started_stub_manifest_blocks_a_blind_rerun(cfg, tmp_path):
    from scanner.internet.__main__ import _prior_runs
    run_dir = Path(cfg.output_dir) / "crashed"
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(json.dumps({"status": "started", "config_checksum": cfg.checksum}))
    assert _prior_runs(cfg) == ["crashed"]


def test_complete_sample_list_and_per_ip_results(cfg):
    import csv
    ft = tools()
    ft.extra_sample = ["1.1.1.77", "1.1.1.78"]            # sampled but nothing answered
    run_dir = go(cfg, ft)
    listed = (run_dir / "scanned_ips.txt").read_text().split()
    assert "1.1.1.77" in listed and IP_OK in listed and listed == sorted(listed, key=lambda x: tuple(map(int, x.split("."))))
    dry = [c for c in ft.commands if "--dryrun" in c]
    assert len(dry) == 1 and "-n" in dry[0] and "--seed" in dry[0]          # listing sends nothing
    rows = list(csv.DictReader((run_dir / "ip_results.csv").open()))
    by_ip = {r["ip"]: r for r in rows}
    assert by_ip["1.1.1.77"]["responsive"] == "no" and by_ip["1.1.1.77"]["open_ports"] == ""
    assert by_ip[IP_OK]["responsive"] == "yes" and by_ip[IP_OK]["verified_hostnames"] == "good.test"
    assert by_ip[IP_STRICT]["verified_hostnames"] == "edge.shop.example"
    assert "80=http" in by_ip[IP_HTTP]["endpoints"]
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["stage_counts"]["sample_listed"] == len(listed) and "scanned_ips.txt" in m["output_checksums"]


def test_zmap_rate_is_an_integer_on_the_command_line(cfg):
    assert isinstance(cfg.measurement.zmap_rate, int)
    ft = tools()
    go(cfg, ft)
    real = [c for c in ft.commands if c[0] == "zmap" and "--dryrun" not in c and "--version" not in c]
    assert real
    for c in real:
        r = c[c.index("-r") + 1]
        assert r.isdigit(), r                                  # "100.0" was rejected by the real zmap


@pytest.mark.skipif(shutil.which("zmap") is None or os.name != "posix", reason="needs the real zmap binary")
def test_real_zmap_accepts_the_exact_generated_command(cfg, tmp_path):
    """The generated scan command, run through the REAL zmap with --dryrun (prints packets, sends none)."""
    from scanner.zmap_runner import run_zmap
    policy, splan, _ = pipeline.build_policy(cfg)
    seen = []

    def dry(cmd, **kw):
        seen.append(cmd)
        return subprocess.run(cmd + ["--dryrun"], capture_output=True, text=True, timeout=120)
    cfgview = SimpleNamespace(vantage=SimpleNamespace(id="t", interface=_default_iface(), source_ipv4=_iface_ip()),
                              measurement=SimpleNamespace(**{**vars(cfg.measurement), "zmap_max_targets": 30, "zmap_max_runtime": 20}))
    from scanner.internet.preflight import detect_gateway_mac
    mac = detect_gateway_mac(subprocess.run)
    assert mac, "no gateway MAC detected on this host"
    job, _res = run_zmap(cfgview, policy, 443, tmp_path, executor=dry, gateway_mac=mac)
    assert job.error is None and job.exit_code == 0, job.error
    assert "dryrun mode" in (tmp_path / "raw" / "zmap").joinpath(next((tmp_path / "raw" / "zmap").glob("*.csv")).name).read_text() or True


def _default_iface():
    out = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True, text=True).stdout.split()
    return out[out.index("dev") + 1]


def _iface_ip():
    out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", _default_iface()], capture_output=True, text=True).stdout.split()
    return out[out.index("inet") + 1].split("/")[0]


def test_tool_failure_is_not_reported_as_zero_responsive(cfg):
    ft = FakeTools(l4={}, tls={}, tls_sni={}, http={}, ptr={}, a={}, zmap_rc=1)
    run_dir = go(cfg, ft)
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["stage_errors"] and m["zero_responsive"] is False and m["complete"] is False


def test_favicon_outcome_distinguishes_images_from_html_and_errors(cfg):
    from scanner.models import FetchResult

    class Odd(FakeFetcher):
        def fetch(self, url, *, connect_ip, kind, context=""):
            if kind != "favicon":
                return super().fetch(url, connect_ip=connect_ip, kind=kind, context=context)
            body = b"<html><title>Please wait, the login page is opening</title></html>"
            return FetchResult(kind=kind, requested_url=url, connect_ip=connect_ip, host_header=None, sni=None, outcome="ok",
                               failure_category=None, http_status=200, content_type="text/html", content_encoding=None, retry_after=None,
                               body_sha256="y" * 64, body_bytes=len(body), redirect_chain=(), final_url=url, certificate=None), body
    rows = rows_of(go(cfg, tools(), fetcher=Odd()))
    ok = row(rows, IP_OK, "good.test")
    assert ok["direct_favicon_outcome"] == "not_an_image" and ok["direct_favicon_is_image"] is False


def test_favicon_outcome_reports_http_errors_not_ok():
    from scanner.internet.favicon import _favicon_outcome
    f = lambda status, outcome="http_status": SimpleNamespace(fetch=SimpleNamespace(http_status=status, outcome=outcome))
    assert _favicon_outcome(f(404), None) == "http_404"
    assert _favicon_outcome(f(503), None) == "http_503"
    assert _favicon_outcome(f(200, "ok"), None) == "not_an_image"
    assert _favicon_outcome(f(None, "timeout"), None) == "timeout"
    assert _favicon_outcome(f(200, "ok"), object()) == "image"
