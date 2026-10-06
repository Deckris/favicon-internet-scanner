"""Sharding, campaigns, listing limits and the run guards (egress change, low disk)."""
import json
from collections import namedtuple
from pathlib import Path

import pytest
import yaml

from scanner.internet import campaign, favicon as fav, pipeline, population as pop
from scanner.internet import preflight as pre
from scanner.internet.__main__ import main
from scanner.internet.config import ConfigError, load_config
from tests.helpers import FakeFetcher, config_dict, write_approval, write_exclusions
from tests.test_pipeline import IP_OK, tools


def _cfg(tmp_path, *, sample=None, output=None, operations=None):
    excl = write_exclusions(tmp_path)
    d = config_dict(tmp_path, excl, write_approval(tmp_path, excl))
    d["sample"] = sample or {"fraction": 0.0001, "seed": 4, "shards": 3}
    d["output"].update(output or {})
    d["operations"].update(operations or {})
    p = tmp_path / "scale.yaml"
    p.write_text(yaml.safe_dump(d), encoding="utf-8")
    return p


# ------------------------------------------------------------------ plan arithmetic

def test_shard_shares_add_up_and_differ_by_at_most_one():
    population = pop.population_cidrs()
    shares = [pop.plan(population, [], fraction=0.0001, ports=(80,), rate=100, probes=1, shards=7, shard=i).targets_per_port
              for i in range(7)]
    total = pop.plan(population, [], fraction=0.0001, ports=(80,), rate=100, probes=1, shards=7).total_targets
    assert sum(shares) == total and max(shares) - min(shares) <= 1
    with pytest.raises(ValueError, match="fewer shards"):                     # never more targets than the fraction allows
        pop.plan(population, [], fraction=1e-9, ports=(80,), rate=100, probes=1, shards=50)


def test_confirm_token_is_one_token_for_the_whole_campaign(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    tokens = {pipeline.confirm_token(c, pipeline.build_policy(c)[1])
              for c in (__import__("dataclasses").replace(cfg, shard=i) for i in range(3))}
    assert len(tokens) == 1
    other = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 4}))
    assert pipeline.confirm_token(other, pipeline.build_policy(other)[1]) not in tokens


def test_shard_options_are_validated(tmp_path):
    with pytest.raises(ConfigError):
        load_config(_cfg(tmp_path, sample={"seed": 4, "target_ips": [IP_OK], "shards": 2}))
    with pytest.raises(ConfigError):
        load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 0}))
    with pytest.raises(ConfigError):
        load_config(_cfg(tmp_path, operations={"min_free_mib": 1}))


# ------------------------------------------------------------------ pipeline per shard

def _run(cfg, ft, **kw):
    return pipeline.run(cfg, executor=ft, fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True, **kw)


def test_shard_run_passes_shard_flags_to_both_zmap_calls_and_names_the_run(tmp_path):
    cfg = __import__("dataclasses").replace(load_config(_cfg(tmp_path)), shard=1)
    ft = tools()
    run_dir = _run(cfg, ft)
    zmap_cmds = [c for c in ft.commands if c[0].endswith("zmap") and "-p" in c]
    assert len(zmap_cmds) == 1 + len(cfg.measurement.ports)                 # sample listing + one scan per port
    for c in zmap_cmds:
        assert c[c.index("--shards") + 1] == "3" and c[c.index("--shard") + 1] == "1"
    assert "s001of003" in run_dir.name
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["shard"]["index"] == 1 and manifest["shard"]["of"] == 3


def test_large_shards_skip_the_target_list_and_keep_only_responsive_rows(tmp_path):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4}, output={"max_listed_targets": 0}))
    ft = tools()
    run_dir = _run(cfg, ft)
    assert not (run_dir / "scanned_ips.txt").exists()
    assert not any("--dryrun" in c for c in ft.commands)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert "skipped" in manifest["stage_counts"]["sample_listing"]
    warnings = json.loads((run_dir / "report" / "summary.json").read_text())["warnings"]
    assert manifest["complete"] and not any("sample list" in w for w in warnings)      # no false "list does not match" alarm
    lines = (run_dir / "ip_results.csv").read_text().splitlines()[1:]
    assert lines and all(",yes," in l for l in lines)                          # no row for a non-responsive address


def test_default_still_lists_every_target(tmp_path):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4}))
    run_dir = _run(cfg, tools())
    assert (run_dir / "scanned_ips.txt").read_text().split()


# ------------------------------------------------------------------ guards

def _stages(tmp_path, guards=True):
    cfg = load_config(_cfg(tmp_path, operations={"egress_check_seconds": 60}))
    st = pipeline._Stages(cfg, tmp_path, guards=guards)
    st._next_egress = 0.0
    return cfg, st


def test_changed_public_ip_stops_the_run(tmp_path, monkeypatch):
    cfg, st = _stages(tmp_path)
    monkeypatch.setattr(pre, "_public_ip", lambda *a, **k: "45.129.56.145")
    assert st.killed() and st.reason == "egress_changed"


def test_same_ip_keeps_running_and_failed_lookups_are_tolerated_twice(tmp_path, monkeypatch):
    cfg, st = _stages(tmp_path)
    answers = iter([None, None, cfg.vantage.public_egress_ip, None, None, None])
    monkeypatch.setattr(pre, "current_egress", lambda *a, **k: next(answers))
    for expected in (False, False, False, False, False, True):
        st._next_egress = 0.0
        assert st.killed() is expected
    assert st.reason == "egress_unknown"


def test_guards_are_off_for_offline_runs(tmp_path, monkeypatch):
    cfg, st = _stages(tmp_path, guards=False)
    monkeypatch.setattr(pre, "_public_ip", lambda *a, **k: pytest.fail("offline runs must not look up the public IP"))
    assert st.killed() is False


def test_low_disk_stops_the_run(tmp_path, monkeypatch):
    cfg, st = _stages(tmp_path, guards=False)
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(pipeline.shutil, "disk_usage", lambda p: usage(10**12, 10**12 - 1000, 1000))
    assert st.killed() and st.reason == "disk_low"


# ------------------------------------------------------------------ campaign

def _fake_run(tmp_path, outcomes):
    """run_fn double: writes a manifest + summary per shard; outcomes[i] = 'complete' | 'incomplete' | 'zero' | exception."""
    calls = []

    def run_fn(cfg, *, run_id, **_kw):
        calls.append((cfg.shard, run_id))
        outcome = outcomes.get(cfg.shard, "complete")
        if isinstance(outcome, Exception):
            raise outcome
        d = Path(cfg.output_dir) / run_id
        (d / "report").mkdir(parents=True)
        (d / "manifest.json").write_text(json.dumps({
            "complete": outcome in ("complete", "zero"), "abort_reason": "kill_switch" if outcome == "incomplete" else None,
            "zero_responsive": outcome == "zero", "stage_errors": {}, "elapsed_seconds": 1.0}))
        (d / "report" / "summary.json").write_text(json.dumps({
            "counts": {"l4_endpoints": 10 + cfg.shard, "l4_per_port": {"80": 5, "443": 5}}, "protocol_by_endpoint": {"https": 4},
            "unique_ips": 3, "tarpit_suspect_ips": 1}))
        return d
    return run_fn, calls


def test_campaign_runs_every_shard_merges_and_is_idempotent(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    run_fn, calls = _fake_run(tmp_path, {})
    result = campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)
    assert result["complete"] and result["shards_complete"] == 3 and [c[0] for c in calls] == [0, 1, 2]
    merged = json.loads(Path(result["summary_file"]).read_text())["merged"]
    assert merged["counts"]["l4_endpoints"] == 10 + 11 + 12 and merged["counts"]["l4_per_port"] == {"443": 15, "80": 15}
    assert merged["protocol_by_endpoint"] == {"https": 12} and merged["unique_ips"] == 9 and merged["shards_merged"] == 3
    again = campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)
    assert again["complete"] and len(calls) == 3                               # finished shards are never repeated


def test_campaign_stops_at_an_incomplete_shard_and_resumes_there(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    run_fn, calls = _fake_run(tmp_path, {1: "incomplete"})
    first = campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)
    assert not first["complete"] and first["stopped"]["shard"] == 1 and first["stopped"]["reason"] == "kill_switch"
    assert [c[0] for c in calls] == [0, 1]                                      # shard 2 was never started
    run_fn2, calls2 = _fake_run(tmp_path, {})
    second = campaign.run_campaign(cfg, run_fn=run_fn2, log=lambda *_: None)
    assert second["complete"] and [c[0] for c in calls2] == [1, 2]              # shard 0 skipped, shard 1 repeated
    assert calls2[0][1].endswith("-a2")                                         # new attempt, new run directory
    state = json.loads(Path(second["state_file"]).read_text())
    assert state["shard_states"]["1"]["attempts"] == 2


def test_campaign_stops_on_zero_responsive_and_on_crashes_and_refusals(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    run_fn, _ = _fake_run(tmp_path, {0: "zero"})
    assert campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)["stopped"]["reason"] == "zero_responsive"
    cfg2 = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 5, "shards": 2}))
    run_fn, _ = _fake_run(tmp_path, {0: RuntimeError("boom")})
    r = campaign.run_campaign(cfg2, run_fn=run_fn, log=lambda *_: None)
    assert r["stopped"]["reason"] == "crashed" and "boom" in r["stopped"]["detail"]
    cfg3 = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 6, "shards": 2}))
    run_fn, _ = _fake_run(tmp_path, {0: pre.PreflightFailed({"checks": [], "ok": False})})
    assert campaign.run_campaign(cfg3, run_fn=run_fn, log=lambda *_: None)["stopped"]["reason"] == "preflight_failed"


def test_campaign_state_from_another_config_is_refused(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    run_fn, _ = _fake_run(tmp_path, {})
    campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)
    state_file = campaign.campaign_dir(cfg) / "campaign.json"
    data = json.loads(state_file.read_text())
    data["shards"] = 9
    state_file.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="different configuration"):
        campaign.load_state(cfg)


def test_offhost_caps_carry_over_between_shards(tmp_path):
    from scanner.web_fetch import FetchLimits
    lim = FetchLimits(connect_timeout=1, read_timeout=1, total_timeout=2, max_bytes=1000, max_decoded_bytes=1000, max_redirects=1)
    from scanner.safety import TargetPolicy

    def make():
        return fav.OffhostIconFetcher(TargetPolicy.for_tests(["127.0.0.1/32"]), None, user_agent="t", document_limits=lim,
                                      favicon_limits=lim, max_total=5, max_per_host=2, min_interval=0.0,
                                      state_path=tmp_path / "state" / "offhost_state.json")
    a = make()
    a._per_host, a._sent = {"cdn.example": 2}, 3
    a.save_state()
    b = make()
    assert b._per_host == {"cdn.example": 2} and b._sent == 3
    res, _ = b.fetch("http://cdn.example/icon.png", connect_ip=None, kind="favicon")
    assert res.failure_category == "host_cap"                                    # the cap was already used up in an earlier shard


# ------------------------------------------------------------------ CLI

def test_cli_enforces_shard_rules_before_sending_anything(tmp_path, capsys):
    p = _cfg(tmp_path)
    cfg = load_config(p)
    token = pipeline.confirm_token(cfg, pipeline.build_policy(cfg)[1])
    assert main(["run", "--skip-pilot-check", "--config", str(p), "--confirm", token]) == 2           # sharded config needs --shard or campaign
    assert "shards" in capsys.readouterr().err
    assert main(["run", "--skip-pilot-check", "--config", str(p), "--confirm", token, "--shard", "9"]) == 2
    assert main(["campaign", "--skip-pilot-check", "--config", str(p), "--confirm", "wrong"]) == 2
    unsharded = _cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4})
    cfg_u = load_config(unsharded)
    tok_u = pipeline.confirm_token(cfg_u, pipeline.build_policy(cfg_u)[1])
    assert main(["campaign", "--skip-pilot-check", "--config", str(unsharded), "--confirm", tok_u]) == 2
    assert main(["run", "--skip-pilot-check", "--config", str(unsharded), "--confirm", tok_u, "--shard", "1"]) == 2


def test_two_campaigns_cannot_run_on_one_config_and_stale_locks_are_replaced(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    lock = campaign._acquire_lock(cfg)
    with pytest.raises(campaign.CampaignLocked):
        campaign._acquire_lock(cfg)
    lock.unlink()
    lock.write_text("999999999")                                              # a pid that cannot exist: crashed campaign
    campaign._acquire_lock(cfg).unlink()
    run_fn, _ = _fake_run(tmp_path, {})
    assert campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)["complete"]
    assert not (campaign.campaign_dir(cfg) / "campaign.lock").exists()        # released afterwards


def test_a_shard_finished_by_hand_is_adopted_not_probed_again(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    done = Path(cfg.output_dir) / "manual-run"
    done.mkdir(parents=True)
    (done / "report").mkdir()
    (done / "manifest.json").write_text(json.dumps({"config_checksum": cfg.checksum, "shard": {"index": 1, "of": 3},
                                                    "complete": True, "zero_responsive": False}))
    (done / "report" / "summary.json").write_text(json.dumps({"counts": {"l4_endpoints": 7}}))
    run_fn, calls = _fake_run(tmp_path, {})
    result = campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)
    assert result["complete"] and [c[0] for c in calls] == [0, 2]
    assert json.loads(Path(result["state_file"]).read_text())["shard_states"]["1"]["adopted"] is True


def test_partial_shards_stay_out_of_the_merged_totals_and_retries_clear_stale_fields(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    run_fn, _ = _fake_run(tmp_path, {1: "incomplete"})
    first = campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)
    merged = json.loads(Path(first["summary_file"]).read_text())["merged"]
    assert merged["shards_merged"] == 1 and merged["counts"]["l4_endpoints"] == 10          # only shard 0
    state = json.loads(Path(first["state_file"]).read_text())
    assert state["shard_states"]["1"]["abort_reason"] == "kill_switch"
    seen = {}

    def spy(cfg_, *, run_id, **kw):
        if cfg_.shard == 1:
            seen.update(json.loads(Path(first["state_file"]).read_text())["shard_states"]["1"])
        return _fake_run(tmp_path, {})[0](cfg_, run_id=run_id, **kw)
    campaign.run_campaign(cfg, run_fn=spy, log=lambda *_: None)
    assert "abort_reason" not in seen and "run_dir" not in seen                 # nothing stale while the retry runs


def test_a_corrupt_state_file_is_never_silently_replaced(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    run_fn, _ = _fake_run(tmp_path, {})
    campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)
    (campaign.campaign_dir(cfg) / "campaign.json").write_text("{not json")
    with pytest.raises(ValueError, match="unreadable"):
        campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)
    assert not (campaign.campaign_dir(cfg) / "campaign.lock").exists()


def test_a_run_directory_is_never_reused(tmp_path):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4}))
    _run(cfg, tools(), run_id="same")
    with pytest.raises(ConfigError, match="already holds a run"):
        _run(cfg, tools(), run_id="same")


def test_campaign_exit_codes_distinguish_refusal_zero_and_partial(tmp_path, monkeypatch):
    import scanner.internet.campaign as c
    p = _cfg(tmp_path)
    cfg = load_config(p)
    token = pipeline.confirm_token(cfg, pipeline.build_policy(cfg)[1])
    for reason, code in (("preflight_failed", 2), ("zero_responsive", 4), ("kill_switch", 5), ("egress_changed", 5)):
        monkeypatch.setattr(c, "run_campaign", lambda cfg_, r=reason: {"complete": False, "stopped": {"reason": r}})
        assert main(["campaign", "--skip-pilot-check", "--config", str(p), "--confirm", token]) == code, reason
    monkeypatch.setattr(c, "run_campaign", lambda cfg_: {"complete": True, "stopped": None})
    assert main(["campaign", "--skip-pilot-check", "--config", str(p), "--confirm", token]) == 0


# ------------------------------------------------------------------ reviewer fixes

def test_executor_does_not_start_a_tool_once_a_stop_condition_is_set(tmp_path):
    from scanner.internet.runner import ManagedExecutor
    cfg = load_config(_cfg(tmp_path))
    ex = ManagedExecutor(cfg, tmp_path, lambda: True)
    proc = ex(["zmap", "--version"])
    assert proc.returncode == -15 and "stopped before start" in proc.stderr
    assert not list((tmp_path / "raw").glob("**/*.txt")) if (tmp_path / "raw").exists() else True      # nothing was launched


def _serve(body: bytes | None):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            return

        def do_GET(self):      # noqa: N802
            if body is None:
                import time
                time.sleep(30)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    s = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def test_public_ip_lookup_ignores_proxy_variables_and_cannot_hang(monkeypatch):
    import time
    ok, hung = _serve(b"203.0.113.9\n"), _serve(None)
    try:
        monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        assert pre._public_ip(f"http://127.0.0.1:{ok.server_address[1]}/", timeout=2) == "203.0.113.9"
        t = time.monotonic()
        assert pre._public_ip(f"http://127.0.0.1:{hung.server_address[1]}/", timeout=0.5) is None
        assert time.monotonic() - t < 5
    finally:
        for s in (ok, hung):
            s.shutdown()
            s.server_close()


def test_live_run_aborts_before_scanning_when_the_dry_run_does_not_match_the_plan(tmp_path, monkeypatch):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 3}))
    monkeypatch.setattr(pre, "_public_ip", lambda *a, **k: cfg.vantage.public_egress_ip)
    ft = tools()                                                   # dry run lists 4 targets; the plan expects ~123k per shard
    run_dir = pipeline.run(cfg, executor=ft, fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=False)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["abort_reason"] == "sample_list_mismatch" and not manifest["complete"]
    assert not any(c[0] == "zmap" and "--dryrun" not in c and "-p" in c for c in ft.commands)       # no real scan was started


def test_favicon_jobs_for_one_host_never_overlap():
    import threading
    import time
    lock, active, worst = threading.Lock(), {}, {}

    class Probe:
        def fetch(self, url, *, connect_ip, kind, context=""):
            with lock:
                active[connect_ip] = active.get(connect_ip, 0) + 1
                worst[connect_ip] = max(worst.get(connect_ip, 0), active[connect_ip])
            time.sleep(0.02)
            with lock:
                active[connect_ip] -= 1
            return FakeFetcher().fetch(url, connect_ip=connect_ip, kind=kind)
    jobs = [{"scheme": "http", "ip": ip, "port": 80, "hostname": h}
            for ip in ("1.1.1.1", "1.1.1.2", "1.1.1.3") for h in (None, "a.example", "b.example", "c.example")]
    out = fav.run_favicon_stage(Probe(), jobs, workers=8, max_icons=2)
    assert len(out) == len(jobs) and [(r["ip"], r["hostname"]) for r in out] == [(j["ip"], j["hostname"]) for j in jobs]
    assert max(worst.values()) == 1 and len(worst) == 3                 # parallel across hosts, serial within one


def test_favicon_stage_deadline_marks_the_shard_incomplete(tmp_path):
    import time

    class Slow(FakeFetcher):
        def fetch(self, *a, **k):
            time.sleep(0.7)
            return super().fetch(*a, **k)
    p = _cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4})
    d = yaml.safe_load(p.read_text())
    d["favicon"].update(stage_max_seconds=1, workers=1)
    p.write_text(yaml.safe_dump(d))
    cfg = load_config(p)
    run_dir = pipeline.run(cfg, executor=tools(), fetcher=Slow(), skip_preflight=True, offline_preflight=True)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert "favicon_deadline" in manifest["stage_errors"] and not manifest["complete"]


def test_dns_trouble_share_and_offhost_per_address_cap():
    from scanner.internet.enrich import dns_unknown_share
    assert dns_unknown_share(["resolved"] * 9 + ["timeout"]) == 0.1 and dns_unknown_share([]) == 0.0
    assert dns_unknown_share(["nxdomain", "resolved", "servfail", "tool_error"]) == 0.5       # nxdomain is an answer
    from urllib.parse import urlsplit
    from scanner.safety import TargetPolicy
    from scanner.web_fetch import FetchLimits
    lim = FetchLimits(connect_timeout=0.5, read_timeout=0.5, total_timeout=1, max_bytes=1000, max_decoded_bytes=1000, max_redirects=1)
    f = fav.OffhostIconFetcher(TargetPolicy.for_tests(["127.0.0.1/32"]), None, user_agent="t", document_limits=lim, favicon_limits=lim,
                               max_total=9, max_per_host=1, min_interval=0.0)
    outcomes = [f._one_request(urlsplit(f"http://h{i}.example/x"), f"h{i}.example", 80, "127.0.0.1", lim, 1, 1e12).outcome for i in range(3)]
    assert outcomes[2] == "policy_refused" and outcomes[0] != "policy_refused"           # many names, one machine: capped at 2 x max_per_host


def test_zmap_gets_one_sender_thread_and_a_per_packet_rate_ceiling(tmp_path):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4}))
    assert cfg.measurement.zmap_rate == 100 and cfg.measurement.zmap_probes == 2
    ft = tools()
    _run(cfg, ft)
    scans = [c for c in ft.commands if c[0].endswith("zmap") and "-p" in c and "--dryrun" not in c]
    assert scans
    for c in scans:
        assert c[c.index("-T") + 1] == "1"                                   # not one thread per core
        assert c[c.index("-r") + 1] == "50"                                  # 100 packets/s ceiling / 2 probes per target
