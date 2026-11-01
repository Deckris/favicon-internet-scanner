"""Shard ranges, network-only shards, the favicon-only stage, shard export and the derived favicon stage cap."""
import json
from pathlib import Path

import pytest

from scanner.internet import campaign, pipeline
from scanner.internet.__main__ import main
from scanner.internet.config import ConfigError, load_config
from tests.helpers import FakeFetcher
from tests.test_pipeline import tools
from tests.test_scale import _cfg, _fake_run


def _real_run(ft):
    def run_fn(cfg, **kw):
        return pipeline.run(cfg, executor=ft, fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True, **kw)
    return run_fn


# ------------------------------------------------------------------ shard ranges

def test_shard_range_is_from_inclusive_to_exclusive(tmp_path):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 5}))
    run_fn, calls = _fake_run(tmp_path, {})
    result = campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None, shards_from=1, shards_to=3)
    assert [s for s, _ in calls] == [1, 2]
    assert result["complete"] and result["shard_range"] == [1, 3] and result["shards_complete"] == 2
    summary = json.loads((campaign.campaign_dir(cfg) / "campaign_summary.json").read_text())
    assert summary["complete"] and summary["merged"]["shards_merged"] == 2
    rest = campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None, shards_from=3)
    assert [s for s, _ in calls] == [1, 2, 3, 4] and rest["complete"]


def test_shard_range_does_not_touch_the_campaign_definition(tmp_path):
    p = _cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 5})
    cfg = load_config(p)
    run_fn, _ = _fake_run(tmp_path, {})
    campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None, shards_from=0, shards_to=2)
    assert campaign.campaign_dir(load_config(p)) == campaign.campaign_dir(cfg)
    assert load_config(p).checksum == cfg.checksum


def test_incomplete_range_is_not_complete_even_when_other_shards_are_not_asked_for(tmp_path):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 5}))
    run_fn, calls = _fake_run(tmp_path, {2: "incomplete"})
    result = campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None, shards_from=1, shards_to=4)
    assert not result["complete"] and result["stopped"]["shard"] == 2 and [s for s, _ in calls] == [1, 2]


@pytest.mark.parametrize("lo, hi", [(-1, 2), (2, 2), (3, 2), (0, 6), (5, None)])
def test_bad_shard_ranges_are_refused(tmp_path, lo, hi):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 5}))
    with pytest.raises(ValueError, match="shard range"):
        campaign.run_campaign(cfg, run_fn=_fake_run(tmp_path, {})[0], log=lambda *_: None, shards_from=lo, shards_to=hi)


def test_two_disjoint_ranges_scan_disjoint_zmap_slices(tmp_path):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 4}))
    seen = []
    for lo, hi in ((0, 2), (2, 4)):
        ft = tools()
        result = campaign.run_campaign(cfg, run_fn=_real_run(ft), log=lambda *_: None, shards_from=lo, shards_to=hi)
        assert result["complete"]
        scans = [c for c in ft.commands if c[0].endswith("zmap") and "-p" in c]
        slices = {(c[c.index("--shards") + 1], c[c.index("--shard") + 1]) for c in scans}
        assert {n for _, n in slices} == {str(i) for i in range(lo, hi)} and {t for t, _ in slices} == {"4"}
        seen.append({n for _, n in slices})
    assert not seen[0] & seen[1] and seen[0] | seen[1] == {"0", "1", "2", "3"}


def test_cli_passes_the_range_through(tmp_path, monkeypatch):
    import scanner.internet.campaign as c
    p = _cfg(tmp_path)
    cfg = load_config(p)
    token = pipeline.confirm_token(cfg, pipeline.build_policy(cfg)[1])
    got = {}
    monkeypatch.setattr(c, "run_campaign", lambda cfg_, **kw: got.update(kw) or {"complete": True, "stopped": None})
    assert main(["campaign", "--skip-pilot-check", "--config", str(p), "--confirm", token, "--shards-from", "1", "--shards-to", "2"]) == 0
    assert got == {"shards_from": 1, "shards_to": 2}


# ------------------------------------------------------------------ favicon stage cap and tool timeouts at 100 and 1000 shards

def _scale_cfg(tmp_path, shards, **favicon):
    import yaml
    tmp_path = tmp_path / f"s{shards}-{len(favicon)}"
    tmp_path.mkdir(exist_ok=True)
    from tests.helpers import config_dict, write_approval, write_exclusions
    excl = write_exclusions(tmp_path)
    d = config_dict(tmp_path, excl, write_approval(tmp_path, excl, max_sample_fraction=1.0, max_rate_per_second=130000))
    d["sample"] = {"fraction": 1.0, "seed": 4, "shards": shards}
    d["measurement"].update(zmap_version="4.4.0", zmap_rate=130000, zmap_probes=1, zgrab_senders=500, zgrab_batch_size=20000,
                            zmap_max_runtime=7 * 24 * 3600 // shards if shards > 1 else 7 * 24 * 3600)
    d["measurement"]["min_seconds_between_probes_per_ip"] = 5
    d["favicon"].update(favicon)
    p = tmp_path / f"scale{shards}.yaml"
    p.write_text(yaml.safe_dump(d), encoding="utf-8")
    return load_config(p)


def test_favicon_stage_cap_follows_the_shard_size_unless_set(tmp_path):
    from scanner.internet.config import favicon_stage_seconds
    c100, c1000 = _scale_cfg(tmp_path, 100), _scale_cfg(tmp_path, 1000)
    assert favicon_stage_seconds(c1000, 170_000) == 7200                       # a small shard keeps the floor
    assert favicon_stage_seconds(c100, 1_700_000) > 7200                       # 100 shards would be killed at the old default
    assert favicon_stage_seconds(c100, 1_700_000) == -(-1_700_000 // 180)
    assert favicon_stage_seconds(c100, 10**9) == 86400                         # the cap
    assert favicon_stage_seconds(c100, 0) == 7200


def test_an_explicit_stage_cap_wins_over_the_derived_one(tmp_path):
    from scanner.internet.config import favicon_stage_seconds
    cfg = _scale_cfg(tmp_path, 100, stage_max_seconds=900)
    assert favicon_stage_seconds(cfg, 10**9) == 900
    assert favicon_stage_seconds(cfg, 10**9, longest_chain=10**6, resumed=5) == 900


def test_the_stage_cap_allows_for_the_pause_between_requests_to_one_address(tmp_path):
    from scanner.internet.config import favicon_stage_seconds
    cfg = _scale_cfg(tmp_path, 1000)
    icons = cfg.favicon.max_icons_per_page
    pause = cfg.measurement.min_seconds_between_probes_per_ip
    chain = 1000                                     # one address with many hostnames: slow by pace, not by volume
    assert favicon_stage_seconds(cfg, chain, longest_chain=chain) == chain * (1 + icons) * pause > 7200
    assert favicon_stage_seconds(cfg, chain, longest_chain=1) == 7200


def test_lookups_an_earlier_attempt_holds_do_not_count_toward_the_stage_cap(tmp_path):
    from scanner.internet.config import favicon_stage_seconds
    cfg = _scale_cfg(tmp_path, 100)
    assert favicon_stage_seconds(cfg, 1_700_000, resumed=1_700_000 - 1000) == 7200
    assert favicon_stage_seconds(cfg, 1_700_000, resumed=0) == -(-1_700_000 // 180)


def test_tool_timeouts_cover_a_shard_ten_times_larger(tmp_path):
    from scanner.internet.runner import ManagedExecutor
    for shards in (100, 1000):
        cfg = _scale_cfg(tmp_path, shards)
        plan = pipeline.build_policy(cfg)[1]
        ex = ManagedExecutor.__new__(ManagedExecutor)
        ex.cfg = cfg
        # ZMap: the hard timeout must exceed the time the shard's sweep needs at the configured rate
        assert ex.timeout_for("zmap", ["zmap"], None) > plan.seconds_per_port
        # ZGrab2: a batch is bounded by its own size, never by the shard
        batch = "".join(f"1.2.3.{i % 250},,,443\n" for i in range(cfg.measurement.zgrab_batch_size))
        assert ex.timeout_for("zgrab2", ["zgrab2"], batch) >= 1800 + cfg.measurement.zgrab_target_timeout * 2
    big = _scale_cfg(tmp_path, 100)
    ex = ManagedExecutor.__new__(ManagedExecutor)
    ex.cfg = big
    assert ex.timeout_for("zdns", ["zdns"], "a\n" * 10) == ex.timeout_for("zdns", ["zdns"], "a\n" * 10**6)   # zdns is chunked at 50,000 names
