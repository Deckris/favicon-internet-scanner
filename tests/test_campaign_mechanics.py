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
