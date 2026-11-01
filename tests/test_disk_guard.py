"""The free-disk check between shards of a campaign (--pipeline 1 and --pipeline 2)."""
import json
import shutil
from collections import namedtuple
from dataclasses import replace
from pathlib import Path

import pytest

from scanner.internet import campaign, pipeline, supervisor
from scanner.internet.__main__ import CAMPAIGN_EXIT, main
from scanner.internet.config import ConfigError, load_config
from tests.test_compaction import _finished_run
from tests.test_scale import _cfg
from tests.test_supervisor import fake, posix    # noqa: F401  (the fake-child fixture)

GIB = 1 << 30
Usage = namedtuple("Usage", "total used free")


def test_the_disk_threshold_is_optional_and_validated(tmp_path):
    for name in ("a", "b", "c"):
        (tmp_path / name).mkdir()
    assert load_config(_cfg(tmp_path / "a", operations={})).min_free_gb_between_shards is None
    assert load_config(_cfg(tmp_path / "b", operations={"min_free_gb_between_shards": 12.5})).min_free_gb_between_shards == 12.5
    with pytest.raises(ConfigError, match="min_free_gb_between_shards"):
        load_config(_cfg(tmp_path / "c", operations={"min_free_gb_between_shards": -1}))


class Disk:
    """shutil.disk_usage double: reports ``free`` bytes."""

    def __init__(self, free_gb):
        self.free = int(free_gb * GIB)

    def __call__(self, _path):
        return Usage(10**13, 10**13 - self.free, self.free)


def test_the_default_floor_is_twice_the_largest_shard_plus_15_gb_and_20_before_the_first(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    state = {"shard_states": {}}
    assert campaign.disk_floor(cfg, state)[0] == 20 * GIB
    state["shard_states"] = {"0": {"status": "complete", "disk_bytes": 3 * GIB}, "1": {"status": "complete", "disk_bytes": 5 * GIB},
                             "2": {"status": "crashed", "disk_bytes": 99 * GIB}}
    assert campaign.disk_floor(cfg, state)[0] == 25 * GIB
    assert campaign.disk_floor(replace(cfg, min_free_gb_between_shards=7.0), state)[0] == 7 * GIB


def test_the_campaign_does_not_start_a_shard_without_the_space_and_resumes_when_it_is_freed(tmp_path, monkeypatch):
    cfg = load_config(_cfg(tmp_path))
    disk = Disk(5)
    monkeypatch.setattr(shutil, "disk_usage", disk)
    calls, logs = [], []

    def run_fn(c, *, run_id, **kw):
        calls.append(c.shard)
        return _finished_run(c, run_id)
    result = campaign.run_campaign(cfg, run_fn=run_fn, log=logs.append)
    assert calls == [] and not result["complete"]
    stopped = result["stopped"]
    assert stopped["reason"] == "disk" and stopped["shard"] == 0
    assert "5.0 GB free" in stopped["detail"] and "20.0 GB needed" in stopped["detail"] and "15.0 GB short" in stopped["detail"]
    assert any("not starting shard 1/3" in line for line in logs)
    state = json.loads(Path(result["state_file"]).read_text())
    assert state["shard_states"]["0"]["attempts"] == 0                  # nothing was started, so no attempt is counted
    disk.free = 100 * GIB
    again = campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)
    assert again["complete"] and calls == [0, 1, 2]


def test_the_floor_grows_with_the_finished_shards_and_stops_the_campaign_between_two_shards(tmp_path, monkeypatch):
    cfg = load_config(_cfg(tmp_path))
    disk = Disk(100)
    monkeypatch.setattr(shutil, "disk_usage", disk)
    calls = []

    def run_fn(c, *, run_id, **kw):
        calls.append(c.shard)
        d = _finished_run(c, run_id)
        if len(calls) == 1:
            disk.free = 14 * GIB                              # the first shard used most of what was left
        return d
    result = campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)
    assert calls == [0] and result["shards_complete"] == 1
    assert result["stopped"]["reason"] == "disk" and result["stopped"]["shard"] == 1
    assert "twice the largest finished shard" in result["stopped"]["detail"] and "14.0 GB free" in result["stopped"]["detail"]
    disk.free = 100 * GIB
    assert campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)["complete"] and calls == [0, 1, 2]


def test_an_explicit_threshold_replaces_the_default_and_zero_turns_the_check_off(tmp_path, monkeypatch):
    cfg = load_config(_cfg(tmp_path))
    monkeypatch.setattr(shutil, "disk_usage", Disk(40))
    calls = []

    def run_fn(c, *, run_id, **kw):
        calls.append(c.shard)
        return _finished_run(c, run_id)
    stopped = campaign.run_campaign(replace(cfg, min_free_gb_between_shards=50.0), run_fn=run_fn, log=lambda *_: None)["stopped"]
    assert stopped["reason"] == "disk" and "50.0 GB needed" in stopped["detail"] and calls == []
    monkeypatch.setattr(shutil, "disk_usage", Disk(0))
    assert campaign.run_campaign(replace(cfg, min_free_gb_between_shards=0.0), run_fn=run_fn, log=lambda *_: None)["complete"]


def test_the_disk_stop_has_its_own_exit_code(tmp_path, monkeypatch, capsys):
    import scanner.internet.campaign as c
    assert CAMPAIGN_EXIT["disk"] == 6 and 6 not in {v for k, v in CAMPAIGN_EXIT.items() if k != "disk"}
    p = _cfg(tmp_path)
    cfg = load_config(p)
    token = pipeline.confirm_token(cfg, pipeline.build_policy(cfg)[1])
    monkeypatch.setattr(c, "run_campaign", lambda cfg_, **_kw: {"complete": False, "stopped": {"shard": 2, "reason": "disk", "detail": "1 GB short"}})
    assert main(["campaign", "--skip-pilot-check", "--config", str(p), "--confirm", token]) == 6
    assert "1 GB short" in capsys.readouterr().err


@posix
def test_the_overlapped_campaign_stops_cleanly_for_lack_of_disk_and_resumes(tmp_path, monkeypatch, fake):    # noqa: F811
    cfg = load_config(_cfg(tmp_path))
    asked = []
    disk = Disk(100)

    def usage(path):
        asked.append(path)
        if len(asked) > 1:                                    # room for the first shard, none for the second
            disk.free = 5 * GIB
        return disk(path)
    monkeypatch.setattr(shutil, "disk_usage", usage)
    logs = []
    result = supervisor.run_overlapped(cfg, log=logs.append, launcher=fake.launcher(cfg, a=0.3, b=0.3), poll=0.05)
    assert result["stopped"]["reason"] == "disk" and result["stopped"]["shard"] == 1
    assert "5.0 GB free" in result["stopped"]["detail"] and any("not starting shard 2/3" in line for line in logs)
    assert result["shards_complete"] == 1                     # the shard in flight finished
    assert [e[0] for e in fake.events() if e[1] == 0][-1] == "end" and not [e for e in fake.events() if e[1] != 0]
    monkeypatch.setattr(shutil, "disk_usage", Disk(100))
    again = supervisor.run_overlapped(cfg, log=lambda *_: None, launcher=fake.launcher(cfg, a=0.3, b=0.3), poll=0.05)
    assert again["complete"]
    assert len([e for e in fake.events() if e[0] == "begin" and e[1] == 0]) == 1        # the finished shard was not run again
