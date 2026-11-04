"""The ZMap stage and the network stages of one shard as separate runs in one directory."""
import json
import sqlite3
from pathlib import Path

import pytest

from scanner.internet import outputs, pipeline
from scanner.internet import resume as resume_mod
from scanner.internet import runner
from scanner.internet.config import ConfigError, load_config
from tests.helpers import FakeFetcher, write_config
from tests.test_pipeline import tools
from tests.test_resume import Crash, Dying, real_calls, tables


@pytest.fixture
def cfg(tmp_path):
    return load_config(write_config(tmp_path))


def go(cfg, run_id, executor, **kw):
    return pipeline.run(cfg, run_id=run_id, executor=executor, fetcher=FakeFetcher(), skip_preflight=True,
                        offline_preflight=True, **kw)


def cfg_at(tmp_path, name):
    d = tmp_path / name
    d.mkdir()
    return load_config(write_config(d))


def manifest(d):
    return json.loads((d / "manifest.json").read_text(encoding="utf-8"))


def sweeps(fake):
    return [c for c in fake.commands if Path(c[0]).name == "zmap" and not {"--dryrun", "--version"} & set(c)]


def steady(rows):
    return [{k: v for k, v in r.items() if not k.endswith("age_seconds")} for r in rows]


def test_stop_after_zmap_keeps_the_store_and_says_so(cfg):
    fake = tools()
    d = go(cfg, "z1", fake, stop_after_zmap=True)
    m = manifest(d)
    assert m["status"] == "zmap_done" and m["zmap_done"] is True and m["complete"] is False
    assert m["zmap_started_at"] <= m["zmap_finished_at"] and m["zmap_started_at"].endswith("+00:00")
    assert (d / "work" / "facts.sqlite").is_file() and (d / "scanned_ips.txt").is_file()
    assert len(sweeps(fake)) == len(cfg.measurement.ports)
    assert not any(Path(c[0]).name == "zgrab2" and "--help" not in c for c in fake.commands)           # no target-facing network stage ran
    assert resume_mod.missing_zmap_ports(d, cfg) == []


def test_zmap_then_network_gives_the_outputs_of_one_run(tmp_path, cfg):
    whole = go(cfg, "whole", tools(), network_only=True)
    other = cfg_at(tmp_path, "split")
    first = go(other, "s1", tools(), stop_after_zmap=True)
    fake = tools()
    d = go(other, "s1", fake, from_zmap=True)
    assert d == first
    assert not sweeps(fake)                                             # no sweep and no sample listing in the second run
    m = manifest(d)
    assert m["status"] == "network_done" and m["network_done"] is True and not m["stage_errors"] and not m["stages_skipped"]
    assert m["zmap_done"] is True and m["zmap_finished_at"]
    assert steady(outputs.iter_endpoint_rows(d)) == steady(outputs.iter_endpoint_rows(whole))
    assert steady(outputs.iter_hostname_rows(d)) == steady(outputs.iter_hostname_rows(whole))
    assert (d / "ip_results.csv").read_text(encoding="utf-8") == (whole / "ip_results.csv").read_text(encoding="utf-8")
    assert sorted(tables(d)[2]) == sorted(tables(whole)[2])
    finished = pipeline.run_favicon_only(other, d, executor=tools(), fetcher=FakeFetcher())
    assert manifest(finished)["complete"]


def test_from_zmap_with_a_missing_sweep_raises_and_sends_nothing(tmp_path, cfg):
    d = go(cfg, "m1", tools(), stop_after_zmap=True)
    db = sqlite3.connect(str(d / "work" / "facts.sqlite"))
    try:
        db.execute("DELETE FROM units WHERE unit = (SELECT unit FROM units WHERE stage = 'zmap' AND port = 80)")
        db.commit()
    finally:
        db.close()
    fake = tools()
    with pytest.raises(ConfigError, match="zmap results missing"):
        go(cfg, "m1", fake, from_zmap=True)
    assert fake.commands == []


def test_from_zmap_without_a_store_raises_before_any_traffic(cfg):
    fake = tools()
    with pytest.raises(ConfigError, match="zmap results missing"):
        go(cfg, "none", fake, from_zmap=True)
    assert fake.commands == []
    assert not (Path(cfg.output_dir) / "none").exists()


def test_a_sweep_that_cannot_be_reused_is_never_sent(cfg, monkeypatch):
    d = go(cfg, "g1", tools(), stop_after_zmap=True)
    monkeypatch.setattr(resume_mod, "missing_zmap_ports", lambda *a, **k: [])      # get past the early check
    for p in (d / "raw" / "zmap").glob("ZMAP-*"):
        p.unlink()
    fake = tools()
    result = go(cfg, "g1", fake, from_zmap=True)
    assert not sweeps(fake)
    assert not manifest(result)["complete"] and any(k.startswith("zmap") for k in manifest(result)["stage_errors"])


def test_the_two_modes_exclude_each_other(cfg):
    with pytest.raises(ConfigError):
        go(cfg, "x", tools(), stop_after_zmap=True, from_zmap=True)


def test_an_existing_directory_is_refused_without_continue_in_place(cfg):
    go(cfg, "r1", tools(), stop_after_zmap=True)
    with pytest.raises(ConfigError, match="already holds a run"):
        go(cfg, "r1", tools(), stop_after_zmap=True)


def test_continue_in_place_reuses_the_committed_units(tmp_path, cfg):
    clean_cfg = cfg_at(tmp_path, "clean")
    clean_fake = tools()
    clean = go(clean_cfg, "c1", clean_fake)
    try:
        go(cfg, "d1", Dying(tools(), 6))
    except Crash:
        pass
    d = Path(cfg.output_dir) / "d1"
    assert (d / "work" / "facts.sqlite").is_file()
    fake = tools()
    again = go(cfg, "d1", fake, continue_in_place=True)
    assert again == d
    assert manifest(d)["complete"]
    assert len(real_calls(fake)) < len(real_calls(clean_fake))
    assert tables(d)[0] == tables(clean)[0] and tables(d)[3] == tables(clean)[3]


def test_continue_in_place_stops_after_zmap_in_two_attempts(cfg):
    try:
        go(cfg, "p1", Dying(tools(), 1), stop_after_zmap=True)
    except Crash:
        pass
    fake = tools()
    d = go(cfg, "p1", fake, stop_after_zmap=True, continue_in_place=True)
    assert manifest(d)["zmap_done"] is True
    assert len(sweeps(fake)) == len(cfg.measurement.ports)           # nothing had been committed before the first sweep died
    third = tools()
    go(cfg, "p1", third, stop_after_zmap=True, continue_in_place=True)
    assert not sweeps(third)                                          # all sweeps are on file now


def test_continue_in_place_refuses_a_store_of_another_identity(cfg):
    go(cfg, "i1", tools(), stop_after_zmap=True)
    d = Path(cfg.output_dir) / "i1"
    db = sqlite3.connect(str(d / "work" / "facts.sqlite"))
    try:
        stored = json.loads(db.execute("SELECT value FROM meta WHERE key = 'identity'").fetchone()[0])
        stored["sample_seed"] = "other"
        db.execute("UPDATE meta SET value = ? WHERE key = 'identity'", (json.dumps(stored, sort_keys=True),))
        db.commit()
    finally:
        db.close()
    with pytest.raises(ConfigError, match="different run identity"):
        go(cfg, "i1", tools(), continue_in_place=True)


def test_a_finished_run_is_not_continued(cfg):
    go(cfg, "f1", tools())
    with pytest.raises(ConfigError, match="finished run"):
        go(cfg, "f1", tools(), continue_in_place=True)


def test_the_zmap_lock_is_held_for_the_run_and_dropped_after(cfg):
    seen = []

    class Watch:
        def __init__(self, inner):
            self.inner = inner

        def __call__(self, command, **kw):
            if Path(command[0]).name == "zmap" and not {"--dryrun", "--version"} & set(command):
                seen.append(dict(runner._INHERITED_FDS))
            return self.inner(command, **kw)

    go(cfg, "l1", Watch(tools()), stop_after_zmap=True, zmap_lock_fd=97)
    assert seen and all(s.get(97) == 1 for s in seen)
    assert 97 not in runner._INHERITED_FDS
