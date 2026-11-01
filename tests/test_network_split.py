"""Network-only shards, the favicon-only stage on a second machine, and the export of finished shards."""
import json
from dataclasses import replace
from pathlib import Path

import pytest

from scanner.internet import archive, campaign, outputs, pipeline, split
from scanner.internet.__main__ import main
from scanner.internet.config import ConfigError, load_config
from tests.helpers import FakeFetcher, write_config
from tests.test_pipeline import tools
from tests.test_scale import _cfg


class NoFetch(FakeFetcher):
    def fetch(self, *a, **k):
        raise AssertionError("a lookup was sent although every record was imported")


def _real_run(ft):
    def run_fn(cfg, **kw):
        return pipeline.run(cfg, executor=ft, fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True, **kw)
    return run_fn


def _cfg_at(tmp_path, name, **over):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    return load_config(write_config(d, **over))


def _network_run(cfg, ft=None, run_id="t1"):
    return pipeline.run(cfg, run_id=run_id, executor=ft or tools(), fetcher=FakeFetcher(), skip_preflight=True,
                        offline_preflight=True, network_only=True)


def _whole(cfg, run_id="t1"):
    return pipeline.run(cfg, run_id=run_id, executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)


def _tables(run_dir):
    """The result tables; the age of a reused page is the one value that depends on when the favicon stage ran."""
    def plain(rows):
        return [{k: v for k, v in r.items() if not k.endswith("document_age_seconds")} for r in rows]
    return (plain(outputs.iter_endpoint_rows(run_dir)), plain(outputs.iter_hostname_rows(run_dir)),
            (run_dir / "ip_results.csv").read_text(encoding="utf-8"))


# ------------------------------------------------------------------ network-only shards and the favicon-only stage

def test_network_only_run_keeps_the_store_and_the_pages_and_is_not_finished(tmp_path):
    cfg = _cfg_at(tmp_path, "a")
    fetcher = FakeFetcher()
    run_dir = pipeline.run(cfg, run_id="t1", executor=tools(), fetcher=fetcher, skip_preflight=True, offline_preflight=True,
                           network_only=True)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["status"] == "network_done" and manifest["network_done"] is True and manifest["complete"] is False
    assert not manifest["stage_errors"] and not manifest["stages_skipped"]
    assert (run_dir / "work" / "facts.sqlite").is_file()
    assert (run_dir / "normalized" / "http_documents.jsonl").is_file() and "normalized/http_documents.jsonl" in manifest["output_checksums"]
    assert not (run_dir / "raw" / "favicon_records.jsonl").exists() and not fetcher.calls
    assert (run_dir / "normalized" / "endpoints.jsonl").is_file() and (run_dir / "ip_results.csv").is_file()
    assert not campaign._finished_cleanly(run_dir) and campaign._network_done(run_dir)
    assert campaign.resume_source(cfg, 0, "scanner-test-00000000-s000of001-a2") is None


def test_favicon_only_stage_gives_the_same_outputs_as_one_run(tmp_path):
    whole = _whole(_cfg_at(tmp_path, "whole"))
    cfg = _cfg_at(tmp_path, "split")
    run_dir = _network_run(cfg)
    jobs_before = (run_dir / "normalized" / "tool_jobs.jsonl").read_bytes()
    ft = tools()
    finished = pipeline.run_favicon_only(cfg, run_dir, executor=ft, fetcher=FakeFetcher())
    assert not ft.commands                                              # nothing but favicon lookups is sent
    manifest = json.loads((finished / "manifest.json").read_text())
    assert manifest["complete"] and manifest["status"] == "finished" and not manifest.get("network_done")
    assert not (finished / "work").exists()
    assert _tables(finished) == _tables(whole)
    reference = json.loads((whole / "manifest.json").read_text())
    assert manifest["stage_counts"]["l4_endpoints"] == reference["stage_counts"]["l4_endpoints"]
    assert manifest["tool_job_counts"] == reference["tool_job_counts"]
    assert (finished / "normalized" / "tool_jobs.jsonl").read_bytes() == jobs_before


def test_both_paths_build_the_same_favicon_jobs(tmp_path):
    cfg = _cfg_at(tmp_path, "jobs")
    run_dir = _network_run(cfg)
    from scanner.internet.shardstore import ShardStore
    store = ShardStore(run_dir / "work" / "facts.sqlite")
    jobs, ips, endpoints = pipeline.favicon_jobs(store, cfg, {})
    store.close()
    assert jobs and ips and endpoints == {(j["ip"], j["port"]) for j in jobs}
    done = pipeline.run_favicon_only(cfg, run_dir, executor=tools(), fetcher=FakeFetcher())
    lines = outputs.iter_lines(outputs.resolve(done / "raw" / "favicon_records.jsonl"))
    records = {(r["ip"], r["port"], r.get("hostname")) for r in (json.loads(l) for l in lines)}
    assert records == {(j["ip"], j["port"], j["hostname"]) for j in jobs}


def test_favicon_stage_refuses_a_shard_that_is_not_network_only(tmp_path):
    cfg = _cfg_at(tmp_path, "whole")
    with pytest.raises(ConfigError, match="not a network-only"):
        pipeline.run_favicon_only(cfg, _whole(cfg), executor=tools(), fetcher=FakeFetcher())


def test_second_machine_flow_ships_the_store_and_merges_the_favicon_outputs_back(tmp_path):
    whole = _whole(_cfg_at(tmp_path, "whole"))
    cfg = _cfg_at(tmp_path, "main")
    run_dir = _network_run(cfg)
    ship = tmp_path / "ship"
    record = split.export_network(run_dir, ship)
    assert {"work/facts.sqlite", "normalized/http_documents.jsonl", "manifest.json"} <= set(record["files"])
    assert split.verify_export(ship) == []

    remote = replace(_cfg_at(tmp_path, "remote"), compact_outputs=outputs.COMPRESSION == "zstd")
    pipeline.run_favicon_only(remote, ship, executor=tools(), fetcher=FakeFetcher())
    imported = split.import_favicons(run_dir, ship)
    assert "raw/favicon_records.jsonl" in imported["files"] and any(k.startswith("favicons/") for k in imported["files"])
    assert (run_dir / "favicon_import.json").is_file()

    finished = pipeline.run_favicon_only(cfg, run_dir, executor=tools(), fetcher=NoFetch())
    assert json.loads((finished / "manifest.json").read_text())["complete"]
    assert _tables(finished) == _tables(whole)
    assert sorted(p.name for p in (finished / "favicons").glob("*")) == sorted(p.name for p in (whole / "favicons").glob("*"))


def test_import_refuses_corrupt_favicon_outputs_and_copies_nothing(tmp_path):
    cfg = _cfg_at(tmp_path, "main")
    run_dir = _network_run(cfg)
    ship = tmp_path / "ship"
    split.export_network(run_dir, ship)
    pipeline.run_favicon_only(_cfg_at(tmp_path, "remote"), ship, executor=tools(), fetcher=FakeFetcher())
    icon = next(p for p in (ship / "favicons").iterdir() if p.is_file() and p.suffix != ".jsonl")
    icon.write_bytes(icon.read_bytes() + b"x")
    with pytest.raises(ConfigError, match="nothing was imported"):
        split.import_favicons(run_dir, ship)
    assert not (run_dir / "raw" / "favicon_records.jsonl").exists() and not (run_dir / "favicons").exists()


def test_export_network_detects_a_damaged_copy_and_does_not_overwrite(tmp_path):
    run_dir = _network_run(_cfg_at(tmp_path, "main"))
    ship = tmp_path / "ship"
    split.export_network(run_dir, ship)
    (ship / "work" / "facts.sqlite").write_bytes(b"damaged")
    assert any("facts.sqlite" in p for p in split.verify_export(ship))
    with pytest.raises(ConfigError, match="not empty"):
        split.export_network(run_dir, ship)


# ------------------------------------------------------------------ campaign state of network-only shards

def _network_run_fn(calls):
    def run_fn(cfg, *, run_id, **kw):
        calls.append((cfg.shard, kw.get("network_only")))
        d = Path(cfg.output_dir) / run_id
        (d / "report").mkdir(parents=True)
        (d / "work").mkdir()
        (d / "work" / "facts.sqlite").write_bytes(b"x")
        (d / "manifest.json").write_text(json.dumps({
            "complete": False, "network_done": bool(kw.get("network_only")), "status": "network_done", "abort_reason": None,
            "zero_responsive": False, "stage_errors": {}, "elapsed_seconds": 1.0}))
        return d
    return run_fn


def _two_shards(tmp_path):
    return load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 2}))


def test_campaign_records_network_done_shards_and_does_not_repeat_or_finish_them(tmp_path):
    cfg = _two_shards(tmp_path)
    calls = []
    result = campaign.run_campaign(cfg, run_fn=_network_run_fn(calls), log=lambda *_: None, network_only=True)
    state = json.loads((campaign.campaign_dir(cfg) / "campaign.json").read_text())
    assert [e["status"] for e in state["shard_states"].values()] == ["network_done", "network_done"]
    assert not result["complete"] and result["network_complete"] and result["shards_network_done"] == 2 and not result["stopped"]
    assert calls == [(0, True), (1, True)]
    campaign.run_campaign(cfg, run_fn=_network_run_fn(calls), log=lambda *_: None, network_only=True)
    assert len(calls) == 2                                              # neither started again
    assert all((Path(e["run_dir"]) / "work" / "facts.sqlite").is_file() for e in state["shard_states"].values())


def test_a_network_done_shard_that_finished_its_favicon_stage_is_adopted(tmp_path):
    cfg = _two_shards(tmp_path)
    calls = []
    campaign.run_campaign(cfg, run_fn=_network_run_fn(calls), log=lambda *_: None, network_only=True)
    state = json.loads((campaign.campaign_dir(cfg) / "campaign.json").read_text())
    for e in state["shard_states"].values():
        d = Path(e["run_dir"])
        (d / "report" / "summary.json").write_text(json.dumps({"counts": {"l4_endpoints": 3}}))
        (d / "manifest.json").write_text(json.dumps({"complete": True, "status": "finished", "stage_errors": {}, "zero_responsive": False}))
    assert campaign.record_finished_shard(cfg, Path(state["shard_states"]["0"]["run_dir"]))
    result = campaign.run_campaign(cfg, run_fn=_network_run_fn(calls), log=lambda *_: None)
    assert result["complete"] and len(calls) == 2


def test_network_only_campaign_cannot_be_overlapped(tmp_path):
    with pytest.raises(ValueError, match="overlap"):
        campaign.run_campaign(_two_shards(tmp_path), pipeline_depth=2, network_only=True, config_path=tmp_path / "x.yaml")


def test_cli_stop_after_network_passes_through_and_exits_zero(tmp_path, monkeypatch):
    import scanner.internet.campaign as c
    p = _cfg(tmp_path)
    cfg = load_config(p)
    token = pipeline.confirm_token(cfg, pipeline.build_policy(cfg)[1])
    got = {}
    monkeypatch.setattr(c, "run_campaign", lambda cfg_, **kw: got.update(kw) or {"complete": False, "network_complete": True, "stopped": None})
    assert main(["campaign", "--skip-pilot-check", "--config", str(p), "--confirm", token, "--stop-after-network"]) == 0
    assert got["network_only"] is True


# ------------------------------------------------------------------ export of finished shards

def _finished(tmp_path, name="e", compact=False):
    cfg = replace(_cfg_at(tmp_path, name), compact_outputs=compact)
    return cfg, pipeline.run(cfg, run_id="t1", executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)


@pytest.mark.parametrize("compact", [False, True])
def test_export_shard_verifies_then_removes_only_when_asked(tmp_path, compact):
    if compact and outputs.COMPRESSION != "zstd":
        pytest.skip("zstandard is not installed")
    _cfg_, run_dir = _finished(tmp_path, compact=compact)
    dest = tmp_path / "disk"
    kept = archive.export_shard(run_dir, dest)
    assert kept["verified"] and kept["removed_source"] is False
    assert outputs.exists(run_dir / "normalized" / "endpoints.jsonl")
    assert (dest / run_dir.name / archive.VERIFICATION).is_file()
    moved = archive.export_shard(run_dir, dest, remove_source=True)
    assert moved["removed_source"] and sorted(p.name for p in run_dir.iterdir()) == ["archive_record.json", "manifest.json", "report"]
    assert json.loads((dest / run_dir.name / "manifest.json").read_text())["complete"]
    assert archive.export_shard(run_dir, dest, remove_source=True)["status"] == "unchanged"


def test_export_shard_never_removes_anything_when_verification_fails(tmp_path):
    _cfg_, run_dir = _finished(tmp_path)
    with open(run_dir / "normalized" / "endpoints.jsonl", "ab") as fh:
        fh.write(b"\n")                                                   # no longer what the manifest recorded
    before = sorted(p.relative_to(run_dir).as_posix() for p in run_dir.rglob("*"))
    with pytest.raises(archive.ArchiveRefused, match="nothing was removed"):
        archive.export_shard(run_dir, tmp_path / "disk", remove_source=True)
    assert sorted(p.relative_to(run_dir).as_posix() for p in run_dir.rglob("*")) == before


def test_export_shard_checks_raw_sha256_of_the_tool_jobs(tmp_path):
    _cfg_, run_dir = _finished(tmp_path)
    rows = [json.loads(l) for l in outputs.iter_lines(outputs.resolve(run_dir / "normalized" / "tool_jobs.jsonl")) if l.strip()]
    assert rows and all((run_dir / r["raw_path"]).is_file() for r in rows)
    assert archive._raw_problems(run_dir, {}) == []
    victim = run_dir / rows[0]["raw_path"]
    victim.write_bytes(victim.read_bytes() + b"x")
    assert archive._raw_problems(run_dir, {}) != []


def test_export_shard_refuses_an_unfinished_run(tmp_path):
    run_dir = _network_run(_cfg_at(tmp_path, "n"))
    with pytest.raises(archive.ArchiveRefused, match="finish"):
        archive.export_shard(run_dir, tmp_path / "disk", remove_source=True)
    assert (run_dir / "work" / "facts.sqlite").is_file()


def test_campaign_exports_finished_shards_when_the_disk_is_low_and_keeps_them_complete(tmp_path):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 3}))
    run_fn = _real_run(tools())
    campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None, shards_from=0, shards_to=2)
    policy = campaign.ArchivePolicy(tmp_path / "disk", remove_source=True, free_gb_below=10**9)       # the disk is always "low"
    result = campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None, shards_from=2, shards_to=3, archive=policy)
    entries = json.loads((campaign.campaign_dir(cfg) / "campaign.json").read_text())["shard_states"]
    assert entries["0"]["archived_to"] and entries["0"]["source_removed"] and entries["0"]["status"] == "complete"
    assert entries["1"]["archived_to"] and entries["2"].get("archived_to") is None
    assert result["complete"] is True
    first = Path(entries["0"]["run_dir"])
    assert not (first / "normalized").exists() and (tmp_path / "disk" / first.name / "normalized").is_dir()
    # a repeated campaign neither probes again nor loses the archived shards from the totals
    calls = []
    again = campaign.run_campaign(cfg, run_fn=lambda *a, **k: calls.append(1), log=lambda *_: None)
    assert again["complete"] and not calls
    merged = json.loads((campaign.campaign_dir(cfg) / "campaign_summary.json").read_text())["merged"]
    assert merged["shards_merged"] == 3


def test_campaign_leaves_everything_alone_when_the_export_does_not_verify(tmp_path, monkeypatch):
    cfg = load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 2}))
    run_fn = _real_run(tools())
    campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None, shards_from=0, shards_to=1)
    monkeypatch.setattr(archive, "verify_copy", lambda *a: ["endpoints.jsonl does not match output_checksums"])
    logs = []
    policy = campaign.ArchivePolicy(tmp_path / "disk", remove_source=True, free_gb_below=10**9)
    campaign.run_campaign(cfg, run_fn=run_fn, log=logs.append, shards_from=1, shards_to=2, archive=policy)
    entries = json.loads((campaign.campaign_dir(cfg) / "campaign.json").read_text())["shard_states"]
    assert not entries["0"].get("archived_to")
    assert (Path(entries["0"]["run_dir"]) / "normalized" / "endpoints.jsonl").is_file()
    assert any("could not export" in l for l in logs)


def test_cli_export_commands(tmp_path):
    _cfg_, run_dir = _finished(tmp_path, "cli")
    assert main(["export-shard", str(run_dir), str(tmp_path / "disk")]) == 0
    assert (run_dir / "normalized").is_dir()                               # no --remove-source: nothing removed
    assert main(["export-shard", str(run_dir), str(tmp_path / "disk"), "--remove-source"]) == 0
    assert not (run_dir / "normalized").exists()
    net = _network_run(_cfg_at(tmp_path, "cli2"))
    assert main(["export-network", str(net), str(tmp_path / "ship")]) == 0
    assert main(["export-network", str(net), str(tmp_path / "ship")]) == 2
    assert main(["export-shard", str(net), str(tmp_path / "disk2"), "--remove-source"]) == 2


def test_a_network_done_shard_that_lost_its_fact_store_is_refused_not_rescanned(tmp_path):
    cfg = _two_shards(tmp_path)
    calls = []
    campaign.run_campaign(cfg, run_fn=_network_run_fn(calls), log=lambda *_: None, network_only=True)
    state = json.loads((campaign.campaign_dir(cfg) / "campaign.json").read_text())
    (Path(state["shard_states"]["0"]["run_dir"]) / "work" / "facts.sqlite").unlink()
    with pytest.raises(ValueError, match="network_done"):
        campaign.run_campaign(cfg, run_fn=_network_run_fn(calls), log=lambda *_: None, network_only=True)
    assert len(calls) == 2


def _shipped(tmp_path):
    cfg = _cfg_at(tmp_path, "main")
    run_dir = _network_run(cfg)
    ship = tmp_path / "ship"
    split.export_network(run_dir, ship)
    pipeline.run_favicon_only(_cfg_at(tmp_path, "remote"), ship, executor=tools(), fetcher=FakeFetcher())
    return run_dir, ship


@pytest.mark.parametrize("damage", ["incomplete", "stage_error", "other_config"])
def test_import_needs_a_complete_error_free_run_of_the_same_configuration(tmp_path, damage):
    run_dir, ship = _shipped(tmp_path)
    manifest = json.loads((ship / "manifest.json").read_text())
    if damage == "incomplete":
        manifest["complete"] = False
    elif damage == "stage_error":
        manifest["stage_errors"] = {"favicon_deadline": "stage cap reached"}
    else:
        snap = json.loads((ship / "config.snapshot.json").read_text())
        snap["measurement"]["ports"] = [8080]
        (ship / "config.snapshot.json").write_text(json.dumps(snap))
    (ship / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ConfigError):
        split.import_favicons(run_dir, ship)
    assert not (run_dir / "favicon_import.json").exists() and not (run_dir / "favicons").exists()


def test_export_folds_the_write_ahead_log_into_the_copied_store(tmp_path):
    import sqlite3
    run_dir = _network_run(_cfg_at(tmp_path, "main"))
    store = run_dir / "work" / "facts.sqlite"
    db = sqlite3.connect(store)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA wal_autocheckpoint=0")
    db.execute("CREATE TABLE late (x)")
    db.execute("INSERT INTO late VALUES (1)")
    db.commit()
    wal = store.with_name(store.name + "-wal")
    assert wal.stat().st_size > 0
    ship = tmp_path / "ship"
    split.export_network(run_dir, ship)
    db.close()
    copy = sqlite3.connect(ship / "work" / "facts.sqlite")
    assert copy.execute("SELECT x FROM late").fetchall() == [(1,)]
    copy.close()
