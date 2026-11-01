"""Deleting raw/ of a compacted shard: the checks, the record it leaves, the resume and the campaign option."""
import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from scanner.internet import campaign, outputs
from scanner.internet.__main__ import main
from scanner.internet.config import ConfigError, load_config
from tests.helpers import write_config
from tests.test_compaction import _config, _finished_run, _manifest, needs_zstd
from tests.test_pipeline import go, tools
from tests.test_scale import _cfg

pytestmark = needs_zstd


def _compacted(tmp_path):
    run_dir = go(_config(tmp_path), tools())
    assert (run_dir / "raw").is_dir() and "compaction" in _manifest(run_dir)
    return run_dir


def _write_manifest(run_dir, manifest):
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _edit_manifest(run_dir, **changes):
    _write_manifest(run_dir, {**_manifest(run_dir), **changes})


def _refused(run_dir, reason):
    manifest = (run_dir / "manifest.json").read_bytes()
    result = outputs.prune_raw(run_dir)
    assert result["status"] == "refused" and reason in result["reason"], result
    assert (run_dir / "raw").is_dir() and not (run_dir / "raw.pruning").exists() and not (run_dir / "raw_pruned.json").exists()
    assert (run_dir / "manifest.json").read_bytes() == manifest


# ------------------------------------------------------------------ the function

def test_a_compacted_complete_run_loses_raw_and_keeps_everything_else(tmp_path):
    run_dir = _compacted(tmp_path)
    manifest = (run_dir / "manifest.json").read_bytes()
    raw_files = {p.relative_to(run_dir).as_posix(): p.stat().st_size for p in (run_dir / "raw").rglob("*") if p.is_file()}
    others = {p.relative_to(run_dir).as_posix() for p in run_dir.rglob("*") if p.is_file() and "raw" not in p.relative_to(run_dir).parts}
    result = outputs.prune_raw(run_dir)
    assert result["status"] == "pruned" and result["files_removed"] == len(raw_files) > 0
    assert not (run_dir / "raw").exists() and not (run_dir / "raw.pruning").exists()
    assert (run_dir / "manifest.json").read_bytes() == manifest
    assert others <= {p.relative_to(run_dir).as_posix() for p in run_dir.rglob("*") if p.is_file()}
    record = json.loads((run_dir / "raw_pruned.json").read_text(encoding="utf-8"))
    assert record["files_removed"] == len(raw_files) and record["bytes_removed"] == sum(raw_files.values()) and record["pruned_at"] > 0
    assert {f["file"]: f["bytes"] for f in record["files"]} == raw_files
    recorded = _manifest(run_dir)["output_checksums"]
    assert all(f["sha256"] == recorded.get(f["file"]) for f in record["files"])
    assert any(f["sha256"] for f in record["files"])


def test_pruning_twice_is_harmless(tmp_path):
    run_dir = _compacted(tmp_path)
    assert outputs.prune_raw(run_dir)["status"] == "pruned"
    record = (run_dir / "raw_pruned.json").read_bytes()
    assert outputs.prune_raw(run_dir)["status"] == "unchanged"
    assert (run_dir / "raw_pruned.json").read_bytes() == record
    assert outputs.compact_run(run_dir)["status"] == "unchanged"       # a resumed campaign does not trip over the missing file


def test_refuses_an_incomplete_manifest(tmp_path):
    run_dir = _compacted(tmp_path)
    _edit_manifest(run_dir, complete=False)
    _refused(run_dir, "complete")


def test_refuses_a_manifest_with_stage_errors(tmp_path):
    run_dir = _compacted(tmp_path)
    _edit_manifest(run_dir, stage_errors={"favicon": "boom"})
    _refused(run_dir, "stage errors")


def test_refuses_a_run_that_was_not_compacted(tmp_path):
    run_dir = go(_config(tmp_path, compact=False), tools())
    _refused(run_dir, "not been compacted")


def test_refuses_without_a_manifest(tmp_path):
    run_dir = _compacted(tmp_path)
    (run_dir / "manifest.json").unlink()
    assert outputs.prune_raw(run_dir)["status"] == "refused" and (run_dir / "raw").is_dir()


def test_refuses_a_compressed_file_that_no_longer_matches(tmp_path):
    run_dir = _compacted(tmp_path)
    packed = run_dir / "normalized" / "endpoints.jsonl.zst"
    data = bytearray(packed.read_bytes())
    data[len(data) // 2] ^= 0xFF
    packed.write_bytes(bytes(data))
    _refused(run_dir, "endpoints.jsonl.zst does not match")


def test_refuses_a_file_of_the_compaction_block_that_is_gone(tmp_path):
    run_dir = _compacted(tmp_path)
    (run_dir / "ip_results.csv.zst").unlink()
    _refused(run_dir, "ip_results.csv.zst")


def test_refuses_when_a_table_the_analysis_reads_is_missing(tmp_path):
    run_dir = _compacted(tmp_path)
    m = _manifest(run_dir)
    rel = "normalized/hostname_resolution.jsonl.zst"       # gone, and no longer claimed by the manifest either
    (run_dir / rel).unlink()
    m["compaction"]["files"].pop(rel)
    _write_manifest(run_dir, m)
    _refused(run_dir, "hostname_resolution.jsonl is missing")


def test_a_plain_table_counts_as_present(tmp_path):
    run_dir = _compacted(tmp_path)
    packed = run_dir / "normalized" / "tool_jobs.jsonl.zst"
    (run_dir / "normalized" / "tool_jobs.jsonl").write_bytes(outputs.read_text(packed).encode("utf-8"))
    m = _manifest(run_dir)
    m["compaction"]["files"].pop("normalized/tool_jobs.jsonl.zst")
    packed.unlink()
    _write_manifest(run_dir, m)
    assert outputs.prune_raw(run_dir)["status"] == "pruned"


def test_a_compaction_entry_pointing_outside_the_run_is_refused(tmp_path):
    run_dir = _compacted(tmp_path)
    (tmp_path / "outside.zst").write_bytes(b"x")
    m = _manifest(run_dir)
    m["compaction"]["files"]["../outside.zst"] = {"sha256": hashlib.sha256(b"x").hexdigest()}
    _write_manifest(run_dir, m)
    _refused(run_dir, "outside the run")


def test_an_interrupted_removal_is_finished_by_the_next_call(tmp_path, monkeypatch):
    run_dir = _compacted(tmp_path)

    def fail(_path):
        raise PermissionError("in use")
    with monkeypatch.context() as patched:
        patched.setattr(shutil, "rmtree", fail)
        result = outputs.prune_raw(run_dir)
    assert result["status"] == "failed" and "in use" in result["reason"]
    leftover = run_dir / "raw.pruning"
    assert leftover.is_dir() and not (run_dir / "raw").exists()
    record = (run_dir / "raw_pruned.json").read_bytes()
    next(p for p in leftover.rglob("*") if p.is_file()).unlink()        # part of it went before the interruption
    assert outputs.prune_raw(run_dir)["status"] == "pruned"
    assert not leftover.exists() and (run_dir / "raw_pruned.json").read_bytes() == record


def test_a_crash_between_the_rename_and_the_record_still_leaves_a_record(tmp_path):
    run_dir = _compacted(tmp_path)
    (run_dir / "raw").rename(run_dir / "raw.pruning")
    assert outputs.prune_raw(run_dir)["status"] == "pruned" and not (run_dir / "raw.pruning").exists()
    assert json.loads((run_dir / "raw_pruned.json").read_text(encoding="utf-8"))["resumed"] is True


def test_a_leftover_directory_next_to_a_new_raw_is_not_touched(tmp_path):
    run_dir = _compacted(tmp_path)
    (run_dir / "raw.pruning").mkdir()
    assert outputs.prune_raw(run_dir)["status"] == "refused" and (run_dir / "raw").is_dir()


# ------------------------------------------------------------------ the command

def test_the_command_prunes_and_refuses(tmp_path, capsys):
    run_dir = _compacted(tmp_path)
    _edit_manifest(run_dir, complete=False)
    assert main(["prune-raw", str(run_dir)]) == 2
    assert "REFUSED: raw/ was not removed" in capsys.readouterr().err.splitlines()[-1] and (run_dir / "raw").is_dir()
    _edit_manifest(run_dir, complete=True)
    assert main(["prune-raw", str(run_dir)]) == 0 and not (run_dir / "raw").exists()
    assert main(["prune-raw", str(run_dir)]) == 0


def test_the_command_needs_a_run_directory():
    with pytest.raises(SystemExit):
        main(["prune-raw"])


# ------------------------------------------------------------------ the campaign option

def _cfg4(tmp_path, keep):
    return load_config(_cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 4},
                            output={"prune_raw_keep_every": keep} if keep is not None else None))


def _finished_with_raw(cfg, run_id, **kw):
    d = _finished_run(cfg, run_id, **kw)
    (d / "raw" / "zgrab2_a.jsonl.zst").write_bytes(b"raw output")
    for name in ("hostname_resolution", "tool_jobs", "policy_refusals"):
        (d / "normalized" / f"{name}.jsonl").write_text("{}\n")
    outputs.compact_run(d, log=lambda *_: None)            # what the pipeline does when a shard ends
    return d


def _raw_present(result):
    state = json.loads(Path(result["state_file"]).read_text())
    return {int(i): (Path(e["run_dir"]) / "raw").is_dir() for i, e in state["shard_states"].items()}


def test_keep_every_two_removes_raw_of_the_other_shards(tmp_path):
    logged = []
    result = campaign.run_campaign(_cfg4(tmp_path, 2), run_fn=_finished_with_raw, log=logged.append)
    assert result["complete"] and _raw_present(result) == {0: True, 1: False, 2: True, 3: False}
    assert sum("removed raw/" in line for line in logged) == 2
    state = json.loads(Path(result["state_file"]).read_text())
    assert all(e["disk_bytes"] == outputs.tree_bytes(e["run_dir"]) for e in state["shard_states"].values())


def test_keep_every_one_keeps_every_shard(tmp_path):
    result = campaign.run_campaign(_cfg4(tmp_path, 1), run_fn=_finished_with_raw, log=lambda *_: None)
    assert all(_raw_present(result).values())


def test_nothing_is_pruned_by_default(tmp_path):
    cfg = _cfg4(tmp_path, None)
    assert cfg.prune_raw_keep_every == 0
    result = campaign.run_campaign(cfg, run_fn=_finished_with_raw, log=lambda *_: None)
    assert all(_raw_present(result).values())


def test_a_refusal_is_logged_and_does_not_stop_the_campaign(tmp_path):
    def with_stage_errors(c, run_id, **kw):
        d = _finished_with_raw(c, run_id, **kw)
        m = json.loads((d / "manifest.json").read_text())
        m["stage_errors"] = {"favicon": "x"}
        (d / "manifest.json").write_text(json.dumps(m))
        return d
    logged = []
    result = campaign.run_campaign(_cfg4(tmp_path, 2), run_fn=with_stage_errors, log=logged.append)
    assert result["complete"] and all(_raw_present(result).values())
    assert sum("kept raw/" in line and "stage errors" in line for line in logged) == 2
    assert not any("removed raw/" in line for line in logged)


def test_a_failing_prune_is_logged_and_the_campaign_goes_on(tmp_path, monkeypatch):
    def boom(_run_dir):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(outputs, "prune_raw", boom)
    logged = []
    result = campaign.run_campaign(_cfg4(tmp_path, 2), run_fn=_finished_with_raw, log=logged.append)
    assert result["complete"] and all(_raw_present(result).values())
    assert any("could not prune" in line and "disk on fire" in line for line in logged)


def test_a_resumed_campaign_prunes_the_shards_it_finds_complete(tmp_path):
    cfg = _cfg4(tmp_path, 2)
    campaign.run_campaign(replace(cfg, prune_raw_keep_every=0), run_fn=_finished_with_raw, log=lambda *_: None)
    result = campaign.run_campaign(cfg, run_fn=_finished_with_raw, log=lambda *_: None)
    assert _raw_present(result) == {0: True, 1: False, 2: True, 3: False}


# ------------------------------------------------------------------ the configuration

def test_the_option_is_off_by_default_and_validated(tmp_path):
    assert load_config(write_config(tmp_path, output={"dir": str(tmp_path / "out")})).prune_raw_keep_every == 0
    for i, bad in enumerate((-1, "5", True, 1.5)):
        with pytest.raises(ConfigError, match="prune_raw_keep_every"):
            _config(tmp_path / f"bad{i}", prune_raw_keep_every=bad)
    assert _config(tmp_path / "ok", prune_raw_keep_every=50).prune_raw_keep_every == 50


def test_a_config_without_the_key_keeps_its_checksum(tmp_path):
    cfg = load_config(write_config(tmp_path, output={"dir": str(tmp_path / "out")}))
    assert "prune_raw_keep_every" not in cfg.raw["output"]
    from scanner.internet.config import _without_host_derived
    digest = lambda raw: hashlib.sha256(json.dumps(_without_host_derived(raw), sort_keys=True, default=str).encode()).hexdigest()
    assert cfg.checksum == digest(cfg.raw)
    without = {k: v for k, v in cfg.raw.items()}
    without["output"] = {**cfg.raw["output"], "prune_raw_keep_every": 0}      # only a key that is written changes the checksum
    assert digest(without) != cfg.checksum
