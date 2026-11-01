"""Compacted outputs: the .zst record files of a shard that finished cleanly."""
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from scanner.internet import campaign, favicon as fav, outputs, pipeline, refetch
from scanner.internet.__main__ import main
from scanner.internet.config import ConfigError, load_config
from tests.helpers import FakeFetcher, write_config
from tests.test_pipeline import go, tools
from tests.test_scale import _cfg

needs_zstd = pytest.mark.skipif(outputs.zstandard is None, reason="zstandard not installed")


def _config(tmp_path, compact=True, **output):
    tmp_path.mkdir(parents=True, exist_ok=True)
    return load_config(write_config(tmp_path, output={"dir": str(tmp_path / "out"), "compact": compact, **output}))


def _files(run_dir):
    return {p.relative_to(run_dir).as_posix() for p in Path(run_dir).rglob("*") if p.is_file()}


def _content(run_dir, rel):
    return outputs.read_text(Path(run_dir) / rel)


def _snapshot(run_dir):
    """Content of every record file of a run that has not been compacted yet."""
    return {rel: (Path(run_dir) / rel).read_bytes() for rel in sorted(_files(run_dir))
            if any(Path(rel).match(g) for g in outputs.COMPACT_GLOBS)}


def _manifest(run_dir):
    return json.loads((Path(run_dir) / "manifest.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------------ configuration

def test_compaction_is_on_by_default_and_has_a_switch(tmp_path):
    assert load_config(write_config(tmp_path, output={"dir": str(tmp_path / "out")})).compact_outputs is True
    assert _config(tmp_path / "off", compact=False).compact_outputs is False
    with pytest.raises(ConfigError, match="output.compact"):
        _config(tmp_path / "bad", compact="yes")


# ------------------------------------------------------------------ round trip

@needs_zstd
def test_a_finished_run_is_compacted_and_the_manifest_describes_every_file(tmp_path):
    packed = go(_config(tmp_path), tools())
    m = _manifest(packed)
    files = m["compaction"]["files"]
    assert m["compaction"]["zstd_level"] == outputs.COMPACT_LEVEL
    assert {"normalized/endpoints.jsonl.zst", "normalized/hostname_resolution.jsonl.zst", "normalized/tool_jobs.jsonl.zst",
            "raw/favicon_records.jsonl.zst", "ip_results.csv.zst"} <= set(files)
    assert not [f for f in _files(packed) if f.endswith(".tmp")]
    for key, rec in files.items():
        rel = key[:-4]
        assert not (packed / rel).exists() and (packed / key).is_file()
        stored = (packed / key).read_bytes()
        content = outputs.open_binary(packed / key).read()
        assert rec == {"sha256": hashlib.sha256(stored).hexdigest(), "content_sha256": hashlib.sha256(content).hexdigest(),
                       "bytes": len(stored), "content_bytes": len(content)}
        assert m["output_checksums"][key] == rec["sha256"] and rel not in m["output_checksums"]


@needs_zstd
def test_the_content_survives_compaction_byte_for_byte(tmp_path):
    run_dir = go(_config(tmp_path, compact=False), tools())
    original = _snapshot(run_dir)
    checksums = _manifest(run_dir)["output_checksums"]
    assert "compaction" not in _manifest(run_dir) and not [f for f in _files(run_dir) if f.startswith("normalized") and f.endswith(".zst")]
    assert outputs.compact_run(run_dir)["status"] == "compacted"
    files = _manifest(run_dir)["compaction"]["files"]
    for rel, data in original.items():
        assert outputs.open_binary(run_dir / rel).read() == data
        assert files[rel + ".zst"]["content_sha256"] == checksums[rel] == hashlib.sha256(data).hexdigest()


@needs_zstd
def test_compacting_twice_changes_nothing(tmp_path):
    run_dir = go(_config(tmp_path), tools())
    before = (run_dir / "manifest.json").read_bytes()
    assert outputs.compact_run(run_dir)["status"] == "unchanged"
    assert (run_dir / "manifest.json").read_bytes() == before


# ------------------------------------------------------------------ readers

@needs_zstd
def test_readers_take_a_compacted_run_like_a_plain_one(tmp_path):
    cfg = _config(tmp_path, compact=False)
    run_dir = go(cfg, tools())

    def readings():
        out = tmp_path / "hostnames.csv"
        assert main(["export-csv", str(run_dir), "--out", str(out)]) == 0
        return {"hostnames": list(outputs.iter_hostname_rows(run_dir)), "endpoints": list(outputs.iter_endpoint_rows(run_dir)),
                "csv": out.read_bytes(), "source": refetch.load_source(run_dir, cfg)[1:],
                "plan": refetch.plan(cfg, run_dir, all_jobs=True)["jobs_to_run"],
                "lookups": fav.RecordLog(run_dir / "raw" / "favicon_records.jsonl").load()}
    before = readings()
    assert before["csv"] and before["plan"] > 0 and before["lookups"]
    assert outputs.compact_run(run_dir)["status"] == "compacted"
    assert not (run_dir / "raw" / "favicon_records.jsonl").exists() and outputs.is_compressed(outputs.resolve(run_dir / "ip_results.csv"))
    assert readings() == before


@needs_zstd
def test_a_run_resumes_from_a_compacted_attempt(tmp_path):
    cfg = _config(tmp_path)
    first = go(cfg, tools())
    assert not (first / "raw" / "favicon_records.jsonl").exists()
    n = len(outputs.read_text(first / "raw" / "favicon_records.jsonl").splitlines())
    assert n > 0
    fetcher = FakeFetcher()
    second = pipeline.run(cfg, run_id="t1-a2", executor=tools(), fetcher=fetcher, skip_preflight=True, offline_preflight=True,
                          resume_from=first)
    assert fetcher.calls == []
    assert _manifest(second)["stage_counts"]["favicon_lookups_resumed"] == n


@needs_zstd
def test_the_campaign_resume_source_finds_a_compressed_lookup_log(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    d = Path(cfg.output_dir) / campaign._run_id(cfg, 1, 1)
    (d / "raw").mkdir(parents=True)
    (d / "manifest.json").write_text(json.dumps({"complete": False, "zero_responsive": False, "config_checksum": cfg.checksum}))
    (d / "raw" / "favicon_records.jsonl.zst").write_bytes(outputs.compress_bytes(b"{}\n"))
    assert campaign.resume_source(cfg, 1, campaign._run_id(cfg, 1, 2)) == d


# ------------------------------------------------------------------ crashes

class Crash(BaseException):
    """Stands for the process dying at that point."""


def _unfinished_compaction(tmp_path, monkeypatch, where):
    """A finished, uncompacted run whose compaction was stopped at ``where``; returns the run and its original files."""
    run_dir = go(_config(tmp_path, compact=False), tools())
    original = _snapshot(run_dir)
    stray = run_dir / "normalized" / "endpoints.jsonl.zst.tmp"
    stray.write_bytes(b"left over from an earlier crash")
    calls = []

    def boom(*_a, **_k):
        calls.append(1)
        if where == "rename" or (where == "after rename" and len(calls) == 1) or (where == "after delete" and len(calls) == 2):
            raise Crash()
    if where == "rename":
        monkeypatch.setattr(outputs.os, "replace", boom)
    else:
        monkeypatch.setattr(outputs, "_fsync_dir", boom)
    with pytest.raises(Crash):
        outputs.compact_run(run_dir)
    monkeypatch.undo()
    return run_dir, original


@needs_zstd
@pytest.mark.parametrize("where", ["rename", "after rename", "after delete"])
def test_a_crash_during_compaction_leaves_every_file_readable_and_the_next_call_finishes(tmp_path, monkeypatch, where):
    run_dir, original = _unfinished_compaction(tmp_path, monkeypatch, where)
    for rel, data in original.items():                    # either the plain or the verified compressed file, never neither
        assert outputs.exists(run_dir / rel), rel
        assert outputs.open_binary(run_dir / rel).read() == data
    csv_path = outputs.export_csv(run_dir, tmp_path / "mid.csv")
    assert csv_path.stat().st_size > 0
    assert "compaction" not in _manifest(run_dir)                      # the manifest is only rewritten at the very end
    assert outputs.compact_run(run_dir)["status"] == "compacted"
    assert not [f for f in _files(run_dir) if f.endswith(".tmp")]
    m = _manifest(run_dir)
    assert set(m["compaction"]["files"]) == {rel + ".zst" for rel in original}
    for rel, data in original.items():
        assert not (run_dir / rel).exists() and outputs.open_binary(run_dir / rel).read() == data
        rec = m["compaction"]["files"][rel + ".zst"]
        assert rec["content_sha256"] == hashlib.sha256(data).hexdigest() and rec["content_bytes"] == len(data)
        assert m["output_checksums"][rel + ".zst"] == hashlib.sha256((run_dir / (rel + ".zst")).read_bytes()).hexdigest()


@needs_zstd
def test_a_crash_before_the_manifest_is_rewritten_is_repaired_from_the_old_checksums(tmp_path, monkeypatch):
    run_dir = go(_config(tmp_path, compact=False), tools())
    original = _snapshot(run_dir)
    monkeypatch.setattr(outputs, "_write_manifest", lambda *_a, **_k: (_ for _ in ()).throw(Crash()))
    with pytest.raises(Crash):
        outputs.compact_run(run_dir)
    monkeypatch.undo()
    assert all(not (run_dir / rel).exists() and (run_dir / (rel + ".zst")).exists() for rel in original)
    assert "compaction" not in _manifest(run_dir)
    assert list(outputs.iter_hostname_rows(run_dir))                   # readable in that state
    assert outputs.compact_run(run_dir)["status"] == "compacted"
    m = _manifest(run_dir)
    assert set(m["compaction"]["files"]) == {rel + ".zst" for rel in original}
    assert all(rel not in m["output_checksums"] for rel in original)


@needs_zstd
def test_a_copy_that_does_not_verify_is_discarded_and_the_original_kept(tmp_path, monkeypatch):
    run_dir = go(_config(tmp_path, compact=False), tools())
    original = _snapshot(run_dir)
    real = outputs._sha256_stream

    def wrong(path, *, compressed):
        digest, size = real(path, compressed=compressed)
        return ("0" * 64, size) if compressed else (digest, size)
    monkeypatch.setattr(outputs, "_sha256_stream", wrong)
    result = outputs.compact_run(run_dir, log=lambda *_: None)
    assert result["status"] == "unchanged" and set(result["failed"]) == set(original)
    assert _snapshot(run_dir) == original
    assert not any((run_dir / (rel + ".zst")).exists() for rel in original) and not [f for f in _files(run_dir) if f.endswith(".tmp")]
    assert "compaction" not in _manifest(run_dir)


@needs_zstd
def test_a_file_that_differs_from_the_manifest_is_not_compacted(tmp_path):
    run_dir = go(_config(tmp_path, compact=False), tools())
    target = run_dir / "normalized" / "endpoints.jsonl"
    target.write_bytes(target.read_bytes() + b"{}\n")
    result = outputs.compact_run(run_dir, log=lambda *_: None)
    assert "normalized/endpoints.jsonl" in result["failed"] and target.exists()
    assert not (run_dir / "normalized" / "endpoints.jsonl.zst").exists()
    assert (run_dir / "normalized" / "hostname_resolution.jsonl.zst").exists()      # the others went through


# ------------------------------------------------------------------ shards that did not finish cleanly

@needs_zstd
def test_an_aborted_shard_keeps_its_plain_files(tmp_path):
    cfg = _config(tmp_path)
    ft = tools()
    orig = ft._zmap

    def zmap_then_kill(c):
        out = orig(c)
        Path(cfg.kill_switch_file).write_text("stop")
        return out
    ft._zmap = zmap_then_kill
    run_dir = go(cfg, ft)
    m = _manifest(run_dir)
    assert m["abort_reason"] == "kill_switch" and not m["complete"]
    before = _snapshot(run_dir)
    assert before and "compaction" not in m
    assert not any((run_dir / (rel + ".zst")).exists() for rel in before)
    assert outputs.compact_run(run_dir)["status"] == "skipped" and _snapshot(run_dir) == before


@needs_zstd
def test_a_shard_with_no_responsive_endpoint_keeps_its_plain_files(tmp_path):
    run_dir = go(_config(tmp_path), tools(l4={}))
    assert _manifest(run_dir)["zero_responsive"] is True
    assert (run_dir / "normalized" / "endpoints.jsonl").exists() and "compaction" not in _manifest(run_dir)


@needs_zstd
def test_compaction_can_be_switched_off(tmp_path):
    run_dir = go(_config(tmp_path, compact=False), tools())
    assert (run_dir / "normalized" / "endpoints.jsonl").exists() and "compaction" not in _manifest(run_dir)


def test_the_compact_command_refuses_a_run_that_did_not_finish(tmp_path, capsys):
    run_dir = tmp_path / "run"
    (run_dir / "normalized").mkdir(parents=True)
    (run_dir / "normalized" / "endpoints.jsonl").write_text("{}\n")
    (run_dir / "manifest.json").write_text(json.dumps({"status": "finished", "complete": False, "abort_reason": "stalled"}))
    assert main(["compact", str(run_dir)]) == 2
    assert (run_dir / "normalized" / "endpoints.jsonl").exists()


@needs_zstd
def test_the_compact_command_compacts_a_finished_run(tmp_path):
    run_dir = go(_config(tmp_path, compact=False), tools())
    assert main(["compact", str(run_dir)]) == 0
    assert not (run_dir / "normalized" / "endpoints.jsonl").exists() and outputs.exists(run_dir / "normalized" / "endpoints.jsonl")


# ------------------------------------------------------------------ campaign: compaction

def _finished_run(cfg, run_id, **_kw):
    """run_fn double that writes a small, finished run with the record files."""
    d = Path(cfg.output_dir) / run_id
    for sub in ("report", "raw", "normalized"):
        (d / sub).mkdir(parents=True)
    (d / "normalized" / "endpoints.jsonl").write_text('{"target_ip": "192.0.2.1", "port": 443}\n' * 50)
    (d / "ip_results.csv").write_text("ip,responsive\n192.0.2.1,yes\n")
    (d / "manifest.json").write_text(json.dumps({
        "status": "finished", "complete": True, "abort_reason": None, "zero_responsive": False, "stage_errors": {}, "elapsed_seconds": 1.0,
        "config_checksum": cfg.checksum, "shard": {"index": cfg.shard}, "output_checksums": {}}))
    (d / "report" / "summary.json").write_text("{}")
    return d


@needs_zstd
def test_a_resumed_campaign_completes_a_compaction_that_was_interrupted(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    campaign.run_campaign(replace(cfg, compact_outputs=False), run_fn=_finished_run, log=lambda *_: None)
    runs = sorted(Path(cfg.output_dir).glob("scanner-*"))
    assert len(runs) == 3 and all((r / "normalized" / "endpoints.jsonl").exists() for r in runs)
    result = campaign.run_campaign(replace(cfg, compact_outputs=True), run_fn=_finished_run, log=lambda *_: None)
    assert result["complete"]
    for r in runs:
        assert not (r / "normalized" / "endpoints.jsonl").exists() and (r / "normalized" / "endpoints.jsonl.zst").exists()
        assert _manifest(r)["compaction"]["files"]["ip_results.csv.zst"]["content_bytes"] > 0
    state = json.loads(Path(result["state_file"]).read_text())
    assert all(e["disk_bytes"] == outputs.tree_bytes(e["run_dir"]) for e in state["shard_states"].values())


def test_a_shard_that_finished_before_the_state_file_heard_of_it_is_not_repeated(tmp_path):
    cfg = load_config(_cfg(tmp_path))
    calls = []

    def run_fn(c, *, run_id, **kw):
        calls.append(c.shard)
        d = _finished_run(c, run_id)
        if len(calls) == 1:
            raise KeyboardInterrupt            # the process was stopped while it compacted the finished shard
        return d
    with pytest.raises(KeyboardInterrupt):
        campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)
    assert campaign.run_campaign(cfg, run_fn=run_fn, log=lambda *_: None)["complete"] and calls == [0, 1, 2]
