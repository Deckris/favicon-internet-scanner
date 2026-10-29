"""The facts store and the streaming write-out: memory does not grow with the shard, the work files stay out of the outputs."""
import gc
import json
import tracemalloc
from pathlib import Path

from scanner.internet import favicon as fav
from scanner.internet import icon_store, pipeline
from scanner.internet.config import load_config
from scanner.internet.shardstore import ShardStore
from tests.bench_scale_memory import BenchFetcher, build_tools
from tests.helpers import FakeFetcher, write_config
from tests.test_pipeline import tools


def _run(tmp_path, n=None, **over):
    cfg = load_config(write_config(tmp_path))
    ft = build_tools(n) if n else tools(**over)
    fetcher = BenchFetcher() if n else FakeFetcher()
    return pipeline.run(cfg, run_id="t1", executor=ft, fetcher=fetcher, skip_preflight=True, offline_preflight=True)


def _peak_mib(tmp_path, n):
    gc.collect()
    tracemalloc.start()
    try:
        _run(tmp_path, n)
        return tracemalloc.get_traced_memory()[1] / 1048576
    finally:
        tracemalloc.stop()


def test_peak_memory_does_not_grow_with_the_shard(tmp_path_factory):
    small = _peak_mib(tmp_path_factory.mktemp("small"), 500)
    large = _peak_mib(tmp_path_factory.mktemp("large"), 2000)
    # four times the addresses; holding every stage's results (about 50 KiB per address) would give 100 MiB here
    assert large < 2.0 * small and large < 40, (small, large)


def test_work_files_are_removed_after_a_complete_write_out(tmp_path):
    run_dir = _run(tmp_path)
    assert not (run_dir / "work").exists()
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert not [k for k in manifest["output_checksums"] if k.startswith("work/")]


def test_work_files_are_kept_but_not_listed_after_a_failed_write_out(tmp_path, monkeypatch):
    def broken(*args, **kw):
        raise RuntimeError("row builder broke")
    monkeypatch.setattr(pipeline, "_ip_rows", broken)
    run_dir = _run(tmp_path)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert "records" in manifest["stage_errors"] and not manifest["complete"]
    assert (run_dir / "work" / "facts.sqlite").is_file()
    assert not [k for k in manifest["output_checksums"] if k.startswith("work/")]


def test_streamed_files_are_checksummed_as_written(tmp_path):
    run_dir = _run(tmp_path)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    for rel in ("normalized/endpoints.jsonl", "normalized/hostname_resolution.jsonl", "ip_results.csv"):
        assert manifest["output_checksums"][rel] == pipeline.sha256_file(run_dir / rel)


def _records():
    out = []
    for i in range(60):
        out.append({"ip": f"192.0.2.{i % 30}", "port": 443 if i % 2 else 80, "scheme": "https", "hostname": None if i % 3 else f"h{i}.test",
                    "url": f"https://192.0.2.{i % 30}/", "document_title": "t", "favicon_is_image": i % 7 != 0,
                    "favicon_sha256": f"{i % 4:064x}", "favicon_bytes": 10, "favicon_mmh3": 1, "favicon_md5": "m",
                    "favicon_content_type": "image/png", "favicon_url": "https://x/f.png"})
    return out


def test_spooled_icon_index_equals_the_in_memory_index(tmp_path):
    recs = _records()
    for name, spool in (("mem", None), ("disk", tmp_path / "spool.sqlite")):
        store = icon_store.IconStore(tmp_path / name / "favicons")
        for sha in {r["favicon_sha256"] for r in recs}:
            store.save(sha, b"\x89PNG\r\n\x1a\n" + sha.encode())
        assert store.write_index(iter(recs), spool=spool) == 4
    assert (tmp_path / "mem" / "favicons" / "index.jsonl").read_bytes() == (tmp_path / "disk" / "favicons" / "index.jsonl").read_bytes()
    assert not (tmp_path / "spool.sqlite").exists()


def test_favicon_stage_hands_every_record_to_the_sink(monkeypatch):
    def probe(fetcher, *, scheme, ip, port, hostname, max_icons, icon_store=None):
        return {"favicon_outcome": "none_declared"}
    monkeypatch.setattr(fav, "probe_identity", probe)
    jobs = [{"scheme": "http", "ip": f"192.0.2.{i}", "port": 80, "hostname": None} for i in range(1, 6)]
    earlier = {("192.0.2.1", 80, None): {"ip": "192.0.2.1", "port": 80, "hostname": None, "favicon_outcome": "image"}}
    got = {}
    out = fav.run_favicon_stage(None, jobs, workers=3, max_icons=2, done=earlier, record_sink=lambda i, rec: got.__setitem__(i, rec))
    assert out == [] and sorted(got) == [0, 1, 2, 3, 4]
    assert got[0]["favicon_outcome"] == "image" and got[4]["favicon_outcome"] == "none_declared"


def test_favicon_records_resumed_from_the_log_reach_the_outputs(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    first = _run(tmp_path / "a")
    cfg = load_config(write_config(tmp_path / "b"))
    log = Path(cfg.output_dir) / "t1" / "raw"
    log.mkdir(parents=True)
    (log / "favicon_records.jsonl").write_text((first / "raw" / "favicon_records.jsonl").read_text(encoding="utf-8"), encoding="utf-8")

    class Refuse(FakeFetcher):
        def fetch(self, *a, **kw):
            raise AssertionError("fetched again")
    again = pipeline.run(cfg, run_id="t1", executor=tools(), fetcher=Refuse(), skip_preflight=True, offline_preflight=True)
    for rel in ("normalized/endpoints.jsonl", "normalized/hostname_resolution.jsonl"):
        assert (again / rel).read_bytes() == (first / rel).read_bytes()


def test_store_tracks_a_late_favicon_record_by_job_position(tmp_path):
    with ShardStore(tmp_path / "s.sqlite", reset=True) as s:
        s.put_endpoints([("192.0.2.1", 80)])
        s.put_favicon(5, {"ip": "192.0.2.1", "port": 80, "hostname": None, "favicon_outcome": "a"})
        s.put_favicon(2, {"ip": "192.0.2.1", "port": 80, "hostname": None, "favicon_outcome": "b"})
        assert [r["favicon_outcome"] for r in s.iter_favicons()] == ["a"]
