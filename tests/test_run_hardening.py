"""Stop latency, favicon deadline, store failures, resume across attempts and the raw/index files of failed steps."""
import hashlib
import json
import time
from types import SimpleNamespace

import pytest

from scanner import zdns_runner
from scanner.internet import favicon as fav
from scanner.internet import icon_store, outputs, pipeline, preflight
from scanner.internet.config import load_config
from scanner.internet.shardstore import ShardStore
from tests.helpers import FakeFetcher, write_config
from tests.test_pipeline import go, overlap_cfg, tools


# ---------------------------------------------------------------- kill file behind a slow egress lookup

def _guard_cfg(tmp_path):
    return SimpleNamespace(shard=0, shards=1, egress_check_seconds=1, kill_switch_file=str(tmp_path / "STOP"), approval=None,
                           min_free_mib=16, stall_minutes=0, vantage=SimpleNamespace(public_egress_ip="203.0.113.5"))


def test_kill_file_is_seen_while_the_egress_lookup_is_slow(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "MONITOR_TICK", 0.05)
    entered = []

    def slow(_cfg, timeout=6.0):
        entered.append(1)
        time.sleep(3)
        return "203.0.113.5"
    monkeypatch.setattr(preflight, "current_egress", slow)
    st = pipeline._Stages(_guard_cfg(tmp_path), tmp_path, guards=True)
    st._next_egress = time.monotonic()
    st.start_monitor()
    try:
        deadline = time.monotonic() + 2
        while not entered and time.monotonic() < deadline:
            time.sleep(0.01)
        assert entered                              # the guard thread is inside the slow lookup
        t0 = time.monotonic()
        (tmp_path / "STOP").write_text("x")
        while not st.killed() and time.monotonic() - t0 < 2.5:
            time.sleep(0.01)
        assert st.reason == "kill_switch" and time.monotonic() - t0 < 1.0
    finally:
        monkeypatch.setattr(preflight, "current_egress", lambda *a, **k: "203.0.113.5")
        st.stop_monitor()


def test_guard_thread_still_stops_the_run_when_the_egress_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "MONITOR_TICK", 0.05)
    monkeypatch.setattr(preflight, "current_egress", lambda *a, **k: "198.51.100.1")
    st = pipeline._Stages(_guard_cfg(tmp_path), tmp_path, guards=True)
    st._next_egress = time.monotonic()
    st.start_monitor()
    try:
        t0 = time.monotonic()
        while not st.killed() and time.monotonic() - t0 < 3:
            time.sleep(0.01)
        assert st.reason == "egress_changed"
    finally:
        st.stop_monitor()


# ---------------------------------------------------------------- favicon deadline reaches the fetcher and the pacer

def test_fetcher_and_pacer_see_the_stage_deadline(tmp_path, monkeypatch):
    seen = {}

    def fake_make(cfg, fp, resolver, endpoints, **kw):
        seen.update(kw)
        return FakeFetcher()
    monkeypatch.setattr(fav, "make_fetcher", fake_make)
    cfg = load_config(write_config(tmp_path, favicon={"enabled": True, "max_hostnames_per_endpoint": 3, "workers": 2,
                                                      "max_icons_per_page": 4, "stage_max_seconds": 1}))
    pipeline.run(cfg, run_id="t1", executor=tools(), skip_preflight=True, offline_preflight=True)
    time.sleep(1.2)
    assert seen["killed"]() is True                 # the stage deadline has passed
    pacer = seen["pacer"]
    pacer.min_interval = 5.0
    pacer._next["9.9.9.9"] = time.monotonic() + 60
    assert pacer.wait("9.9.9.9") is False           # a pacer waiting for its slot gives up as well


# ---------------------------------------------------------------- store failures stop the target-facing stages

class _LossyStore(ShardStore):
    def put_synack_port(self, port, fields_by_ip):
        super().put_synack_port(port, fields_by_ip)
        self.dropped_rows += 1
        self.errors.append("OperationalError: disk I/O error")


def _assert_nothing_contacted(run_dir, ft, fetcher):
    assert ft.zgrab_ips == [] and fetcher.calls == []
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["complete"] is False and "store" in m["stage_errors"]
    assert {"http_direct", "sni_confirm", "favicon"} <= set(m["stages_skipped"])
    return m


def test_store_loss_stops_before_the_target_facing_stages(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "ShardStore", _LossyStore)
    ft, fetcher = tools(), FakeFetcher()
    run_dir = go(load_config(write_config(tmp_path)), ft, fetcher=fetcher)
    m = _assert_nothing_contacted(run_dir, ft, fetcher)
    assert "tls_direct" in m["stages_skipped"]


def test_store_loss_during_overlap_stops_the_overlapped_handshakes(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "ShardStore", _LossyStore)
    ft, fetcher = tools(), FakeFetcher()
    run_dir = go(overlap_cfg(tmp_path), ft, fetcher=fetcher)
    _assert_nothing_contacted(run_dir, ft, fetcher)


def test_unreadable_tarpit_list_in_overlap_stops_later_stages(tmp_path, monkeypatch):
    class NoTarpits(ShardStore):
        calls = 0

        def tarpit_ips(self, tiny):
            NoTarpits.calls += 1
            if NoTarpits.calls > 3:                 # the per-port lookups of the overlapped handshakes work; the final one fails
                raise RuntimeError("unreadable")
            return super().tarpit_ips(tiny)
    monkeypatch.setattr(pipeline, "ShardStore", NoTarpits)
    fetcher = FakeFetcher()
    run_dir = go(overlap_cfg(tmp_path), tools(), fetcher=fetcher)
    m = json.loads((run_dir / "manifest.json").read_text())
    assert fetcher.calls == [] and m["complete"] is False
    assert {"http_direct", "sni_confirm", "favicon"} <= set(m["stages_skipped"])


# ---------------------------------------------------------------- ip_results is not written from a failed write-out

def test_ip_results_is_skipped_when_the_records_failed(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(pipeline, "_write_records", boom)
    run_dir = go(load_config(write_config(tmp_path)), tools())
    m = json.loads((run_dir / "manifest.json").read_text())
    assert not (run_dir / "ip_results.csv").exists()
    assert "not written" in m["stage_errors"]["ip_results"] and m["complete"] is False


# ---------------------------------------------------------------- resume from an earlier attempt

def test_favicon_lookups_of_an_earlier_attempt_are_not_sent_again(tmp_path):
    cfg = load_config(write_config(tmp_path))
    first = pipeline.run(cfg, run_id="t1", executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)
    log = first / "raw" / "favicon_records.jsonl"
    n = len(log.read_text().splitlines())
    assert n > 0
    with log.open("a") as fh:           # a lookup of an address that is not in the second attempt's jobs
        fh.write(json.dumps({"ip": "9.9.9.9", "port": 80, "hostname": None, "favicon_outcome": "image"}) + "\n")
    fetcher = FakeFetcher()
    second = pipeline.run(cfg, run_id="t1-a2", executor=tools(), fetcher=fetcher, skip_preflight=True, offline_preflight=True,
                          resume_from=first)
    assert fetcher.calls == []
    m = json.loads((second / "manifest.json").read_text())
    assert m["stage_counts"]["favicon_lookups_resumed"] == n
    again = [json.loads(line) for line in (second / "raw" / "favicon_records.jsonl").read_text().splitlines()]
    assert len(again) == n and all(r["ip"] != "9.9.9.9" for r in again)
    name = "hostname_resolution.jsonl"
    assert (first / "normalized" / name).read_text() == (second / "normalized" / name).read_text()


def test_resume_from_a_missing_attempt_is_ignored(tmp_path):
    cfg = load_config(write_config(tmp_path))
    fetcher = FakeFetcher()
    run_dir = pipeline.run(cfg, run_id="t1", executor=tools(), fetcher=fetcher, skip_preflight=True, offline_preflight=True,
                           resume_from=tmp_path / "nowhere")
    assert fetcher.calls
    assert "favicon_lookups_resumed" not in json.loads((run_dir / "manifest.json").read_text())["stage_counts"]


# ---------------------------------------------------------------- tool crash leaves a readable raw file

@pytest.mark.skipif(outputs.zstandard is None, reason="zstandard not installed")
def test_failed_tool_call_leaves_a_valid_empty_compressed_file(tmp_path):
    def crash(command, **kw):
        raise OSError("no such binary")
    jobs, _answers = zdns_runner.run_zdns("PTR", ["192.0.2.1"], nameservers=["9.9.9.9"], run_dir=tmp_path, threads=1, timeout=1,
                                          retries=1, network_timeout=1, binary="zdns", executor=crash)
    assert jobs and jobs[0].error
    for job in jobs:
        path = tmp_path / job.raw_path
        assert outputs.is_compressed(path) and list(outputs.iter_lines(path)) == []
        assert hashlib.sha256(path.read_bytes()).hexdigest() == job.raw_sha256


# ---------------------------------------------------------------- lone surrogate in an index entry

@pytest.mark.parametrize("spool", [False, True])
def test_index_survives_a_lone_surrogate_in_a_hostname(tmp_path, spool):
    store = icon_store.IconStore(tmp_path / "favicons")
    store.save("a" * 64, b"\x89PNG\r\n\x1a\nxx")
    recs = [{"favicon_sha256": "a" * 64, "favicon_is_image": True, "ip": "1.1.1.1", "port": 443, "scheme": "https",
             "hostname": "bad\ud800.test", "url": "https://bad\ud800.test/", "document_title": "t\udc80"}]
    n = store.write_index(iter(recs), spool=tmp_path / "spool.sqlite" if spool else None)
    assert n == 1
    entry = json.loads((tmp_path / "favicons" / "index.jsonl").read_text(encoding="utf-8"))
    assert entry["observations"][0]["hostname"] == "bad?.test" and entry["observations"][0]["page_title"] == "t?"
