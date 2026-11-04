"""Request times, per-batch tool statistics and run identity: what an analysis needs to judge the age and load of a row."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
import yaml

from scanner.internet import favicon as fav
from scanner.internet import outputs, pipeline, tls
from scanner.internet.config import ConfigError, load_config
from scanner.internet.runner import zgrab_batch_stats
from scanner.internet.shardstore import ShardStore
from scanner.internet.zmap_compat import response_fields
from scanner.zdns_runner import parse_zdns_line, resolve
from scanner.zgrab_runner import _parse_line
from scanner.zmap_runner import sweep_stats
from tests.helpers import FIX, HTTP_STAMP, FakeFetcher, write_config
from tests.test_pipeline import IP_HTTP, IP_OK, go, rows_of, tools

FROZEN = "2026-10-04T18:00:00+00:00"        # conftest fixes the favicon stage's clock to this


def _endpoint(run_dir: Path, ip: str, port: int) -> dict:
    hits = [r for r in outputs.iter_endpoint_rows(run_dir) if r["target_ip"] == ip and r["port"] == port]
    assert len(hits) == 1
    return hits[0]


def _run(tmp_path, **kw):
    ft = tools()
    ft.http_stamp = HTTP_STAMP
    ft.dns_stamp = "2026-10-04T19:52:53+02:00"
    return go(load_config(write_config(tmp_path, **kw)), ft), ft


# ------------------------------------------------------------------ request times

def test_every_stage_leaves_its_request_time_on_the_row(tmp_path):
    run_dir, ft = _run(tmp_path)
    ok = _endpoint(run_dir, IP_OK, 443)
    assert ok["l4_seen_at"] == "2026-10-04T17:52:40.123000+00:00"                 # ZMap's own response time
    assert ok["tls_at"] == "2026-10-04T17:52:45+00:00"                            # ZGrab2's, written with an offset, read as UTC
    assert ok["http_at"] is None                                                  # TLS answered, so no plain HTTP request was made
    assert ok["direct_favicon_at"] == FROZEN and ok["direct_document_captured_at"] == FROZEN   # fetched live by the favicon stage
    http = _endpoint(run_dir, IP_HTTP, 80)
    assert http["http_at"] == "2026-10-04T17:53:00+00:00"
    assert http["direct_document_source"] == "reused"
    assert http["direct_document_captured_at"] == "2026-10-04T17:53:00+00:00"     # the page is as old as the HTTP request, not the favicon stage
    assert http["direct_document_age_seconds"] is not None                        # still there next to the absolute time

    rows = rows_of(run_dir)
    named = next(r for r in rows if r["target_ip"] == IP_OK and r["hostname"] == "good.test")
    assert named["dns_at"] == "2026-10-04T17:52:53+00:00"
    assert named["sni_at"] == "2026-10-04T17:52:45+00:00"
    assert named["hostname_favicon_at"] == FROZEN and named["hostname_document_captured_at"] == FROZEN
    unnamed = next(r for r in rows if r["target_ip"] == IP_HTTP)
    assert unnamed["hostname"] is None and unnamed["dns_at"] is None and unnamed["sni_at"] is None
    assert not set(outputs.CONTEXT_FIELDS) - set(named)


def test_hostname_rows_keep_the_name_level_times_and_the_endpoint_rows_the_rest(tmp_path):
    run_dir, _ = _run(tmp_path)
    slim = list(outputs._jsonl(run_dir / "normalized" / "hostname_resolution.jsonl"))
    name_level = {"dns_at", "sni_at", "hostname_favicon_at", "hostname_document_captured_at"}
    assert name_level <= outputs.HOSTNAME_FIELDS and all(name_level <= set(r) for r in slim)
    assert not {"l4_seen_at", "tls_at", "http_at", "direct_favicon_at"} & set(slim[0])


def test_a_missing_timestamp_stays_missing(tmp_path):
    ft = tools()                                                                   # the fakes print no http or zdns timestamp
    run_dir = go(load_config(write_config(tmp_path)), ft)
    assert _endpoint(run_dir, IP_HTTP, 80)["http_at"] is None
    assert all(r["dns_at"] is None for r in rows_of(run_dir))


def test_zmap_asks_for_its_own_receive_time():
    assert response_fields("2.1.1").split(",") == ["saddr", "window", "ttl", "timestamp-str"]
    assert response_fields("4.4.0") == response_fields("2.1.1")
    with pytest.raises(ValueError):
        response_fields("3.0.0")


def test_zgrab_and_zdns_timestamps_are_read_from_their_lines():
    tls_line = (FIX / "zgrab_tls" / "ok.jsonl").read_text(encoding="utf-8").splitlines()[0]
    assert tls.parse_line(tls_line, port=443, sni=None, mode="direct_ip").requested_at == "2026-10-04T17:52:45+00:00"
    http = json.dumps({"ip": "192.0.2.1", "data": {"http": {"status": "success", "timestamp": "2026-10-04T19:53:00+02:00", "result": {}}}})
    assert _parse_line(http, job_id="J", scheme="http", mode="direct_ip", port=80, observed_at="x").requested_at == "2026-10-04T17:53:00+00:00"
    bare = json.dumps({"ip": "192.0.2.1", "data": {"http": {"status": "connection-timeout"}}})
    assert _parse_line(bare, job_id="J", scheme="http", mode="direct_ip", port=80, observed_at="x").requested_at is None
    dns_line = (FIX / "zdns" / "A_a.test.jsonl").read_text(encoding="utf-8").splitlines()[0]
    answer = parse_zdns_line(dns_line, "A")
    assert answer.queried_at == "2026-10-04T17:52:53+00:00"
    assert resolve("a.test", answer, None).queried_at == "2026-10-04T17:52:53+00:00"


# ------------------------------------------------------------------ favicon documents

def test_a_fetched_document_has_an_absolute_capture_time_and_no_age(monkeypatch):
    seen = iter(["2026-10-04T18:00:01+00:00", "2026-10-04T18:00:02+00:00"])
    monkeypatch.setattr(fav, "now_iso", lambda: next(seen))
    rec = fav.probe_identity(FakeFetcher(), scheme="https", ip="198.51.100.9", port=443, hostname=None, max_icons=2)
    assert rec["document_source"] == "fetched" and rec["document_age_seconds"] is None
    assert rec["captured_at"] == "2026-10-04T18:00:01+00:00"           # before the page request
    assert rec["favicon_at"] == "2026-10-04T18:00:02+00:00"            # before the first icon request


def test_a_reused_document_is_dated_by_the_http_stage():
    doc = {"http_status": 200, "content_type": "text/html", "content_encoding": None, "location": None, "body_bytes": 10,
           "captured_at": 1_790_000_000.0, "document_title": "t", "document_body_sha256": "a" * 64, "declarations": []}
    rec = fav.probe_identity(FakeFetcher(), scheme="http", ip="198.51.100.9", port=80, hostname=None, max_icons=2,
                             stored_document=doc, max_document_bytes=1_000_000)
    assert rec["document_source"] == "reused" and rec["captured_at"] == "2026-09-21T14:13:20+00:00"
    assert rec["document_age_seconds"] > 0           # the age stays next to the absolute time


def test_a_page_request_that_was_skipped_has_no_capture_time():
    class Busy(FakeFetcher):
        def fetch(self, url, *, connect_ip, kind, context=""):
            result, body = super().fetch(url, connect_ip=connect_ip, kind=kind, context=context)
            from dataclasses import replace
            return replace(result, outcome="skipped_network_busy", http_status=None), None
    rec = fav.probe_identity(Busy(), scheme="https", ip="198.51.100.9", port=443, hostname=None, max_icons=2)
    assert rec["favicon_outcome"] == "skipped_network_busy" and rec["captured_at"] is None and rec["favicon_at"] is None


# ------------------------------------------------------------------ per-batch tool statistics

def test_zgrab_batch_stats_sort_statuses():
    assert zgrab_batch_stats(["success", "success", "io-timeout", "connection-timeout", "connection-refused",
                              "connection-closed", "protocol-error", "no_output"]) == {
        "targets": 8, "success": 2, "timeout": 2, "connection_error": 2, "other": 2}
    assert zgrab_batch_stats([])["targets"] == 0


def test_zgrab_jobs_carry_their_outcome_counts(tmp_path):
    run_dir, _ = _run(tmp_path)
    jobs = [json.loads(line) for line in outputs.iter_lines(run_dir / "normalized" / "tool_jobs.jsonl")]
    grabs = [j for j in jobs if j["tool"] == "zgrab2"]
    assert grabs
    for j in grabs:
        s = j["stats"]
        assert s["targets"] == j["output_count"] == s["success"] + s["timeout"] + s["connection_error"] + s["other"]
    direct = next(j for j in grabs if j["purpose"] == "tls:direct_ip:port=443")
    assert direct["stats"]["success"] == 2 and direct["stats"]["other"] == 1        # ok, ok, strict-SNI handshake failure
    plain = next(j for j in grabs if j["purpose"].startswith("direct_ip:http"))
    assert plain["stats"]["targets"] == plain["output_count"] and plain["stats"]["success"] >= 1


def test_zmap_stats_from_the_status_file_and_from_stderr(tmp_path):
    status = tmp_path / "status.csv"
    status.write_text("real-time,time-elapsed,sent-total,recv-success-total,recv-total,pcap-drop-total,sendto-fail-total\n"
                      "a,1,100,2,3,0,0\nb,2,250,5,9,4,1\n", encoding="utf-8")
    assert sweep_stats(status, "") == {"sent": 250, "received": 9, "received_success": 5, "dropped": 4, "send_failed": 1}
    line = "Nov 04 12:00:00.000 [INFO] monitor: 0:08 100% (0s left); send: 4096 done (500 Kp/s avg); recv: 17 (2 p/s avg); drops: 3 (0 p/s avg); hitrate: 0.41%"
    assert sweep_stats(None, "noise\n" + line + "\n") == {"sent": 4096, "received": 17, "dropped": 3}
    assert sweep_stats(tmp_path / "absent.csv", line)["sent"] == 4096
    assert sweep_stats(None, "zmap boom") is None
    status.write_text("real-time,sent-total\n", encoding="utf-8")                   # a header and no reading yet
    assert sweep_stats(status, "") is None


def test_zmap_jobs_take_their_counts_from_stderr(tmp_path):
    ft = tools()
    plain = ft._zmap

    def with_summary(c):
        res = plain(c)
        if "--dryrun" not in c:
            res.stderr = "monitor: 100% (0s left); send: 77 done (1 Kp/s avg); recv: 5 (1 p/s avg); drops: 0 (0 p/s avg)"
        return res
    ft._zmap = with_summary
    run_dir = go(load_config(write_config(tmp_path)), ft)
    jobs = [json.loads(line) for line in outputs.iter_lines(run_dir / "normalized" / "tool_jobs.jsonl")]
    assert [j["stats"] for j in jobs if j["tool"] == "zmap"] == [{"sent": 77, "received": 5, "dropped": 0}] * 3
    assert all(j["stats"] is None for j in jobs if j["tool"] == "zdns")


# ------------------------------------------------------------------ manifest

def test_manifest_names_the_epoch_and_the_resolvers(tmp_path):
    cfg = load_config(write_config(tmp_path))
    run_dir = go(cfg, tools())
    m = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert m["output_schema"] == outputs.OUTPUT_SCHEMA == 3
    assert m["epoch_id"] == cfg.checksum[:12] and m["config_checksum"].startswith(m["epoch_id"])
    assert m["resolvers"] == [{"address": "9.9.9.9:53"}, {"address": "1.1.1.1"}]       # no version unless asked for


def _dns_section(tmp_path, **extra) -> dict:
    base = yaml.safe_load(write_config(tmp_path).read_text(encoding="utf-8"))["dns"]
    return {**base, **extra}


def test_resolver_version_is_asked_only_when_enabled(tmp_path, monkeypatch):
    asked = []
    monkeypatch.setattr(pipeline, "query_resolver_version", lambda addr, timeout=5.0: asked.append(addr) or f"ver-{addr}")
    off = load_config(write_config(tmp_path))
    assert pipeline.resolver_identity(off) == [{"address": "9.9.9.9:53"}, {"address": "1.1.1.1"}] and not asked
    on = load_config(write_config(tmp_path, dns=_dns_section(tmp_path, query_resolver_version=True)))
    assert pipeline.resolver_identity(on) == [{"address": "9.9.9.9:53", "version": "ver-9.9.9.9:53"},
                                              {"address": "1.1.1.1", "version": "ver-1.1.1.1"}]
    assert asked == ["9.9.9.9:53", "1.1.1.1"]


def test_asking_for_the_version_does_not_change_the_epoch(tmp_path):
    off = load_config(write_config(tmp_path))
    on = load_config(write_config(tmp_path, dns=_dns_section(tmp_path, query_resolver_version=True)))
    assert on.dns.query_resolver_version and not off.dns.query_resolver_version
    assert on.checksum == off.checksum
    with pytest.raises(ConfigError, match="query_resolver_version"):
        load_config(write_config(tmp_path, dns=_dns_section(tmp_path, query_resolver_version="yes please")))


def test_a_silent_resolver_gives_no_version(monkeypatch):
    import dns.exception
    import dns.query

    def timeout(*a, **k):
        raise dns.exception.Timeout()
    monkeypatch.setattr(dns.query, "udp", timeout)
    assert pipeline.query_resolver_version("192.0.2.53:53", 0.1) is None


# ------------------------------------------------------------------ older runs

def test_older_runs_still_read_and_export(tmp_path):
    for schema in (1, 2):
        run = tmp_path / f"run{schema}"
        (run / "normalized").mkdir(parents=True)
        (run / "manifest.json").write_text(json.dumps({"run_id": "x", **({"output_schema": schema} if schema > 1 else {})}))
        full = _full_row()
        eps = [{k: v for k, v in full.items() if k not in outputs.HOSTNAME_FIELDS} | {"hostnames": ["a.test"]}]
        hosts = [{k: v for k, v in full.items() if k in outputs.KEY_FIELDS or k in outputs.HOSTNAME_FIELDS}] if schema == 2 else [full]
        (run / "normalized" / "endpoints.jsonl").write_text("".join(json.dumps(r) + "\n" for r in eps))
        (run / "normalized" / "hostname_resolution.jsonl").write_text("".join(json.dumps(r) + "\n" for r in hosts))
        assert [r["hostname"] for r in outputs.iter_hostname_rows(run)] == ["a.test"]
        out = outputs.export_csv(run)
        header, line = out.read_text(encoding="utf-8").splitlines()[:2]
        assert header.split(",")[-4:] == ["dns_at", "sni_at", "hostname_favicon_at", "hostname_document_captured_at"]
        assert line.endswith(",,,,")


def _full_row() -> dict:
    cols = [c for c in outputs.CSV_COLUMNS_NAMED if c not in outputs.CONTEXT_FIELDS]
    row = {c: None for c in cols}
    row.update(target_ip="192.0.2.1", port=443, hostname="a.test")
    return row


def test_a_store_written_before_the_column_existed_is_upgraded(tmp_path):
    path = tmp_path / "old.sqlite"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE synack (ip TEXT NOT NULL, port INTEGER NOT NULL, window INTEGER, ttl INTEGER, PRIMARY KEY (ip, port)) WITHOUT ROWID")
    db.execute("INSERT INTO synack VALUES ('10.0.0.1', 80, 64240, 64)")
    db.commit()
    db.close()
    with ShardStore(path) as store:
        assert store.get_synack("10.0.0.1", 80) == {"window": 64240, "ttl": 64, "seen_at": None}
        store.put_synack("10.0.0.2", 80, 1, 2, "2026-10-04T17:52:40+00:00")
        assert store.get_synack("10.0.0.2", 80)["seen_at"] == "2026-10-04T17:52:40+00:00"


def test_l4_time_survives_the_store_round_trip(tmp_path):
    run_dir, _ = _run(tmp_path)
    assert {r["l4_seen_at"] for r in outputs.iter_endpoint_rows(run_dir)} == {"2026-10-04T17:52:40.123000+00:00"}
