"""Rejected tarpit addresses are recorded with their reasons, incrementally and after the sweeps."""
import json

import pytest

from scanner.internet import enrich
from scanner.internet.shardstore import ShardStore
from tests.test_enrich import MIXED, ONE, TARPIT, _tarpit_config
from tests.test_pipeline import go, tools


@pytest.fixture
def store(tmp_path):
    s = ShardStore(tmp_path / "work" / "facts.sqlite")
    yield s
    s.close()


def test_incremental_flagging_sees_only_the_ingested_addresses(store):
    store.put_synack_port(80, {"10.0.0.1": {"window": 0, "ttl": 64}, "10.0.0.2": {"window": 64240, "ttl": 64},
                               "10.0.0.3": {"window": 100, "ttl": 64}})
    assert store.flag_tarpits(246, ["10.0.0.1", "10.0.0.2"]) == {"10.0.0.1"}
    assert store.rejected_ips() == {"10.0.0.1"}                  # 10.0.0.3 was not part of this call
    store.put_synack_port(443, {"10.0.0.2": {"window": 5, "ttl": 64}, "10.0.0.4": {"window": None, "ttl": 64}})
    assert store.flag_tarpits(246, ["10.0.0.2", "10.0.0.4"]) == {"10.0.0.2"}
    assert store.rejected_ips() == {"10.0.0.1", "10.0.0.2"}


def test_full_recheck_matches_the_old_window_test_and_adds_what_was_missed(store):
    store.put_synack_port(80, {f"10.0.1.{i}": {"window": w, "ttl": 64} for i, w in enumerate([0, 245, 246, 65535, None])})
    store.put_synack_port(443, {"10.0.1.3": {"window": 1, "ttl": 64}})
    store.flag_tarpits(246, ["10.0.1.0"])
    store.flag_tarpits(246)
    assert store.rejected_ips() == store.tarpit_ips(246) == {"10.0.1.0", "10.0.1.1", "10.0.1.3"}


def test_rows_carry_port_signal_and_window_in_address_order(store):
    store.put_synack_port(80, {"10.0.2.9": {"window": 0, "ttl": 64}, "10.0.2.1": {"window": 7, "ttl": 64}})
    store.put_synack_port(8080, {"10.0.2.9": {"window": 3, "ttl": 64}})
    store.flag_tarpits(246)
    assert list(store.iter_tarpit_rejections()) == [
        ("10.0.2.1", [(80, "tiny_window", 7)]),
        ("10.0.2.9", [(80, "zero_window", 0), (8080, "tiny_window", 3)])]


def test_flagging_twice_does_not_duplicate(store):
    store.put_synack_port(80, {"10.0.3.1": {"window": 0, "ttl": 64}})
    store.flag_tarpits(246)
    store.flag_tarpits(246, ["10.0.3.1"])
    assert len(list(store.iter_tarpit_rejections())) == 1


def test_rejection_record_text():
    rec = enrich.tarpit_rejection("10.0.2.9", [(80, "zero_window", 0), (8080, "tiny_window", 3)], 246)
    assert rec["signals"] == ["tiny_window", "zero_window"] and rec["probed"] is False
    assert rec["reason"] == "SYN-ACK advertised a zero TCP window; SYN-ACK window below 246 bytes"
    assert rec["ports"] == [{"port": 80, "window": 0}, {"port": 8080, "window": 3}]


def test_pipeline_writes_the_rejections_and_keeps_the_count(tmp_path):
    cfg = _tarpit_config(tmp_path)
    ft = tools(
        l4={80: [TARPIT, MIXED, ONE], 443: [TARPIT, MIXED], 8080: [TARPIT, MIXED]},
        tls={(TARPIT, 80): "reset", (TARPIT, 443): "reset", (TARPIT, 8080): "reset",
             (MIXED, 80): "reset", (MIXED, 443): "ok", (MIXED, 8080): "reset", (ONE, 80): "reset"},
        tls_sni={}, http={}, ptr={}, a={}, nxdomain=set())
    ft.windows[(MIXED, 80)] = 0
    run_dir = go(cfg, ft)
    lines = [json.loads(x) for x in (run_dir / "normalized" / "tarpit_rejections.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [r["ip"] for r in lines] == [MIXED]
    assert lines[0]["signals"] == ["zero_window"] and lines[0]["ports"] == [{"port": 80, "window": 0}]
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert "normalized/tarpit_rejections.jsonl" in manifest["output_checksums"]
    assert "tarpit_ips_not_probed" in manifest["stage_counts"]


def test_no_file_when_nothing_is_rejected(tmp_path):
    cfg = _tarpit_config(tmp_path)
    ft = tools(l4={80: [ONE]}, tls={(ONE, 80): "reset"}, tls_sni={}, http={}, ptr={}, a={}, nxdomain=set())
    run_dir = go(cfg, ft)
    assert not (run_dir / "normalized" / "tarpit_rejections.jsonl").exists()
