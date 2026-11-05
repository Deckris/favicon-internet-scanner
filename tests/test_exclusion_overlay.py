"""Live exclusions overlay: an opt-out takes effect on the next batch or sweep without changing the config checksum."""
import ipaddress
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from scanner.internet import favicon as fav
from scanner.internet import pipeline
from scanner.internet import tls as tlsmod
from scanner.internet.config import ConfigError, config_checksum, load_config, shared_config_checksum
from scanner.live_exclusions import LiveExclusions, OverlayError, parse_overlay
from scanner.safety import TargetPolicy
from scanner.zgrab_runner import ZGrabTarget, run_zgrab_batches
from scanner.zmap_runner import run_zmap
from tests.helpers import FakeFetcher, FakeTools, write_config
from tests.test_pipeline import IP_ELSE, IP_OK, tools


def put(path: Path, text: str) -> None:
    """Write the overlay and move its mtime forward, as a rename of a newer file would."""
    before = path.stat().st_mtime_ns if path.exists() else 0
    path.write_text(text, encoding="utf-8")
    os.utime(path, ns=(before + 5_000_000_000, before + 5_000_000_000))


def policy_with(path: Path) -> TargetPolicy:
    pol = TargetPolicy.for_tests(["1.1.1.0/24"])
    return pol.attach_overlay(LiveExclusions(path, min_interval=0))


def cfgview():
    return SimpleNamespace(
        vantage=SimpleNamespace(id="v", interface="eth0", source_ipv4="192.168.1.10"),
        measurement=SimpleNamespace(zmap_rate=100, zmap_max_runtime=100, zmap_cooldown=1, zgrab_batch_size=1, zgrab_senders=1,
                                    zgrab_connect_timeout=1, zgrab_target_timeout=1,
                                    zmap_output_fields="saddr,window,ttl,timestamp-str"),
        fetch=SimpleNamespace(user_agent="ua"))


def test_parse_overlay_comments_bare_addresses_and_errors():
    assert [str(n) for n in parse_overlay("# note\n1.2.3.0/24  # opt-out\n\n5.6.7.8\n2001:db8::/32\n")] == ["1.2.3.0/24", "5.6.7.8/32"]
    with pytest.raises(OverlayError, match="line 2"):
        parse_overlay("1.2.3.0/24\nnot-a-cidr\n")


def test_reload_on_change_logs_sha_entries_and_time(tmp_path):
    f = tmp_path / "overlay.txt"
    put(f, "1.1.1.1\n")
    ov = LiveExclusions(f, min_interval=0)
    assert ov.contains(ipaddress.ip_address("1.1.1.1")) and not ov.contains(ipaddress.ip_address("1.1.1.2"))
    put(f, "1.1.1.1\n1.1.1.2\n")
    assert ov.contains(ipaddress.ip_address("1.1.1.2"))
    loaded = [e for e in ov.events if e["event"] == "loaded"]
    assert [e["entries"] for e in loaded] == [1, 2] and all(len(e["sha256"]) == 64 and e["at"] for e in loaded)
    assert loaded[0]["sha256"] != loaded[1]["sha256"]


def test_malformed_file_keeps_last_good_and_is_logged(tmp_path, caplog):
    f = tmp_path / "overlay.txt"
    put(f, "1.1.1.1\n")
    ov = LiveExclusions(f, min_interval=0)
    put(f, "1.1.1.2\nbroken line\n")
    with caplog.at_level("ERROR"):
        assert ov.refresh(force=True) is False
    assert ov.contains(ipaddress.ip_address("1.1.1.1")) and not ov.contains(ipaddress.ip_address("1.1.1.2"))
    assert ov.events[-1]["event"] == "rejected" and "line 2" in ov.events[-1]["error"]
    assert "overlay" in caplog.text
    ov.refresh(force=True)
    assert [e["event"] for e in ov.events].count("rejected") == 1          # an unchanged bad file is not reported again
    put(f, "1.1.1.2\n")                                                    # a corrected file takes over
    assert ov.contains(ipaddress.ip_address("1.1.1.2")) and not ov.contains(ipaddress.ip_address("1.1.1.1"))


def test_malformed_file_at_start_is_refused(tmp_path):
    f = tmp_path / "overlay.txt"
    put(f, "oops\n")
    with pytest.raises(OverlayError):
        LiveExclusions(f)


def test_overlay_change_takes_effect_on_next_tls_batch_and_counts_drops(tmp_path):
    f = tmp_path / "overlay.txt"
    put(f, "# empty for now\n")
    pol = policy_with(f)
    ft = FakeTools(l4={}, tls={("1.1.1.1", 443): "ok", ("1.1.1.2", 443): "ok"}, tls_sni={}, http={}, ptr={}, a={})
    batch = [("1.1.1.1", 443, None), ("1.1.1.2", 443, None)]
    kw = dict(mode="direct_ip", cfg=cfgview(), policy=pol, run_dir=tmp_path / "run", executor=ft)
    tlsmod.run_tls_batches(batch, **kw)
    assert sorted(ft.zgrab_ips) == ["1.1.1.1", "1.1.1.2"]
    ft.zgrab_ips.clear()
    put(f, "1.1.1.2/32\n")
    tlsmod.run_tls_batches(batch, **kw)
    assert ft.zgrab_ips == ["1.1.1.1"]
    calls = [b for b in pol.overlay.batches if b["label"] == "tls:direct_ip"]
    assert [(b["size"], b["dropped"]) for b in calls] == [(2, 0), (2, 1)]
    assert calls[1]["overlay_sha256"] == pol.overlay.sha256 != calls[0]["overlay_sha256"]
    assert pol.overlay.summary()["dropped_by_stage"] == {"zgrab": 1}
    assert [r.reason for r in pol.refusals] == ["excluded_overlay"]


def test_change_between_chunks_of_one_call_is_honoured(tmp_path):
    f = tmp_path / "overlay.txt"
    put(f, "\n")
    pol = policy_with(f)
    ft = FakeTools(l4={}, tls={}, tls_sni={}, http={}, ptr={}, a={})

    def executor(command, **kw):             # the opt-out arrives while the first chunk is being scanned
        res = ft(command, **kw)
        if len(ft.zgrab_ips) == 1:
            put(f, "1.1.1.3\n")
        return res
    targets = [ZGrabTarget(ip=f"1.1.1.{i}", port=80, hostname=None) for i in (1, 2, 3)]
    run_zgrab_batches(targets, scheme="http", mode="direct_ip", cfg=cfgview(), policy=pol, run_dir=tmp_path / "run", executor=executor)
    assert ft.zgrab_ips == ["1.1.1.1", "1.1.1.2"]
    assert any(b["dropped"] == 1 and b["label"].endswith("chunk") for b in pol.overlay.batches)


def test_zmap_blocklist_of_a_later_sweep_holds_the_overlay(tmp_path):
    f = tmp_path / "overlay.txt"
    put(f, "\n")
    pol = TargetPolicy.for_tests(["1.1.1.0/24"], exclusions=["1.1.1.200/32"]).attach_overlay(LiveExclusions(f, min_interval=0))
    ft = FakeTools(l4={80: ["1.1.1.1", "1.1.1.9"]}, tls={}, tls_sni={}, http={}, ptr={}, a={})
    cv = cfgview()

    def blocklist(command):
        return Path(command[command.index("-b") + 1]).read_text().split()
    _job, res = run_zmap(cv, pol, 80, tmp_path / "run", executor=ft)
    assert blocklist(ft.commands[-1]) == ["1.1.1.200/32"] and len(res) == 2
    put(f, "1.1.1.0/28\n")
    _job, res = run_zmap(cv, pol, 80, tmp_path / "run", executor=ft)
    assert blocklist(ft.commands[-1]) == ["1.1.1.0/28", "1.1.1.200/32"]
    assert res == []                                  # answers from an address opted out during the sweep are dropped too
    sweeps = [b for b in pol.overlay.batches if b["stage"] == "zmap"]
    assert sweeps[-1]["dropped"] == 2 and sweeps[-1]["size"] == 2


def _with_overlay(base: Path, overlay: Path | None) -> None:
    data = yaml.safe_load(base.read_text())
    data["target_policy"]["exclusions_overlay_file"] = str(overlay)
    base.write_text(yaml.safe_dump(data))


def test_checksum_does_not_see_the_overlay(tmp_path):
    base = write_config(tmp_path)
    plain = load_config(base)
    _with_overlay(base, tmp_path / "optouts.txt")
    with_overlay = load_config(base)
    assert with_overlay.exclusions_overlay_file == tmp_path / "optouts.txt"
    assert with_overlay.checksum == plain.checksum
    assert shared_config_checksum(with_overlay.raw) == shared_config_checksum(plain.raw)
    changed = dict(with_overlay.raw)
    changed["target_policy"] = {**changed["target_policy"], "exclusions_overlay_file": "elsewhere.txt"}
    assert config_checksum(changed) == plain.checksum


def test_run_with_overlay_drops_address_records_it_and_keeps_checksum(tmp_path):
    base = write_config(tmp_path)
    plain = load_config(base)
    overlay = tmp_path / "optouts.txt"
    put(overlay, f"# opt-out received\n{IP_ELSE}/32\n")
    _with_overlay(base, overlay)
    cfg = load_config(base)
    ft = tools()
    run_dir = pipeline.run(cfg, run_id="t1", executor=ft, fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)
    assert IP_ELSE not in ft.zgrab_ips and IP_OK in ft.zgrab_ips
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["config_checksum"] == plain.checksum
    ov = m["exclusion_overlay"]
    assert ov["entries"] == 1 and len(ov["sha256"]) == 64 and ov["dropped_total"] >= 1
    assert "normalized/exclusion_overlay.jsonl" in m["output_checksums"]
    recs = [json.loads(line) for line in (run_dir / "normalized" / "exclusion_overlay.jsonl").read_text().splitlines()]
    assert recs[0]["event"] == "loaded" and any(r["record"] == "batch" and r["dropped"] for r in recs)


def test_malformed_overlay_at_start_refuses_the_run(tmp_path):
    base = write_config(tmp_path)
    overlay = tmp_path / "optouts.txt"
    put(overlay, "garbage\n")
    _with_overlay(base, overlay)
    with pytest.raises(ConfigError, match="overlay"):
        pipeline.build_policy(load_config(base))


def test_favicon_and_offhost_policies_refuse_overlay_addresses(tmp_path):
    overlay = tmp_path / "optouts.txt"
    put(overlay, "\n")
    cfg = SimpleNamespace(approval=None, hostname_mode="any_public", hostname_suffixes=(), exclusions_overlay_file=overlay)
    fp, op = fav.fetch_policy(cfg, ["8.8.8.8", "9.9.9.9"]), fav.offhost_policy(cfg, [])
    assert fp.check_ip("8.8.8.8", stage="favicon") is None and op.check_ip("9.9.9.9", stage="favicon") is None
    put(overlay, "8.8.8.8\n9.9.9.9\n")
    fp.overlay.refresh(force=True)
    assert fp.check_ip("8.8.8.8", stage="favicon").reason == "excluded_overlay"
    assert op.check_ip("9.9.9.9", stage="favicon").reason == "excluded_overlay"


@pytest.mark.parametrize("stamps", [
    ["2026-01-01T00:00:00+00:00"] * 8,
    [f"2026-01-01T00:00:{59 - i:02d}+00:00" for i in range(8)],
])
def test_records_keep_write_order_when_timestamps_tie_or_step_back(tmp_path, monkeypatch, stamps):
    from scanner import live_exclusions as live

    ticks = iter(stamps)
    monkeypatch.setattr(live, "_now", lambda: next(ticks))
    path = tmp_path / "optouts.txt"
    put(path, "192.0.2.0/24\n")
    overlay = LiveExclusions(path, min_interval=0)
    overlay.begin_run()
    overlay.note_batch("zmap", "first", 3, 1)
    put(path, "192.0.2.0/24\n198.51.100.0/24\n")
    assert overlay.refresh(force=True)
    overlay.note_batch("zgrab", "second", 2, 0)
    rows = overlay.records()
    assert [(r["record"], r.get("label", r.get("event"))) for r in rows] == [
        ("event", "loaded"), ("batch", "first"), ("event", "loaded"), ("batch", "second")]
    assert rows[0]["reason"] == "in force at start of run" and rows[2]["entries"] == 2
