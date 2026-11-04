"""Operations layer: status summary, worker recycling, certificate serial warnings, unit templates."""
import json
import re
import warnings
from pathlib import Path

import pytest

from scanner import certificates
from scanner.internet import status
from scanner.internet.__main__ import main
from scanner.internet.recycle import EXIT_RECYCLE, Recycler, current_rss_mib

ROOT = Path(__file__).resolve().parents[1]


def write_state(cdir, state):
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / "campaign.json").write_text(json.dumps(state))


def fake_proc(root, procs):
    for pid, cmd, rss_kb in procs:
        d = root / str(pid)
        d.mkdir(parents=True)
        (d / "cmdline").write_bytes(cmd.replace(" ", "\0").encode())
        (d / "status").write_text(f"Name:\tx\nVmRSS:\t{rss_kb} kB\n")
    (root / "self").mkdir(exist_ok=True)


def test_status_legacy_format(tmp_path):
    write_state(tmp_path, {"shards": 5, "shard_states": {"0": {"status": "complete"}, "1": {"status": "running", "attempts": 1}}})
    s = status.collect(tmp_path, proc_root=tmp_path / "no-proc")
    assert s["shards_by_state"] == {"complete": 1, "not_started": 3, "running": 1}
    assert s["shards_by_stage"] == {} and s["workers"] == []
    assert s["processes"] is None and s["zmap_send_rate_pps"] is None
    assert "/proc not available" in status.render(s)


def test_status_stages_workers_and_queue(tmp_path):
    write_state(tmp_path, {"shards": 3, "zmap": {"send_rate_pps": 5000}, "shard_states": {
        "0": {"status": "running", "stages": {"tls": {"status": "running", "owner_pid": 11, "heartbeat": 1000},
                                              "http": {"status": "pending"}}},
        "1": {"status": "running", "stages": {"tls": {"status": "pending", "attempts": 0},
                                              "http": {"status": "pending", "heartbeat": "bad"}}},
        "2": {"status": "pending", "stages": {"tls": {"status": "running", "owner_pid": 11, "heartbeat": "1970-01-01T00:20:00Z"}}}}})
    s = status.collect(tmp_path, proc_root=tmp_path / "x", now=1500)
    assert s["queue_depth"] == {"http": 2, "tls": 1}
    assert s["shards_by_stage"]["tls"] == {"pending": 1, "running": 2}
    (w,) = s["workers"]
    assert (w["stage"], w["pid"], w["shard"], w["age_seconds"]) == ("tls", 11, "2", 300)
    assert s["zmap_send_rate_pps"] == 5000
    text = status.render(s)
    assert "queue 2" in text and "5000 pps" in text
    json.dumps(s)


def test_status_process_rss_from_fake_proc(tmp_path):
    fake_proc(tmp_path / "proc", [(7, "python -m scanner.internet stage-worker", 204800), (8, "bash", 100), (9, "zmap -p 80", 1024)])
    procs = status.process_rss(tmp_path / "proc")
    assert [(p["pid"], p["rss_mib"]) for p in procs] == [(7, 200.0), (9, 1.0)]


def test_status_cli(tmp_path, capsys):
    write_state(tmp_path, {"shards": 1, "shard_states": {"0": {"status": "complete"}}})
    assert main(["status", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["shards_by_state"] == {"complete": 1}
    assert main(["status", str(tmp_path)]) == 0
    assert "shards (1)" in capsys.readouterr().out
    assert main(["status", str(tmp_path / "missing")]) == 2


def test_recycler_by_shards():
    codes = []
    r = Recycler(max_shards=2, exit_fn=codes.append)
    r.after_shard(log=lambda m: None)
    assert codes == []
    r.after_shard(log=lambda m: None)
    assert codes == [EXIT_RECYCLE] == [75]


def test_recycler_by_rss_and_unavailable():
    codes = []
    Recycler(max_rss_mib=100, rss_reader=lambda: 150.0, exit_fn=codes.append).check(log=lambda m: None)
    Recycler(max_rss_mib=100, rss_reader=lambda: 50.0, exit_fn=codes.append).check()
    Recycler(max_rss_mib=100, rss_reader=lambda: None, exit_fn=codes.append).check()
    Recycler(exit_fn=codes.append).after_shard()
    assert codes == [EXIT_RECYCLE]


def test_current_rss_reads_status_file(tmp_path):
    f = tmp_path / "status"
    f.write_text("VmRSS:\t2048 kB\n")
    assert current_rss_mib(str(f)) == 2.0
    assert current_rss_mib(str(tmp_path / "none")) is None


def test_serial_warning_filter_is_narrow():
    cw = certificates._CryptoWarning
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("default")
        warnings.filterwarnings("ignore", message=r".*serial number.*", category=cw)
        warnings.warn("Parsed a serial number which wasn't positive", cw)
        warnings.warn("something else", cw)
    assert [str(w.message) for w in caught] == ["something else"]


def test_nonpositive_serial_counted():
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a.example")])
    now = datetime.now(timezone.utc)
    try:
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
    except Exception:
        pytest.skip("cannot build a certificate")
    der = cert.public_bytes(serialization.Encoding.DER)
    before = certificates.nonpositive_serial_count()
    certificates.parse_der(der, handshake_mode="direct", sni_sent=None, observed_at=now)
    assert certificates.nonpositive_serial_count() == before


def test_unit_templates():
    d = ROOT / "run" / "systemd"
    units = {p.name: p.read_text() for p in d.glob("*.service")}
    assert {"scanner-limiterd.service", "scanner-zmap.service", "scanner-coordinator.service", "scanner-stage@.service",
            "scanner-favicon@.service"} <= set(units)
    assert "Restart=always" in units["scanner-limiterd.service"] and "OOMScoreAdjust=-900" in units["scanner-limiterd.service"]
    assert "KillMode=control-group" in units["scanner-zmap.service"] and "OOMScoreAdjust=-900" in units["scanner-zmap.service"]
    assert "MemoryMax=" in units["scanner-stage@.service"] and "RestartForceExitStatus=75" in units["scanner-stage@.service"]
    assert "Nice=" in units["scanner-favicon@.service"]
    env = (d / "scanner.env.example").read_text()
    keys = set(re.findall(r"^([A-Z_]+)=", env, re.M))
    for name, text in units.items():
        assert "network-online.target" in text and "EnvironmentFile=" in text
        assert set(re.findall(r"\$\{(\w+)\}", text.replace("$${", "")) ) <= keys
        assert set(re.findall(r"\$\$\{(\w+)\}", text)) <= keys, name
    assert (d / "scanner.target").exists() and (ROOT / "run" / "logrotate" / "scanner.example").exists()
