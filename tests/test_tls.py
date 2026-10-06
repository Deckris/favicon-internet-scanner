"""TLS-first stage, pinned against output captured from the real zgrab2 tls module."""
import json
from types import SimpleNamespace

import pytest

from scanner.internet import tls
from scanner.safety import TargetPolicy
from tests.helpers import FIX


def _parse(name: str, sni=None, mode="direct_ip"):
    line = (FIX / "zgrab_tls" / name).read_text(encoding="utf-8").splitlines()[0]
    return tls.parse_line(line, port=443, sni=sni, mode=mode)


def test_success_keeps_certificate_names():
    r = _parse("ok.jsonl")
    assert r.ok and r.certificate is not None
    assert r.certificate.subject_cn == "good.test"
    assert set(r.certificate.san_dns) == {"good.test", "*.wild.test", "www.good.test"}
    assert r.tls_version == "TLSv1.3" and r.cipher_suite


def test_tls_ok_even_when_service_is_not_http():
    r = _parse("nonhttp_ok.jsonl")
    assert r.ok and r.certificate is not None          # cert evidence survives a non-HTTP service


@pytest.mark.parametrize("fixture,expected", [
    ("strict_no_sni.jsonl", tls.ALERT_UNRECOGNIZED_NAME),
    ("handshake_failure.jsonl", tls.ALERT_OTHER),
    ("silent_close.jsonl", tls.CLOSED),
    ("reset.jsonl", tls.RESET),
    ("hang.jsonl", tls.TIMEOUT),
    ("plain_http.jsonl", tls.NOT_TLS),
    ("closed_port.jsonl", tls.CONNECT_TIMEOUT),
])
def test_failure_modes_have_distinct_outcomes(fixture, expected):
    r = _parse(fixture)
    assert r.outcome == expected and not r.ok and r.certificate is None


def test_strict_sni_server_succeeds_when_sni_supplied():
    r = _parse("strict_with_sni.jsonl", sni="other.test", mode="hostname_aware")
    assert r.ok and r.certificate.subject_cn == "other.test"
    assert r.certificate.hostname_matches is True


def test_unparseable_line_is_retained_not_raised():
    r = tls.parse_line("{broken", port=443, sni=None, mode="direct_ip")
    assert r.outcome == tls.PARSE_ERROR and r.raw_line_sha256


def test_malformed_certificate_keeps_handshake_success_and_records_error():
    line = json.dumps({"ip": "1.1.1.1", "port": 443, "data": {"tls": {"status": "success", "result": {"handshake_log": {
        "server_hello": {"version": {"name": "TLSv1.2"}}, "server_certificates": {"certificate": {"raw": "AAAA"}}}}}}})
    r = tls.parse_line(line, port=443, sni=None, mode="direct_ip")
    assert r.ok and r.certificate is None and r.cert_parse_error


def _cfg():
    return SimpleNamespace(measurement=SimpleNamespace(zgrab_batch_size=2, zgrab_connect_timeout=4.0,
                                                       zgrab_target_timeout=8.0, zgrab_senders=5))


def test_batching_groups_by_port_and_chunks(tmp_path):
    policy = TargetPolicy.for_tests(["1.1.1.0/24"])
    calls = []

    def fake(cmd, input="", **kw):
        calls.append((cmd, input))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    targets = [(f"1.1.1.{i}", 443, None) for i in range(1, 6)] + [("1.1.1.9", 8443, None)]
    jobs, results = tls.run_tls_batches(targets, mode="direct_ip", cfg=_cfg(), policy=policy, run_dir=tmp_path, executor=fake)
    assert len(calls) == 4                                     # 3 chunks on 443 (5 targets / 2) + 1 on 8443
    assert all(c[0][1] == "tls" for c in calls)
    assert "--blocklist-file=" in calls[0][0]
    assert len(results) == 6                                   # tool printed nothing: every target still gets a record
    assert {r.outcome for r in results} == {tls.OTHER}


def test_policy_refused_targets_are_never_sent(tmp_path):
    policy = TargetPolicy.for_tests(["1.1.1.0/24"])
    sent = []

    def fake(cmd, input="", **kw):
        sent.append(input)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    tls.run_tls_batches([("1.1.1.1", 443, None), ("10.0.0.1", 443, None), ("127.0.0.1", 443, None)],
                        mode="direct_ip", cfg=_cfg(), policy=policy, run_dir=tmp_path, executor=fake)
    assert sent == ["1.1.1.1,,,443\n"]


def test_same_ip_with_several_sni_names_yields_one_result_each(tmp_path):
    policy = TargetPolicy.for_tests(["1.1.1.0/24"])
    base = json.loads((FIX / "zgrab_tls" / "ok.jsonl").read_text().splitlines()[0])

    def fake(cmd, input="", **kw):
        out = []
        for row in input.splitlines():
            ip, dom, _t, port = row.split(",")
            o = dict(base, ip=ip, port=int(port), domain=dom)
            out.append(json.dumps(o))
        return SimpleNamespace(returncode=0, stdout="\n".join(out) + "\n", stderr="")

    targets = [("1.1.1.1", 443, "a.example.com"), ("1.1.1.1", 443, "b.example.com")]
    cfg = SimpleNamespace(measurement=SimpleNamespace(zgrab_batch_size=50, zgrab_connect_timeout=4.0, zgrab_target_timeout=8.0, zgrab_senders=5))
    _jobs, results = tls.run_tls_batches(targets, mode="hostname_aware", cfg=cfg, policy=policy, run_dir=tmp_path, executor=fake)
    assert sorted(r.sni for r in results) == ["a.example.com", "b.example.com"]
    assert all(r.ok for r in results)


def test_mode_hostname_contract_enforced(tmp_path):
    policy = TargetPolicy.for_tests(["1.1.1.0/24"])
    with pytest.raises(ValueError):
        tls.run_tls_batches([("1.1.1.1", 443, None)], mode="hostname_aware", cfg=_cfg(), policy=policy, run_dir=tmp_path)
    with pytest.raises(ValueError):
        tls.run_tls_batches([("1.1.1.1", 443, "x.example.com")], mode="direct_ip", cfg=_cfg(), policy=policy, run_dir=tmp_path)
