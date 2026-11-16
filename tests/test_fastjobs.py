"""The narrow favicon-job reader builds exactly the jobs of ``pipeline.favicon_jobs``."""
from __future__ import annotations

import random
from types import SimpleNamespace

import pytest

from scanner.internet import fastjobs, tls as tlsmod
from scanner.internet.candidates import EndpointNames
from scanner.internet.pipeline import favicon_jobs
from scanner.internet.shardstore import ShardStore
from scanner.internet.tls import TlsResult
from scanner.models import CertificateInfo, ZGrabResult
from scanner.zdns_runner import Resolution

SOURCES = ["ptr", "certificate_san", "certificate_cn", "ct", "operator_supplied"]


def _cert(rng, ip, port, names, big):
    san = tuple(names) + tuple(f"extra{i}.shared-{rng.randrange(50)}.example.net" for i in range(60 if big else 2))
    return CertificateInfo(
        sha256="%064x" % rng.getrandbits(256), subject_cn=names[0] if names else None, san_dns=san,
        issuer="CN=Example CA " + "x" * 80, serial="%x" % rng.getrandbits(64), not_before="2026-01-01T00:00:00Z",
        not_after="2027-01-01T00:00:00Z", signature_algorithm="SHA256-RSA", public_key_algorithm="RSA",
        public_key_bits=2048, chain_sha256=tuple("%064x" % rng.getrandbits(256) for _ in range(3)),
        handshake_mode="direct_ip", sni_sent=None, self_signed=False, expired_at_observation=False,
        not_yet_valid_at_observation=False, hostname_matches=None, target_ip=ip, port=port)


def _tls(rng, ip, port, outcome, sni, names, big):
    ok = outcome == tlsmod.OK
    return TlsResult(
        ip=ip, port=port, sni=sni, zgrab_status="success" if ok else "protocol-error", outcome=outcome,
        error=None if ok else "remote error: tls: unrecognized name " + "e" * 40,
        tls_version="TLSv1.3" if ok else None, cipher_suite="TLS_AES_128_GCM_SHA256" if ok else None,
        certificate=_cert(rng, ip, port, names, big) if ok else None, cert_parse_error=None,
        raw_line_sha256="%064x" % rng.getrandbits(256), requested_at="2026-11-01T00:00:00Z")


def _http(rng, ip, port, status):
    return ZGrabResult(
        zgrab_job_id="j%d" % rng.getrandbits(32), target_ip=ip, port=port, scheme_attempted="http",
        acquisition_mode="direct_ip", request_hostname=None, sni_hostname=None,
        status="success" if status else "io-timeout", http_status=status, content_type="text/html",
        content_encoding=None, location=None, body_sha256="%064x" % rng.getrandbits(256), body_bytes=1234,
        tls_handshake_ok=None, tls_error=None, certificate=None, error=None,
        raw_line_sha256="%064x" % rng.getrandbits(256), requested_at="2026-11-01T00:00:00Z")


OUTCOMES = [tlsmod.OK] * 5 + [tlsmod.ALERT_UNRECOGNIZED_NAME, tlsmod.ALERT_OTHER, tlsmod.VERSION, tlsmod.NO_CIPHER,
                              tlsmod.NOT_TLS, tlsmod.TIMEOUT, tlsmod.RESET]
RES_STATUS = ["resolved"] * 6 + ["nxdomain", "servfail", "timeout", "no_answer"]


def build_store(path, n_ips, seed=7):
    """A store with ``n_ips`` addresses, one to three endpoints each, and every table that favicon_jobs reads."""
    rng = random.Random(seed)
    store = ShardStore(path, reset=True, batch_size=2000)
    resolutions: dict[str, Resolution] = {}
    for i in range(n_ips):
        ip = "%d.%d.%d.%d" % (10 + rng.randrange(200), rng.randrange(256), rng.randrange(256), 1 + i % 250)
        if rng.random() < 0.02:
            ip = "%d.%d.%d.%d" % (10 + i % 200, i // 200 % 256, i // 51200, 7)
        for port in sorted(rng.sample([80, 443, 8080, 8443, 2083, 3000], rng.choice([1, 1, 2, 3]))):
            store.put_endpoints([(ip, port)])
            big = rng.random() < 0.15
            hosts = [f"h{rng.randrange(400)}.site{rng.randrange(3000)}.example.org" for _ in range(rng.choice([0, 1, 2, 3, 5, 9]))]
            outcome = rng.choice(OUTCOMES)
            if rng.random() < 0.08:
                continue                                             # no direct-IP TLS result at all
            store.put_tls(_tls(rng, ip, port, outcome, None, hosts, big))
            if rng.random() < 0.7:
                store.put_http(_http(rng, ip, port, rng.choice([200, 301, 404, None])))
            names = EndpointNames(
                names={h: set(rng.sample(SOURCES, rng.choice([1, 1, 2, 3]))) for h in hosts},
                wildcards={"*.wild%d.example.org" % rng.randrange(9)} if big else set(),
                dropped=["bad name %d" % k for k in range(40 if big else 0)], truncated=big, source_count=len(hosts))
            if hosts or rng.random() < 0.5:
                store.put_names(ip, port, names)
            for h in hosts:
                if rng.random() < 0.5:
                    store.put_sni(_tls(rng, ip, port, rng.choice(OUTCOMES), h, [h], big))
                if rng.random() < 0.9 and h not in resolutions:
                    st = rng.choice(RES_STATUS)
                    a = ()
                    if st == "resolved":
                        pool = [ip, "192.0.2.%d" % rng.randrange(255), "198.51.100.%d" % rng.randrange(255)]
                        a = tuple(rng.sample(pool, rng.choice([0, 1, 1, 2, 3])))
                    resolutions[h] = Resolution(hostname=h, status=st, cname_chain=("c." + h,) if big else (), a=a,
                                                aaaa=("2001:db8::1",) if big else (), error=None,
                                                queried_at="2026-11-01T00:00:00Z")
    store.put_resolutions(resolutions.values())
    store.flush()
    return store


def make_cfg(max_names=3, max_unverified=2):
    return SimpleNamespace(favicon=SimpleNamespace(max_hostnames_per_endpoint=max_names,
                                                   max_unverified_names_per_endpoint=max_unverified))


@pytest.fixture(scope="module")
def shared_store(tmp_path_factory):
    store = build_store(tmp_path_factory.mktemp("fj") / "a.sqlite", 1500)
    yield store
    store.close()


@pytest.mark.parametrize("limits", [(3, 2), (0, 0), (1, 5), (20, 10), (0, 3), (4, 0)])
def test_same_jobs_in_same_order(shared_store, limits):
    store = shared_store
    if True:
        cfg = make_cfg(*limits)
        old_counts: dict = {"favicon_jobs_unverified_names": 5}
        new_counts: dict = {"favicon_jobs_unverified_names": 5}
        old = favicon_jobs(store, cfg, old_counts)
        new = fastjobs.favicon_jobs_fast(store, cfg, new_counts)
        assert old[0], "the store should produce jobs"
        assert new[0] == old[0]
        assert new[1] == old[1]
        assert new[2] == old[2]
        assert new_counts == old_counts


def test_empty_store(tmp_path):
    with ShardStore(tmp_path / "e.sqlite", reset=True) as store:
        counts: dict = {}
        assert fastjobs.favicon_jobs_fast(store, make_cfg(), counts) == ([], set(), set())
        assert counts == {}
