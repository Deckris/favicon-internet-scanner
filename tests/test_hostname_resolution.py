"""Candidate extraction rules, DNS judging and the final status vocabulary."""
from types import SimpleNamespace

from scanner.certificates import parse_der_safe
from scanner.internet import candidates as cand
from scanner.safety import TargetPolicy
from scanner.zdns_runner import Resolution


def _cert(sans=(), cn=None):
    return SimpleNamespace(san_dns=tuple(sans), subject_cn=cn)


POLICY = TargetPolicy.for_tests(["1.1.1.0/24"])


def test_ptr_san_cn_union_with_merged_provenance():
    ep = cand.build_endpoint_names(["Shop.Example.com."], _cert(["shop.example.com", "www.example.com"], "shop.example.com"),
                                   POLICY, max_candidates=20)
    assert ep.names["shop.example.com"] == {"ptr", "certificate_san", "certificate_cn"}
    assert ep.names["www.example.com"] == {"certificate_san"}


def test_wildcards_recorded_never_candidates_and_base_not_inferred():
    ep = cand.build_endpoint_names([], _cert(["*.example.com", "api.example.com"], "*.example.com"), POLICY, max_candidates=20)
    assert ep.wildcards == {"*.example.com"}
    assert set(ep.names) == {"api.example.com"}              # neither "*.example.com" nor "example.com" is queried


def test_ip_only_and_malformed_names_dropped():
    ep = cand.build_endpoint_names(["10.1.2.3", "localhost", "bad..name"], _cert(["192.0.2.1", "ok.example.com"]), POLICY, max_candidates=20)
    assert set(ep.names) == {"ok.example.com"}
    assert len(ep.dropped) >= 3


def test_idn_is_punycoded():
    ep = cand.build_endpoint_names([], _cert(["bücher.example"]), POLICY, max_candidates=20)
    assert "xn--bcher-kva.example" in ep.names


def test_cap_is_deterministic_and_flagged():
    sans = [f"h{i:03d}.example.com" for i in range(50)]
    ep = cand.build_endpoint_names([], _cert(sans), POLICY, max_candidates=5)
    assert ep.truncated and ep.source_count == 50
    assert sorted(ep.names) == sans[:5]


def test_cert_without_names_yields_no_candidates():
    ep = cand.build_endpoint_names([], _cert([], None), POLICY, max_candidates=20)
    assert ep.names == {} and not ep.truncated
    assert cand.build_endpoint_names([], None, POLICY, max_candidates=20).names == {}


def R(status="resolved", a=(), aaaa=(), chain=()):
    return Resolution("x.example.com", status, cname_chain=tuple(chain), a=tuple(a), aaaa=tuple(aaaa))


def test_dns_judging_matrix():
    ip = "1.1.1.1"
    assert cand.judge_dns(R(a=[ip]), ip) == "verified_current_mapping"
    assert cand.judge_dns(R(a=[ip], chain=["edge.cdn.example"]), ip) == "verified_current_mapping"          # CNAME -> scanned IP
    assert cand.judge_dns(R(a=[ip, "2.2.2.2"]), ip) == "multiple_a_including_target"
    assert cand.judge_dns(R(a=["2.2.2.2"]), ip) == "resolved_elsewhere"
    assert cand.judge_dns(R(a=["2.2.2.2", "3.3.3.3"]), ip) == "multiple_a_excluding_target"
    assert cand.judge_dns(R("nxdomain"), ip) == "nxdomain"
    assert cand.judge_dns(R(aaaa=["2001:db8::1"]), ip) == "no_answer"                                     # AAAA-only is not an IPv4 mapping
    assert cand.judge_dns(None, ip) == "tool_error"


def test_final_status_vocabulary():
    f = cand.final_status
    assert f("verified_current_mapping", {"ptr"}) == "verified"
    assert f("multiple_a_including_target", {"certificate_san"}) == "verified"
    assert f("resolved_elsewhere", {"certificate_san"}) == "resolved_elsewhere"
    assert f("multiple_a_excluding_target", {"ptr"}) == "resolved_elsewhere"
    assert f("nxdomain", {"ptr"}) == "nxdomain"
    # a name that exists but has no IPv4 record keeps the evidence label of its source
    assert f("no_answer", {"ptr"}) == "ptr_only_evidence"
    assert f("no_answer", {"certificate_san", "certificate_cn"}) == "tls_only_evidence"
    assert f("no_answer", {"ptr", "certificate_san"}) == "multi_source_evidence"           # PTR and certificate agree: stronger, not "unresolved"
    assert f("no_answer", {"operator_supplied"}) == "operator_evidence"
    # inconclusive DNS is "unresolved" whatever the source: an outage is never read as evidence
    for status in ("servfail", "timeout", "cname_loop", "too_many_cnames", "tool_error"):
        for sources in ({"ptr"}, {"certificate_san"}, {"ptr", "certificate_san"}):
            assert f(status, sources) == "unresolved", (status, sources)
