"""zdns parsing is pinned against output captured from the real zdns v2.1.1 binary."""
from types import SimpleNamespace

from scanner.zdns_runner import parse_zdns_line, ptr_names, resolve, run_zdns
from tests.helpers import FIX


def _line(name: str) -> str:
    return (FIX / "zdns" / name).read_text(encoding="utf-8").splitlines()[0]


def test_a_record_and_multi_a():
    a = parse_zdns_line(_line("A_multi.test.jsonl"), "A")
    assert a.status == "NOERROR"
    r = resolve("multi.test", a, None)
    assert r.status == "resolved" and r.a == ("10.0.0.1", "10.0.0.2")


def test_cname_chain_is_followed_to_final_a():
    a = parse_zdns_line(_line("A_cn.test.jsonl"), "A")
    r = resolve("cn.test", a, None)
    assert r.status == "resolved"
    assert r.cname_chain == ("c1.test", "target.test")
    assert r.a == ("10.0.0.9",)


def test_cname_loop_detected():
    a = parse_zdns_line(_line("A_loop1.test.jsonl"), "A")
    assert resolve("loop1.test", a, None).status == "cname_loop"


def test_too_many_cnames():
    a = parse_zdns_line(_line("A_cn.test.jsonl"), "A")
    assert resolve("cn.test", a, None, max_cnames=1).status == "too_many_cnames"


def test_negative_and_failure_statuses():
    assert resolve("nx.test", parse_zdns_line(_line("A_nx.test.jsonl"), "A"), None).status == "nxdomain"
    assert resolve("servfail.test", parse_zdns_line(_line("A_servfail.test.jsonl"), "A"), None).status == "servfail"
    assert resolve("timeout.test", parse_zdns_line(_line("A_timeout.test.jsonl"), "A"), None).status == "timeout"


def test_aaaa_is_recorded_not_used_for_ipv4_mapping():
    a = parse_zdns_line(_line("A_a.test.jsonl"), "A")
    aaaa = parse_zdns_line(_line("AAAA_a.test.jsonl"), "AAAA")
    r = resolve("a.test", a, aaaa)
    assert r.a == ("10.0.0.1",) and r.aaaa == ("2001:db8::1",)


def test_ptr_names_strip_trailing_dot_and_nxdomain_is_empty():
    assert ptr_names(parse_zdns_line(_line("PTR_10.0.0.9.jsonl"), "PTR")) == ["host.test"]
    assert ptr_names(parse_zdns_line(_line("PTR_10.0.0.77.jsonl"), "PTR")) == []


def test_garbage_lines_do_not_raise():
    assert parse_zdns_line("not json", "A") is None
    assert parse_zdns_line('{"nothing": 1}', "A") is None
    assert parse_zdns_line('{"name": "x.test", "results": {"A": "weird"}}', "A").status in ("PARSE_ERROR",)


def test_batched_run_one_process_per_chunk_and_missing_names_flagged(tmp_path):
    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        out = (FIX / "zdns" / "A_batch.jsonl").read_text(encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout=out, stderr="progress text")

    names = ["a.test", "multi.test", "cn.test", "nx.test", "dropped.test"]
    jobs, ans = run_zdns("A", names, nameservers=["9.9.9.9"], run_dir=tmp_path, executor=fake)
    assert len(calls) == 1 and len(jobs) == 1                      # batched, not per name
    assert ans["a.test"].status == "NOERROR"
    assert ans["dropped.test"].status == "NO_OUTPUT"               # tool dropped it: still gets a record
    assert "--name-servers" in calls[0] and "9.9.9.9" in calls[0]


def test_chunking_splits_large_inputs(tmp_path):
    calls = []
    fake = lambda cmd, **kw: (calls.append(cmd) or SimpleNamespace(returncode=0, stdout="", stderr=""))
    names = [f"h{i}.test" for i in range(25)]
    jobs, ans = run_zdns("A", names, nameservers=["9.9.9.9"], run_dir=tmp_path, executor=fake, chunk_size=10)
    assert len(calls) == 3 and len(ans) == 25


def test_tool_crash_marks_every_name(tmp_path):
    def boom(cmd, **kw):
        raise FileNotFoundError("zdns")
    jobs, ans = run_zdns("PTR", ["1.1.1.1", "1.1.1.2"], nameservers=["9.9.9.9"], run_dir=tmp_path, executor=boom)
    assert {a.status for a in ans.values()} == {"TOOL_ERROR"}
    assert jobs[0].error


def test_requires_explicit_nameservers_and_known_module(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        run_zdns("A", ["x.test"], nameservers=[], run_dir=tmp_path)
    with pytest.raises(ValueError):
        run_zdns("MX", ["x.test"], nameservers=["9.9.9.9"], run_dir=tmp_path)
