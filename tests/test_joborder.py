"""Dispatch order of the favicon stage: longest chains first, neighbouring addresses spread over /24 networks."""
from __future__ import annotations

import random

from scanner.internet.joborder import order_groups
from scanner.internet.pacing import network_key


def _jobs(ips):
    return [{"ip": ip} for ip in ips]


def _groups(jobs):
    g = {}
    for i, j in enumerate(jobs):
        g.setdefault(j["ip"], []).append(i)
    return list(g.values())


def _max_run(order, jobs):
    best = run = 0
    prev = None
    for g in order:
        n = network_key(jobs[g[0]]["ip"])
        run = run + 1 if n == prev else 1
        prev = n
        best = max(best, run)
    return best


def _dense():
    ips = [f"10.0.0.{i}" for i in range(1, 41)] + [f"10.0.1.{i}" for i in range(1, 6)] + ["10.0.2.1", "10.0.3.1"]
    return _jobs(sorted(ips))


def test_round_robin_interleaves_networks():
    jobs = _dense()
    order = order_groups(_groups(jobs), jobs)
    assert _max_run(order, jobs) == 1 or _max_run(order, jobs) < _max_run(_groups(jobs), jobs)
    assert [network_key(jobs[g[0]]["ip"]) for g in order[:4]] == ["10.0.0", "10.0.1", "10.0.2", "10.0.3"]


def test_deterministic_and_set_equal():
    jobs = _dense()
    groups = _groups(jobs)
    shuffled = groups[:]
    random.Random(1).shuffle(shuffled)
    a = order_groups(groups, jobs)
    assert a == order_groups(groups, jobs)
    assert a == order_groups(shuffled, jobs)
    assert sorted(map(tuple, a)) == sorted(map(tuple, groups))


def test_groups_keep_their_jobs_in_order():
    jobs = _jobs(["1.1.1.1", "1.1.1.2", "1.1.1.1", "1.1.1.2", "2.2.2.2"])
    for g in order_groups(_groups(jobs), jobs):
        assert g == sorted(g)


def test_longest_chain_first_is_kept():
    jobs = _jobs(["9.9.9.9"] + ["1.1.1.1"] * 3 + [f"1.1.1.{i}" for i in range(2, 6)] + ["2.2.2.2"] * 3)
    order = order_groups(_groups(jobs), jobs)
    lens = [len(g) for g in order]
    assert lens == sorted(lens, reverse=True)
    assert {jobs[g[0]]["ip"] for g in order[:2]} == {"1.1.1.1", "2.2.2.2"}


def test_empty():
    assert order_groups([], []) == []
