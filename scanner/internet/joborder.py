"""Dispatch order of address groups in the favicon stage."""
from __future__ import annotations

from typing import Any

from scanner.internet.pacing import network_key


def order_groups(groups: list[list[int]], jobs: list[dict[str, Any]]) -> list[list[int]]:
    """``groups`` (job indexes per address) in dispatch order, deterministic.

    Longer chains come first, so the few addresses with many names do not set the tail of the stage. Among groups of
    the same length the order alternates between /24 (IPv6 /48) networks, so a window of in-flight groups is not
    filled by neighbours that the per-network cap would hold back. Each group keeps its own jobs, in order. Only the
    dispatch order changes; the job indexes, and so the lists they index, stay as they are.
    """
    tiers: dict[int, dict[str, list[list[int]]]] = {}
    for g in sorted((g for g in groups if g), key=lambda g: g[0]):
        tiers.setdefault(len(g), {}).setdefault(network_key(jobs[g[0]]["ip"]), []).append(g)
    out: list[list[int]] = []
    for size in sorted(tiers, reverse=True):
        queues = sorted(tiers[size].values(), key=lambda q: q[0][0])
        for rank in range(max(len(q) for q in queues)):
            out.extend(q[rank] for q in queues if rank < len(q))
    return out
