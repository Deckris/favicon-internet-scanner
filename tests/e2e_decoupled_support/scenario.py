"""The simulated Internet of the decoupled end-to-end test: a few addresses per shard, all in one /24."""
from __future__ import annotations

import os

SHARDS = int(os.environ.get("E2E_SHARDS", "6"))
PER_SHARD = 4
NET = "1.1.1"


def shard_ips(shard: int) -> list[str]:
    return [f"{NET}.{shard * PER_SHARD + k + 1}" for k in range(PER_SHARD)]


def all_ips() -> list[str]:
    return [ip for s in range(SHARDS) for ip in shard_ips(s)]


def shard_of(ip: str) -> int:
    return (int(ip.rsplit(".", 1)[1]) - 1) // PER_SHARD


def host_of(ip: str) -> str:
    return f"h{ip.rsplit('.', 1)[1]}.good.test"


def build_tools(shard: int | None):
    """FakeTools answering for the addresses of ``shard`` (every shard when None)."""
    from tests.helpers import FakeTools
    ips = all_ips() if shard is None else shard_ips(shard)
    http_ips = [ip for ip in ips if int(ip.rsplit(".", 1)[1]) % PER_SHARD == 1]
    l4 = {443: list(ips), 80: http_ips}
    tools = FakeTools(
        l4=l4,
        tls={**{(ip, 443): "ok" for ip in ips}, **{(ip, 80): "plain" for ip in http_ips}},
        tls_sni={(ip, host_of(ip)): "ok" for ip in all_ips()},
        http={(ip, 80): 200 for ip in http_ips},
        ptr={ip: [host_of(ip) + "."] for ip in all_ips()},
        a={host_of(ip): [ip] for ip in all_ips()},
    )
    tools.extra_sample = ips
    return tools
