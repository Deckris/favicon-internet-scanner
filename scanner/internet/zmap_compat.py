"""Pinned ZMap contracts. 2.1.x paces targets; 4.4.0 paces individual probes.

Do not silently accept other releases: changing the iterator can change a sample.
"""
import re


def supported(version: str) -> bool:
    return bool(re.fullmatch(r"2\.1\.\d+", version)) or version == "4.4.0"


def version_number(line: str) -> str | None:
    match = re.search(r"\bzmap\s+v?(\d+\.\d+\.\d+)\b", line)
    return match.group(1) if match else None


def packet_rate_args(version: str, packet_rate: int, probes: int) -> int:
    if not supported(version):
        raise ValueError(f"unsupported ZMap version: {version}")
    if version == "4.4.0":
        return packet_rate
    if packet_rate < probes:
        raise ValueError("ZMap 2.1.x packet rate must be at least the number of probes")
    return packet_rate // probes


def output_args(version: str) -> list[str]:
    if not supported(version):
        raise ValueError(f"unsupported ZMap version: {version}")
    return ["--no-header-row", "--batch", "1"] if version == "4.4.0" else []
