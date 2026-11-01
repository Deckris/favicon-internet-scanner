"""Resource profile: how many connections a host can carry, and the concurrency settings that follow.

The scanner scales from a small virtual machine to a large server. ``derive`` maps the cores, the RAM and the
open-file limit to the concurrency settings of the network and favicon stages, never leaving the ranges that
``config.py`` accepts. Anything the operator sets explicitly (flag or settings.yaml) wins over the derived value.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Starting values, to be replaced by what the pilot measures on the scanning host.
PER_CORE_CONNECTIONS = 250          # simultaneous connections one core can serve (TLS handshakes dominate)
PER_CONNECTION_BYTES = 256 * 1024   # memory held per simultaneous connection (buffers, goroutine or thread stack, state)
OPEN_FILE_FRACTION = 0.8            # share of the open-file limit the connections may use; the rest is for files and pipes
RESERVED_MEMORY_GB = 1.0            # left to the operating system, ZMap and the pipeline itself
NETWORK_SHARE = 0.6                 # share of the connections given to ZGrab2 when the stages can overlap
DNS_THREADS_PER_CORE = 16
DNS_MAX_CONNECTION_SHARE = 8        # DNS threads never exceed connections divided by this
MAX_PARALLEL_BATCHES = 8            # ZGrab2 processes at once; one per two cores up to this
BATCH_PER_SENDER = 40               # addresses in a port-pure batch per ZGrab2 sender
OVERLAP_MIN_CORES = 4               # overlapping TLS with ZMap needs spare cores
DEFAULT_OPEN_FILES = 8192           # assumed where the limit cannot be read
DEFAULT_STAGE_MAX_SECONDS = 86400

# The ranges config.py enforces; derived values stay inside them.
RANGES: dict[str, tuple[int, int]] = {
    "zgrab_senders": (1, 1000),
    "zgrab_parallel_batches": (1, 64),
    "zgrab_batch_size": (1, 100_000),
    "dns_threads": (1, 1000),
    "favicon_workers": (1, 8192),
    "favicon_processes": (1, 64),
    "favicon_max_active_requests": (1, 8192),
    "favicon_stage_max_seconds": (1, 86400),
}
OVERRIDE_KEYS = tuple(RANGES) + ("overlap_tls_with_zmap",)


@dataclass(frozen=True)
class Resources:
    cores: int
    memory_gb: float | None
    open_files: int


def _clamp(value: int, name: str) -> int:
    low, high = RANGES[name]
    return max(low, min(high, int(value)))


def connection_budget(cores: int, memory_gb: float | None, open_files: int) -> int:
    """Simultaneous connections the host can carry: the smallest of the file, memory and CPU limits."""
    limits = [int(OPEN_FILE_FRACTION * open_files), max(1, cores) * PER_CORE_CONNECTIONS]
    if memory_gb is not None:
        limits.append(int(max(memory_gb - RESERVED_MEMORY_GB, 0.25) * 2**30 / PER_CONNECTION_BYTES))
    return max(1, min(limits))


def derive(cores: int, memory_gb: float | None, open_files: int, *, offhost_icons: bool = False,
           overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """The concurrency settings for a host. ``overrides`` (name -> value, None means not set) always win.

    An override outside the range ``config.py`` accepts raises ``ValueError``.
    """
    cores = max(1, int(cores))
    given = {k: v for k, v in (overrides or {}).items() if v is not None}
    unknown = set(given) - set(OVERRIDE_KEYS)
    if unknown:
        raise ValueError(f"unknown setting {', '.join(sorted(unknown))}")
    for name, value in given.items():
        if name in RANGES:
            low, high = RANGES[name]
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError(f"{name} `{value}` must be a whole number from {low} to {high}")
        elif not isinstance(value, bool):
            raise ValueError(f"{name} must be true or false")

    connections = connection_budget(cores, memory_gb, open_files)
    overlap = given.get("overlap_tls_with_zmap", cores >= OVERLAP_MIN_CORES)

    dns_threads = _clamp(min(cores * DNS_THREADS_PER_CORE, connections // DNS_MAX_CONNECTION_SHARE), "dns_threads")
    remaining = max(2, connections - dns_threads)
    network = max(1, round(remaining * NETWORK_SHARE))
    favicon_active = remaining - network

    parallel = given.get("zgrab_parallel_batches") or _clamp(min(cores // 2, MAX_PARALLEL_BATCHES), "zgrab_parallel_batches")
    senders = given.get("zgrab_senders") or _clamp(network // parallel, "zgrab_senders")
    batch = given.get("zgrab_batch_size") or _clamp(senders * BATCH_PER_SENDER, "zgrab_batch_size")

    active = given.get("favicon_max_active_requests") or _clamp(favicon_active, "favicon_max_active_requests")
    processes = given.get("favicon_processes") or _clamp(min(cores, 64), "favicon_processes")
    workers = given.get("favicon_workers") or _clamp(max(64, active * 2, processes), "favicon_workers")
    if "favicon_processes" not in given:
        processes = max(1, min(processes, workers, active))      # each process needs a worker and a request slot

    plan = {
        "zgrab_senders": senders, "zgrab_parallel_batches": parallel, "zgrab_batch_size": batch,
        "dns_threads": given.get("dns_threads") or dns_threads,
        "favicon_workers": workers, "favicon_processes": processes, "favicon_max_active_requests": active,
        "favicon_stage_max_seconds": given.get("favicon_stage_max_seconds") or DEFAULT_STAGE_MAX_SECONDS,
        "overlap_tls_with_zmap": bool(overlap),
    }
    plan["connection_budget"] = connections
    return plan


def file_demand(plan: dict[str, Any]) -> int:
    """Descriptors the plan can hold open at once: ZGrab2 connections, DNS sockets and favicon requests."""
    return (int(plan["zgrab_senders"]) * int(plan["zgrab_parallel_batches"]) + int(plan["dns_threads"])
            + int(plan["favicon_max_active_requests"]))


def fits_open_files(plan: dict[str, Any], open_files: int) -> bool:
    return file_demand(plan) <= OPEN_FILE_FRACTION * open_files


def raise_open_file_limit() -> int | None:
    """Raise the soft descriptor limit to the hard limit where the platform has one. Returns the limit now in force."""
    try:
        import resource
    except ImportError:
        return None
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = hard if hard != resource.RLIM_INFINITY else max(soft, 1 << 20)
    if soft != resource.RLIM_INFINITY and target > soft:
        for candidate in (target, 1 << 20, 65536, 16384):
            if candidate <= soft or candidate > target:
                continue
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (candidate, hard))
                return candidate
            except (ValueError, OSError):
                continue
    return soft if soft != resource.RLIM_INFINITY else target


def detect_cores() -> int:
    try:
        return max(1, len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        return max(1, os.cpu_count() or 1)


def detect_memory_gb(meminfo: Path = Path("/proc/meminfo")) -> float | None:
    try:
        for line in meminfo.read_text(encoding="ascii", errors="replace").splitlines():
            if line.startswith("MemTotal"):
                return int(line.split()[1]) / 2**20
    except (OSError, ValueError, IndexError):
        pass
    if sys.platform == "win32":
        try:
            import ctypes

            class _Status(ctypes.Structure):
                _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong), ("total", ctypes.c_ulonglong),
                            ("avail", ctypes.c_ulonglong), ("page_total", ctypes.c_ulonglong), ("page_avail", ctypes.c_ulonglong),
                            ("virt_total", ctypes.c_ulonglong), ("virt_avail", ctypes.c_ulonglong), ("ext", ctypes.c_ulonglong)]
            status = _Status()
            status.length = ctypes.sizeof(_Status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return status.total / 2**30
        except (AttributeError, OSError):
            pass
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30
    except (AttributeError, ValueError, OSError):
        return None


def detect_open_files() -> int:
    try:
        import resource
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        return DEFAULT_OPEN_FILES if soft == resource.RLIM_INFINITY else int(soft)
    except ImportError:
        return DEFAULT_OPEN_FILES


def detect(cores: int | None = None, memory_gb: float | None = None, open_files: int | None = None) -> Resources:
    """The host's resources; a value given here (from a flag) replaces the detected one."""
    if not open_files:
        raise_open_file_limit()
    return Resources(cores=int(cores) if cores else detect_cores(),
                     memory_gb=float(memory_gb) if memory_gb else detect_memory_gb(),
                     open_files=int(open_files) if open_files else detect_open_files())
