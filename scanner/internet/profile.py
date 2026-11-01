"""Resource profile: how many connections a host can carry, and the concurrency settings that follow.

The scanner scales from a small virtual machine to a large server. ``derive`` maps the cores, the RAM and the
open-file limit to the concurrency settings of the network and favicon stages, never leaving the ranges that
``config.py`` accepts. Anything the operator sets explicitly (flag or settings.yaml) wins over the derived value.
"""
from __future__ import annotations

import math
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Starting values, to be replaced by what the pilot measures on the scanning host.
PER_CORE_CONNECTIONS = 500          # simultaneous connections one core can serve (most are waiting; the handshakes cost the CPU)
PER_CONNECTION_BYTES = 256 * 1024   # memory held per simultaneous connection (buffers, goroutine or thread stack, state)
OPEN_FILE_FRACTION = 0.8            # share of the open-file limit the connections may use; the rest is for files and pipes
RESERVED_MEMORY_GB = 1.0            # left to the operating system, ZMap and the pipeline itself
NETWORK_SHARE = 0.6                 # share of the connections given to ZGrab2 when the stages can overlap
DNS_THREADS_PER_CORE = 16
DNS_MAX_CONNECTION_SHARE = 8        # DNS threads never exceed connections divided by this
MAX_PARALLEL_BATCHES = 32           # ZGrab2 processes at once; one per two cores up to this
SENDERS_PER_PROCESS = 500           # connections one ZGrab2 process is given; more connections come from more processes
BATCH_PER_SENDER = 40               # addresses in a port-pure batch per ZGrab2 sender
OVERLAP_MIN_CORES = 4               # overlapping TLS with ZMap needs spare cores
DEFAULT_OPEN_FILES = 8192           # assumed where the limit cannot be read
DEFAULT_STAGE_MAX_SECONDS = 86400
BROWSER_MEMORY_GB = 0.6             # resident memory of one headless browser with a page open
MAX_BROWSERS = 16

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


def javascript_concurrency(cores: int, memory_gb: float | None) -> int:
    """Headless browsers to run at once: half the cores, as many as fit in the RAM left after the reserve, at most ``MAX_BROWSERS``."""
    limits = [max(1, int(cores) // 2), MAX_BROWSERS]
    if memory_gb is not None:
        limits.append(int(max(memory_gb - RESERVED_MEMORY_GB, 0.0) / BROWSER_MEMORY_GB))
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

    wanted = -(-network // SENDERS_PER_PROCESS)           # processes it takes to use the network share at the usual size
    parallel = given.get("zgrab_parallel_batches") or _clamp(min(cores // 2, wanted, MAX_PARALLEL_BATCHES), "zgrab_parallel_batches")
    senders = given.get("zgrab_senders") or _clamp(min(SENDERS_PER_PROCESS, network // parallel), "zgrab_senders")
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


CGROUP_ROOT = Path("/sys/fs/cgroup")
_NO_LIMIT = 1 << 60                 # cgroup v1 reports "unlimited" as a number close to 2**63


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="ascii", errors="replace").strip()
    except OSError:
        return None


def cgroup_cpu_limit(root: Path = CGROUP_ROOT) -> float | None:
    """CPUs the control group may use (v2 ``cpu.max``, v1 ``cpu.cfs_quota_us``), or None where there is no limit."""
    try:
        text = _read(root / "cpu.max")
        if text:
            quota, period = text.split()[:2]
            return None if quota == "max" else int(quota) / int(period)
        for base in (root / "cpu", root / "cpu,cpuacct"):
            quota, period = _read(base / "cpu.cfs_quota_us"), _read(base / "cpu.cfs_period_us")
            if quota is not None and period is not None:
                return None if int(quota) <= 0 else int(quota) / int(period)
    except (ValueError, ZeroDivisionError):
        pass
    return None


def cgroup_memory_limit_gb(root: Path = CGROUP_ROOT) -> float | None:
    """Memory the control group may use (v2 ``memory.max``, v1 ``memory.limit_in_bytes``), or None where there is no limit."""
    for path in (root / "memory.max", root / "memory" / "memory.limit_in_bytes"):
        text = _read(path)
        if text is None or text == "max":
            continue
        try:
            value = int(text)
        except ValueError:
            continue
        if 0 < value < _NO_LIMIT:
            return value / 2**30
    return None


def detect_cores(cgroup_root: Path = CGROUP_ROOT) -> int:
    try:
        cores = max(1, len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        cores = max(1, os.cpu_count() or 1)
    limit = cgroup_cpu_limit(cgroup_root)
    return cores if limit is None else max(1, min(cores, math.ceil(limit)))


def detect_memory_gb(meminfo: Path = Path("/proc/meminfo"), cgroup_root: Path = CGROUP_ROOT) -> float | None:
    total = _host_memory_gb(meminfo)
    limit = cgroup_memory_limit_gb(cgroup_root)
    if limit is None:
        return total
    return limit if total is None else min(total, limit)


def _host_memory_gb(meminfo: Path) -> float | None:
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


def _positive(value: Any, name: str, whole: bool) -> int | float | None:
    """``value`` as a positive number (a whole one if ``whole``); None stays None. Anything else raises ValueError."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a positive number, not {value!r}")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a positive number, not {value!r}") from None
    if not math.isfinite(number) or number <= 0 or (whole and number != int(number)):
        raise ValueError(f"{name} must be a positive {'whole ' if whole else ''}number, not {value!r}")
    return int(number) if whole else number


def detect(cores: int | None = None, memory_gb: float | None = None, open_files: int | None = None) -> Resources:
    """The host's resources; a value given here (from a flag or settings.yaml) replaces the detected one.

    A given value that is not a positive number raises ``ValueError``; it is never taken for "not given"."""
    cores = _positive(cores, "cores", True)
    memory_gb = _positive(memory_gb, "memory_gb", False)
    open_files = _positive(open_files, "max_open_files", True)
    if open_files is None:
        raise_open_file_limit()
    return Resources(cores=cores if cores is not None else detect_cores(),
                     memory_gb=float(memory_gb) if memory_gb is not None else detect_memory_gb(),
                     open_files=open_files if open_files is not None else detect_open_files())
