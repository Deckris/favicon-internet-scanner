"""Let a long-running worker exit cleanly so its supervisor starts a fresh process.

A worker builds a ``Recycler`` and calls ``after_shard()`` once per finished shard (or ``check()`` at any time). When
the shard budget is used up or the resident memory is above the limit, the process exits with ``EXIT_RECYCLE`` (75).
systemd restarts it through ``RestartForceExitStatus=75``; the unit templates in ``run/systemd`` set that.
"""
from __future__ import annotations

import sys
from collections.abc import Callable

EXIT_RECYCLE = 75


def current_rss_mib(status_path: str = "/proc/self/status") -> float | None:
    """Resident set of this process in MiB; None where /proc is not available."""
    try:
        with open(status_path, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def _log(message: str) -> None:
    print(message, file=sys.stderr)


class Recycler:
    def __init__(self, max_shards: int = 0, max_rss_mib: float = 0, *,
                 rss_reader: Callable[[], float | None] = current_rss_mib,
                 exit_fn: Callable[[int], None] = sys.exit) -> None:
        """A limit of 0 is off."""
        self.max_shards, self.max_rss_mib = max_shards, max_rss_mib
        self.shards = 0
        self._rss, self._exit = rss_reader, exit_fn

    def reason(self) -> str | None:
        if self.max_shards and self.shards >= self.max_shards:
            return f"{self.shards} shards done (limit {self.max_shards})"
        if self.max_rss_mib:
            rss = self._rss()
            if rss is not None and rss > self.max_rss_mib:
                return f"RSS {rss:.0f} MiB above limit {self.max_rss_mib:.0f} MiB"
        return None

    def check(self, log: Callable[[str], None] = _log) -> None:
        why = self.reason()
        if why:
            log(f"recycling worker: {why}")
            self._exit(EXIT_RECYCLE)

    def after_shard(self, log: Callable[[str], None] = _log) -> None:
        self.shards += 1
        self.check(log)
