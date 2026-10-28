"""Direct-IP TLS while ZMap is still sweeping, without breaking the per-address minimum pause.

With one seed every sampled address gets a SYN on every port, so TLS for port N must not reach an address
within ``pace`` seconds of that address's SYN for any other port. ZMap sends in a fixed order (the dry-run
order, the same for every port, probe count and rate; the repeat probes of one target go out back to back),
so an address's position in that order and an upper bound on ZMap's speed bound when its SYN can go out.

``ZmapProgress`` follows the sweeps: start and end of each, plus the ``sent-total`` counter from ZMap's
status file (``-u``) when the binary writes one. ``OverlapGate`` admits a batch only when, for every address:

* past: its last known SYN is at least ``pace`` seconds old (the time of the first progress reading that
  shows it sent, or the end of that sweep), and
* future: its next SYN cannot come within the batch's hard time limit plus ``pace``, assuming ZMap runs at
  ``slack`` times its configured rate from its last known position (or from the start of the sweep).

Without status readings the gate still works, only more cautiously. Once every sweep has ended, an address
is due ``pace`` seconds after the last sweep, which is the sequential behaviour.
"""
from __future__ import annotations

import csv
import threading
import time
from pathlib import Path
from typing import Callable

SLACK = 1.25          # ZMap's real rate measured ~5% above the configured one; leave a wide margin


class ZmapProgress:
    def __init__(self, probes: int, now: Callable[[], float] = time.monotonic) -> None:
        self.probes = max(1, int(probes))
        self._now = now
        self._lock = threading.Lock()
        self.sweeps: list[dict] = []          # {"start", "end", "obs": [(t, targets_sent)], "path", "offset", "col", "rest"}
        self.done = False
        self.readings = 0

    def start_sweep(self, status_path: Path | None) -> None:
        with self._lock:
            self.sweeps.append({"start": self._now(), "end": None, "obs": [], "path": status_path, "offset": 0,
                                "col": None, "rest": ""})

    def end_sweep(self) -> None:
        with self._lock:
            if self.sweeps and self.sweeps[-1]["end"] is None:
                self._poll(self.sweeps[-1])
                self.sweeps[-1]["end"] = self._now()

    def finish(self) -> None:
        """No further sweeps will start."""
        with self._lock:
            self.done = True

    def snapshot(self) -> tuple[list[dict], bool]:
        with self._lock:
            if self.sweeps and self.sweeps[-1]["end"] is None:
                self._poll(self.sweeps[-1])
            return [dict(s, obs=list(s["obs"])) for s in self.sweeps], self.done

    def _poll(self, sweep: dict) -> None:
        path = sweep["path"]
        if path is None:
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                fh.seek(sweep["offset"])
                chunk = fh.read()
                sweep["offset"] = fh.tell()
        except OSError:
            return
        if not chunk:
            return
        seen = self._now()                    # the counter was at least this high by now
        text = sweep["rest"] + chunk
        lines = text.split("\n")
        sweep["rest"] = lines.pop()           # an unfinished last line waits for the next read
        for row in csv.reader(lines):
            if not row:
                continue
            if sweep["col"] is None:
                names = [c.strip().replace("_", "-") for c in row]
                if "sent-total" in names:
                    sweep["col"] = names.index("sent-total")
                continue
            try:
                sent = int(row[sweep["col"]])
            except (IndexError, ValueError):
                continue
            targets = sent // self.probes
            if not sweep["obs"] or targets > sweep["obs"][-1][1]:
                sweep["obs"].append((seen, targets))
                self.readings += 1


class OverlapGate:
    def __init__(self, progress: ZmapProgress, order: dict[str, int], *, sweeps_total: int, rate_targets: float,
                 pace: float, slack: float = SLACK) -> None:
        self.progress = progress
        self.order = order
        self.per_sweep = len(order)
        self.sweeps_total = sweeps_total
        self.rate = max(1e-9, rate_targets * slack)
        self.pace = float(pace)

    def admit(self, ips: list[str], max_seconds: float) -> Callable[[float], bool]:
        """A check for ``ContactLedger.claim``: True once every address may be contacted for ``max_seconds``."""
        return lambda now: self.allowed(ips, now, max_seconds)

    def allowed(self, ips: list[str], now: float, max_seconds: float) -> bool:
        sweeps, done = self.progress.snapshot()
        return all(self._ok(ip, now, max_seconds, sweeps, done) for ip in ips)

    def _ok(self, ip: str, now: float, max_seconds: float, sweeps: list[dict], done: bool) -> bool:
        idx = self.order.get(ip)
        if idx is None:
            return False                       # not in the listed order: wait for the sequential path
        last_syn = None
        current = sweeps[-1] if sweeps and sweeps[-1]["end"] is None else None
        for s in sweeps:
            t = next((t for t, sent in s["obs"] if sent > idx), None)
            if t is None and s["end"] is not None:
                t = s["end"]
            if t is not None:
                last_syn = t if last_syn is None else max(last_syn, t)
        if last_syn is not None and now < last_syn + self.pace:
            return False
        if done and current is None:
            return True
        horizon = now + max_seconds + self.pace
        remaining = self.sweeps_total - len(sweeps)       # sweeps not started yet
        if current is not None:
            t0, p0 = current["obs"][-1] if current["obs"] else (current["start"], 0)
            reach = p0 + 1 + (now - t0) * self.rate           # furthest ZMap can be by now
            sent_here = any(sent > idx for _t, sent in current["obs"])
            if not sent_here:
                if idx < reach:
                    return False
                return now + (idx - reach) / self.rate >= horizon
            if remaining <= 0:
                return True
            # next SYN: the rest of this sweep, then the start of the next one up to this address
            return now + max(0.0, self.per_sweep - reach) / self.rate + idx / self.rate >= horizon
        if remaining <= 0 or done:
            return True
        return now + idx / self.rate >= horizon         # between sweeps: the next one may start at once
