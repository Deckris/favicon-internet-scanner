"""Off-host icon fetching for several favicon worker processes.

Why a parent-side service and not a shared SQLite file: the off-host fetcher owns state that has to be exact
across every process of the stage -- the run-wide and per-host request caps (saved between shards), the cache of
fetched URLs, the per-destination pause and the per-/24 cap of simultaneous connections. A file shared by the
processes would need a transaction around every cap check and a lock-wait loop around every pause, and still
could not hold a request back for a destination another process is talking to. One fetcher in the parent, fed
over a pipe per worker, keeps all of that in memory under the locks it already has, fetches each URL once
however many pages name it, and contacts each destination address through one pacer. The workers keep the
sampled-address fetchers and their one-process-per-address rule exactly as before; only the icon URLs on other
hosts travel through here. Requests are small (a URL and the page it came from) and replies carry a body of
at most ``favicon.offhost_icons.max_bytes``.
"""
from __future__ import annotations

import itertools
import queue
import threading
from typing import Any

from scanner.models import FetchResult

SERVICE_DOWN = "offhost_service_unavailable"
_WAKE_SECONDS = 1.0


def refused(url: str, reason: str) -> tuple[FetchResult, None]:
    """A policy-refused result for a request that never left the worker."""
    return FetchResult(
        kind="favicon", requested_url=url, connect_ip=None, host_header=None, sni=None, outcome="policy_refused",
        failure_category=reason, http_status=None, content_type=None, content_encoding=None, retry_after=None,
        body_sha256=None, body_bytes=0, redirect_chain=(), final_url=url, certificate=None), None


class OffhostClient:
    """Worker-process end: ``fetch`` has the signature of a fetcher and is safe to call from many threads."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn
        self._send = threading.Lock()
        self._lock = threading.Lock()
        self._waiting: dict[int, list[Any]] = {}      # request id -> [event, reply]
        self._ids = itertools.count()
        self._down = False
        threading.Thread(target=self._read, daemon=True, name="offhost-client").start()

    def fetch(self, url: str, *, connect_ip: str | None, kind: str, context: str = ""):
        if connect_ip is not None or kind != "favicon":
            return refused(url, "offhost_favicons_only")
        slot: list[Any] = [threading.Event(), None]
        with self._lock:
            if self._down:
                return refused(url, SERVICE_DOWN)
            rid = next(self._ids)
            self._waiting[rid] = slot
        try:
            with self._send:
                self._conn.send(("fetch", rid, url, context))
        except (OSError, ValueError):
            self._fail()
        while not slot[0].wait(_WAKE_SECONDS):
            if self._down:
                break
        with self._lock:
            self._waiting.pop(rid, None)
        return slot[1] if slot[1] is not None else refused(url, SERVICE_DOWN)

    def _read(self) -> None:
        while True:
            try:
                kind, rid, result = self._conn.recv()
            except (EOFError, OSError, ValueError):
                self._fail()
                return
            with self._lock:
                slot = self._waiting.get(rid)
            if slot is not None and kind == "res":
                slot[1] = result
                slot[0].set()

    def _fail(self) -> None:
        with self._lock:
            self._down = True
            slots = list(self._waiting.values())
        for slot in slots:
            slot[0].set()


class OffhostService:
    """Parent end: serves the requests of every worker from one fetcher on a bounded set of threads."""

    def __init__(self, fetcher: Any, *, threads: int = 32) -> None:
        self.fetcher = fetcher
        self._tasks: queue.SimpleQueue = queue.SimpleQueue()
        self._conns: list[Any] = []
        self._closed = False
        for n in range(max(1, threads)):
            threading.Thread(target=self._work, daemon=True, name=f"offhost-service-{n}").start()

    def open_channel(self, ctx: Any) -> Any:
        """Create a duplex pipe, start serving its parent end, and return the end for a worker process."""
        mine, theirs = ctx.Pipe(duplex=True)
        send = threading.Lock()
        self._conns.append(mine)
        threading.Thread(target=self._serve, args=(mine, send), daemon=True, name="offhost-channel").start()
        return theirs

    def _serve(self, conn: Any, send: Any) -> None:
        while not self._closed:
            try:
                message = conn.recv()
            except (EOFError, OSError, ValueError):
                return
            if isinstance(message, tuple) and len(message) == 4 and message[0] == "fetch":
                self._tasks.put((conn, send, message[1], message[2], message[3]))

    def _work(self) -> None:
        while True:
            task = self._tasks.get()
            if task is None:
                return
            conn, send, rid, url, context = task
            try:
                result = self.fetcher.fetch(url, connect_ip=None, kind="favicon", context=str(context))
            except Exception:
                result = refused(url, "offhost_fetch_error")
            try:
                with send:
                    conn.send(("res", rid, result))
            except (OSError, ValueError):
                pass        # the worker is gone

    def close(self) -> None:
        self._closed = True
        for conn in self._conns:
            try:
                conn.close()
            except OSError:
                pass
