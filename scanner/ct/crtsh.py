"""Date-bounded reads from the public crt.sh PostgreSQL database.

``CrtShWindows`` walks a time range in short windows over one connection. Each window is turned into the set of
certificates whose CT log entry timestamp falls inside it, and the names of those certificates are read in chunks.
The public role has a short statement timeout and the shared pooler refuses connections when busy, so statements
are spaced at least ``min_gap_s`` apart, capped per run, and only connection-level failures are retried, with
exponential back-off and jitter.
"""
from __future__ import annotations

import random
import re
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

from scanner.ct.models import Observation
from scanner.ct.names import normalize_name

DEFAULT_DSN = "postgresql://guest@crt.sh:5432/certwatch"
MIN_GAP_FLOOR_S = 1.0
CHUNK = 400
MAX_BACKOFF_S = 120.0

ENTRIES_SQL = ("SELECT certificate_id, min(entry_timestamp) FROM ct_log_entry "
               "WHERE entry_timestamp >= %s AND entry_timestamp < %s GROUP BY certificate_id")
NAMES_SQL = ("SELECT c.id, ca.name, x509_altNames(c.certificate, 2, TRUE) FROM certificate c "
             "LEFT JOIN ca ON ca.id = c.issuer_ca_id WHERE c.id = ANY(%s) "
             "UNION "
             "SELECT c.id, ca.name, x509_nameAttributes(c.certificate, 'commonName', TRUE) FROM certificate c "
             "LEFT JOIN ca ON ca.id = c.issuer_ca_id WHERE c.id = ANY(%s)")


class StatementCapReached(RuntimeError):
    """The per-run statement budget is used up."""


class StatementFailed(RuntimeError):
    """A statement still failed after ``max_retries`` retries."""


def _application_name(user_agent: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", user_agent.split("(")[0].strip()).strip("-")
    return (cleaned or "ct-reader")[:60]


def default_connect(user_agent: str, dsn: str = DEFAULT_DSN):
    """Open an autocommit connection; psycopg is imported here so the module loads without it."""
    import psycopg
    # the shared pooler drops server-side prepared statements, so they stay off
    return psycopg.connect(dsn, autocommit=True, prepare_threshold=None, connect_timeout=60,
                           application_name=_application_name(user_agent))


def _is_operational(exc: BaseException) -> bool:
    if isinstance(exc, (ConnectionError, TimeoutError)):
        return True
    return any(cls.__name__ == "OperationalError" for cls in type(exc).__mro__)


def _iso(stamp: Any) -> str:
    if not isinstance(stamp, datetime):
        return ""
    stamp = stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp.astimezone(UTC)
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


class CrtShWindows:
    def __init__(self, *, connect: Callable[[], Any], user_agent: str, min_gap_s: float = 1.0,
                 statement_cap: int = 5000, max_retries: int = 5, backoff_base_s: float = 2.0,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 rng: Callable[[], float] = random.random) -> None:
        if min_gap_s < MIN_GAP_FLOOR_S:
            raise ValueError(f"min_gap_s must be at least {MIN_GAP_FLOOR_S}")
        if not isinstance(user_agent, str) or not user_agent.strip() or not ("@" in user_agent or "http" in user_agent):
            raise ValueError("user_agent must be non-empty and include a contact (an address or a URL)")
        if statement_cap < 1 or max_retries < 0 or backoff_base_s < 0:
            raise ValueError("statement_cap must be positive; max_retries and backoff_base_s must not be negative")
        self.user_agent = user_agent
        self.min_gap_s, self.statement_cap, self.max_retries = min_gap_s, statement_cap, max_retries
        self.backoff_base_s = backoff_base_s
        self._connect, self._clock, self._sleep, self._rng = connect, clock, sleep, rng
        self._conn: Any = None
        self._last_sent: float | None = None
        self.statements = 0

    def _execute(self, sql: str, params: tuple) -> list[tuple]:
        retries = 0
        while True:
            if self.statements >= self.statement_cap:
                raise StatementCapReached(f"statement cap of {self.statement_cap} reached")
            if self._last_sent is not None:
                wait = self.min_gap_s - (self._clock() - self._last_sent)
                if wait > 0:
                    self._sleep(wait)
            self._last_sent = self._clock()
            self.statements += 1
            try:
                if self._conn is None:
                    self._conn = self._connect()
                return list(self._conn.execute(sql, params).fetchall())
            except Exception as exc:
                if not _is_operational(exc):
                    raise
                self._drop_connection()
                if retries >= self.max_retries:
                    raise StatementFailed(f"statement failed after {retries} retries: {type(exc).__name__}") from exc
                delay = min(self.backoff_base_s * 2 ** retries, MAX_BACKOFF_S)
                self._sleep(delay * (1.0 + self._rng()))
                retries += 1

    def _drop_connection(self) -> None:
        conn, self._conn = self._conn, None
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass

    def close(self) -> None:
        self._drop_connection()

    def iter_window(self, start: datetime, end: datetime, *, step: timedelta = timedelta(minutes=1)) -> Iterator[Observation]:
        if step <= timedelta(0):
            raise ValueError("step must be positive")
        cursor = start
        while cursor < end:
            upper = min(end, cursor + step)
            yield from self._slice(cursor, upper)
            cursor = upper

    def _slice(self, lo: datetime, hi: datetime) -> Iterator[Observation]:
        seen = {cid: stamp for cid, stamp in self._execute(ENTRIES_SQL, (lo, hi))}
        ids = sorted(seen)
        for offset in range(0, len(ids), CHUNK):
            chunk = ids[offset: offset + CHUNK]
            for cid, issuer, raw in self._execute(NAMES_SQL, (chunk, chunk)):
                name = normalize_name(raw) if raw else None
                if name is None:
                    continue
                yield Observation(name=name, source="crtsh", seen_at=_iso(seen[cid]), cert_id=str(cid), issuer=issuer)
