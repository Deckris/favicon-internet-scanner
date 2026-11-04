"""Date-bounded reads from the public crt.sh PostgreSQL database.

``CrtShWindows`` walks a time range in short windows over one connection. Each window is turned into the set of
certificates whose CT log entry timestamp falls inside it, and the names of those certificates are read in chunks.
The public role has a short statement timeout and the shared pooler refuses connections when busy, so statements
are spaced at least ``min_gap_s`` apart, capped per run, and connection-level failures are retried with
exponential back-off and jitter. A statement that hits the server's statement timeout is not retried as is: the
window (or the chunk of certificates) is halved and read in two parts.

Windows are half-open, ``[start, end)``: a log entry stamped exactly ``end`` belongs to the next window. A window
close to the present may be incomplete, because entries reach the database with a delay.

The database is plain PostgreSQL, so there is no HTTP User-Agent. The identifying string passed as ``user_agent``
(which must contain a contact e-mail address or an http(s) URL) is sent as the connection's ``application_name``,
which the operator can see in the server's activity view.

``ct_log_entry.entry_timestamp`` is ``timestamp without time zone`` holding UTC. Window bounds are therefore sent
as naive UTC datetimes and the session time zone is set to UTC.

The name columns come from libx509pq: ``x509_altNames(cert, 2, TRUE)`` returns one row for every dNSName in the
subjectAltName extension (type 2, subject rather than issuer names) and ``x509_nameAttributes(cert,
'commonName', TRUE)`` one row for every commonName of the subject.
"""
from __future__ import annotations

import math
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
MIN_WINDOW = timedelta(seconds=1)
APPLICATION_NAME_BYTES = 63

ENTRIES_SQL = ("SELECT certificate_id, min(entry_timestamp) FROM ct_log_entry "
               "WHERE entry_timestamp >= %s AND entry_timestamp < %s GROUP BY certificate_id")
NAMES_SQL = ("SELECT c.id, ca.name, x509_altNames(c.certificate, 2, TRUE) FROM certificate c "
             "LEFT JOIN ca ON ca.id = c.issuer_ca_id WHERE c.id = ANY(%s) "
             "UNION "
             "SELECT c.id, ca.name, x509_nameAttributes(c.certificate, 'commonName', TRUE) FROM certificate c "
             "LEFT JOIN ca ON ca.id = c.issuer_ca_id WHERE c.id = ANY(%s)")

_EMAIL = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
_URL = r"https?://[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::\d+)?(?:/[^\s)]*)?"
CONTACT_RE = re.compile(f"{_URL}|{_EMAIL}")


class StatementCapReached(RuntimeError):
    """The per-run statement budget is used up."""


class StatementFailed(RuntimeError):
    """A statement still failed after ``max_retries`` retries."""


class StatementTimedOut(RuntimeError):
    """The server cancelled a statement because of its statement timeout."""


def find_contact(text: str) -> str | None:
    """The first e-mail address or http(s) URL in ``text``, or ``None``."""
    match = CONTACT_RE.search(text) if isinstance(text, str) else None
    return match.group(0) if match else None


def validate_identifier(text: Any) -> str:
    """Return ``text`` if it contains a contact e-mail address or http(s) URL; raise ``ValueError`` otherwise."""
    if not isinstance(text, str) or find_contact(text) is None:
        raise ValueError("the identifying string must contain a contact e-mail address (name@host.tld) or an http(s) URL")
    return text


def application_name(identifier: str) -> str:
    """The ``application_name`` sent for ``identifier``: printable ASCII, whitespace collapsed, at most 63 bytes.

    Characters such as ``@ : / . - _`` are kept. When the text is too long the contact is kept whole and the
    tool part before it is shortened.
    """
    text = re.sub(r"\s+", " ", identifier)
    text = re.sub(r"[^\x20-\x7e]", "", text).strip()
    if len(text) <= APPLICATION_NAME_BYTES:
        return text
    contact = find_contact(text)
    if contact is None or len(contact) >= APPLICATION_NAME_BYTES:
        return (contact or text)[:APPLICATION_NAME_BYTES]
    tool = text[:text.index(contact)].strip()
    room = APPLICATION_NAME_BYTES - len(contact) - 1
    return f"{tool[:room].rstrip()} {contact}".strip()


def default_connect(user_agent: str, dsn: str = DEFAULT_DSN):
    """Open an autocommit UTC-session connection; psycopg is imported here so the module loads without it."""
    import psycopg
    # the shared pooler drops server-side prepared statements, so they stay off
    return psycopg.connect(dsn, autocommit=True, prepare_threshold=None, connect_timeout=60,
                           application_name=application_name(user_agent), options="-c timezone=UTC")


def _class_names(exc: BaseException) -> set[str]:
    return {cls.__name__ for cls in type(exc).__mro__}


def _is_timeout(exc: BaseException) -> bool:
    return "QueryCanceled" in _class_names(exc)


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, (ConnectionError, TimeoutError)):
        return True
    return bool(_class_names(exc) & {"OperationalError", "InterfaceError"})


def _iso(stamp: Any) -> str:
    if not isinstance(stamp, datetime):
        return ""
    stamp = stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp.astimezone(UTC)
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def _naive_utc(stamp: datetime) -> datetime:
    return stamp.astimezone(UTC).replace(tzinfo=None)


def _finite(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


class CrtShWindows:
    def __init__(self, *, connect: Callable[[], Any], user_agent: str, min_gap_s: float = 1.0,
                 statement_cap: int = 5000, max_retries: int = 5, backoff_base_s: float = 2.0,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 rng: Callable[[], float] = random.random) -> None:
        if not _finite(min_gap_s) or min_gap_s < MIN_GAP_FLOOR_S:
            raise ValueError(f"min_gap_s must be a finite number of at least {MIN_GAP_FLOOR_S}")
        validate_identifier(user_agent)
        if not isinstance(statement_cap, int) or isinstance(statement_cap, bool) or statement_cap < 1:
            raise ValueError("statement_cap must be a positive integer")
        if not isinstance(max_retries, int) or isinstance(max_retries, bool) or max_retries < 0:
            raise ValueError("max_retries must be a non-negative integer")
        if not _finite(backoff_base_s) or backoff_base_s < 0:
            raise ValueError("backoff_base_s must be a finite, non-negative number")
        self.user_agent = user_agent
        self.min_gap_s, self.statement_cap, self.max_retries = min_gap_s, statement_cap, max_retries
        self.backoff_base_s = backoff_base_s
        self._connect, self._clock, self._sleep, self._rng = connect, clock, sleep, rng
        self._conn: Any = None
        self._last_sent: float | None = None
        self.statements = 0
        self.errors: list[str] = []   # windows or chunks given up on after repeated statement timeouts

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
                if _is_timeout(exc):
                    raise StatementTimedOut(type(exc).__name__) from exc
                if not _is_retryable(exc):
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
        """Observations for certificates logged in ``[start, end)``, read ``step`` at a time.

        ``start`` and ``end`` must be timezone-aware; they are converted to naive UTC for the query. A window that
        keeps hitting the statement timeout is halved down to one second and then recorded in ``errors``.
        """
        if not isinstance(start, datetime) or not isinstance(end, datetime) or start.tzinfo is None or end.tzinfo is None:
            raise ValueError("start and end must be timezone-aware datetimes")
        if step <= timedelta(0):
            raise ValueError("step must be positive")
        cursor = start
        while cursor < end:
            upper = min(end, cursor + step)
            yield from self._window(cursor, upper)
            cursor = upper

    def _window(self, lo: datetime, hi: datetime) -> Iterator[Observation]:
        try:
            rows = self._execute(ENTRIES_SQL, (_naive_utc(lo), _naive_utc(hi)))
        except StatementTimedOut:
            if hi - lo <= MIN_WINDOW:
                self.errors.append(f"window {_iso(lo)} to {_iso(hi)} timed out and was skipped")
                return
            mid = lo + (hi - lo) / 2
            yield from self._window(lo, mid)
            yield from self._window(mid, hi)
            return
        seen = {cid: stamp for cid, stamp in rows}
        yield from self._names(sorted(seen), seen, f"{_iso(lo)} to {_iso(hi)}")

    def _names(self, ids: list, seen: dict, label: str) -> Iterator[Observation]:
        for offset in range(0, len(ids), CHUNK):
            yield from self._chunk(ids[offset: offset + CHUNK], seen, label)

    def _chunk(self, chunk: list, seen: dict, label: str) -> Iterator[Observation]:
        try:
            rows = self._execute(NAMES_SQL, (chunk, chunk))
        except StatementTimedOut:
            if len(chunk) == 1:
                self.errors.append(f"certificate {chunk[0]} in window {label} timed out and was skipped")
                return
            half = len(chunk) // 2
            yield from self._chunk(chunk[:half], seen, label)
            yield from self._chunk(chunk[half:], seen, label)
            return
        for cid, issuer, raw in rows:
            name = normalize_name(raw) if raw else None
            if name is None:
                continue
            yield Observation(name=name, source="crtsh", seen_at=_iso(seen[cid]), cert_id=str(cid), issuer=issuer)
