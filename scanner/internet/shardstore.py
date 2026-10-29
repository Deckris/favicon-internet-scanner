"""Per-shard facts store: what every stage learned about each endpoint, kept on disk instead of in RAM.

The pipeline used to hold the TLS, HTTP, PTR, candidate-name, DNS, SNI and favicon results of every responsive
address in dictionaries until the write-out, which then built every output row at once. This store keeps the same
facts in one SQLite file (WAL, ``synchronous=NORMAL``) and hands them back one address at a time, in the order the
outputs are written in: by ``(ip, port)`` with the address compared as a string (``order="string"``), or by the
numeric value of the address (``order="numeric"``, the order of ``ip_results.csv``).

Concurrency: one connection guarded by one lock. SQLite allows a single writer anyway, so per-thread connections
would only add file-lock contention for the 512 favicon workers. Rows are JSON-encoded before the lock is taken and
collected in a small buffer that is written in one transaction (``batch_size`` rows, or whenever something is read),
so a worker holds the lock for a list append.

Values are stored as JSON of the result objects themselves (``TlsResult``, ``ZGrabResult``, ``Resolution``,
``EndpointNames`` and favicon record dicts) and come back as equal objects: tuples and sets are restored from the
lists they are written as. Text is written ASCII-escaped, so lone surrogates from hostile DNS or certificate text
survive. Keys use the same care: addresses must be ASCII and hostnames are stored as UTF-8 bytes with surrogates
passed through, whose byte order is the code point order Python sorts by (TEXT would be rejected by sqlite3 for a
lone surrogate).
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

from scanner.internet.candidates import EndpointNames
from scanner.models import CertificateInfo, ZGrabResult
from scanner.internet.tls import TlsResult
from scanner.zdns_runner import Resolution

_IN_CHUNK = 400          # host parameters per IN (...) query; the oldest SQLite builds allow 999


# ------------------------------------------------------------------ codecs

def _dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)


def _dump_obj(obj: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for f in fields(obj):
        v = getattr(obj, f.name)
        out[f.name] = _dump_obj(v) if is_dataclass(v) else (list(v) if isinstance(v, tuple) else v)
    return out


_TUPLE_FIELDS: dict[type, frozenset[str]] = {}


def _load_obj(cls: type, d: Mapping[str, Any]) -> Any:
    tuples = _TUPLE_FIELDS.get(cls)
    if tuples is None:
        tuples = _TUPLE_FIELDS[cls] = frozenset(f.name for f in fields(cls) if str(f.type).startswith("tuple"))
    kw: dict[str, Any] = {}
    for f in fields(cls):
        if f.name not in d:
            continue
        v = d[f.name]
        if f.name in tuples and v is not None:
            v = tuple(v)
        elif f.name == "certificate" and v is not None:
            v = _load_obj(CertificateInfo, v)
        kw[f.name] = v
    return cls(**kw)


def _dump_names(n: EndpointNames) -> str:
    return _dumps({"n": [[h, sorted(s)] for h, s in n.names.items()], "w": sorted(n.wildcards), "d": list(n.dropped),
                   "t": n.truncated, "c": n.source_count})


def _load_names(text: str) -> EndpointNames:
    d = json.loads(text)
    return EndpointNames(names={h: set(s) for h, s in d["n"]}, wildcards=set(d["w"]), dropped=list(d["d"]),
                         truncated=d["t"], source_count=d["c"])


def _transient(err: Exception) -> bool:
    """Disk-level failures that say nothing about the rows themselves."""
    if not isinstance(err, sqlite3.OperationalError):
        return False
    text = str(err).lower()
    return any(w in text for w in ("disk", "full", "locked", "busy", "readonly", "unable to open"))


def _ip(ip: str) -> str:
    if not ip.isascii():
        raise ValueError(f"not an address: {ip!r}")
    return ip


def _ipnum(ip: str) -> int:
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() and len(p) <= 3 for p in parts):
        a, b, c, d = (int(p) for p in parts)
        return (a << 24) | (b << 16) | (c << 8) | d
    return -1


def _hb(host: str | None) -> bytes:
    return (host or "").encode("utf-8", "surrogatepass")


def _hs(raw: bytes) -> str:
    return bytes(raw).decode("utf-8", "surrogatepass")


def _label(value: Any) -> str | None:
    """Short query label (outcome, status) kept beside a JSON document; never raises on odd text."""
    return None if value is None else str(value).encode("ascii", "backslashreplace").decode("ascii")


# ------------------------------------------------------------------ result types

@dataclass
class EndpointFacts:
    """Everything the stages recorded for one (ip, port). Absent facts are None / empty, as the dict lookups were."""
    ip: str
    port: int
    synack_window: int | None = None
    synack_ttl: int | None = None
    tls: TlsResult | None = None
    http: ZGrabResult | None = None
    names: EndpointNames = field(default_factory=EndpointNames)
    sni: dict[str, TlsResult] = field(default_factory=dict)           # hostname -> hostname-aware TLS result
    sni_skipped: dict[str, str] = field(default_factory=dict)         # hostname -> reason
    favicons: dict[str | None, dict[str, Any]] = field(default_factory=dict)    # hostname (None: bare IP) -> record
    sni_ok: bool = False                                              # some SNI handshake on this endpoint succeeded


@dataclass
class IpFacts:
    """One address with all its endpoints (ascending port) and the address-level facts."""
    ip: str
    ptr_names: list[str] = field(default_factory=list)
    ptr_status: str | None = None
    endpoints: list[EndpointFacts] = field(default_factory=list)
    resolutions: dict[str, Resolution] = field(default_factory=dict)  # for every candidate name of its endpoints


# ------------------------------------------------------------------ schema

_SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (ip TEXT NOT NULL, port INTEGER NOT NULL, ipnum INTEGER NOT NULL,
    PRIMARY KEY (ip, port)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS endpoints_port ON endpoints (port, ip);
CREATE INDEX IF NOT EXISTS endpoints_num ON endpoints (ipnum, ip);
CREATE TABLE IF NOT EXISTS synack (ip TEXT NOT NULL, port INTEGER NOT NULL, window INTEGER, ttl INTEGER,
    PRIMARY KEY (ip, port)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS synack_window ON synack (window);
CREATE TABLE IF NOT EXISTS tls_direct (ip TEXT NOT NULL, port INTEGER NOT NULL, outcome TEXT, data TEXT NOT NULL,
    PRIMARY KEY (ip, port)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS http_res (ip TEXT NOT NULL, port INTEGER NOT NULL, data TEXT NOT NULL,
    PRIMARY KEY (ip, port)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS ptr (ip TEXT NOT NULL PRIMARY KEY, data TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS ptr_sent (ip TEXT NOT NULL PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS names (ip TEXT NOT NULL, port INTEGER NOT NULL, data TEXT NOT NULL,
    PRIMARY KEY (ip, port)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS name_index (host BLOB NOT NULL PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS resolutions (host BLOB NOT NULL PRIMARY KEY, status TEXT, data TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS sni_res (ip TEXT NOT NULL, port INTEGER NOT NULL, host BLOB NOT NULL, ok INTEGER NOT NULL,
    data TEXT NOT NULL, PRIMARY KEY (ip, port, host)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS sni_skipped (ip TEXT NOT NULL, port INTEGER NOT NULL, host BLOB NOT NULL, reason TEXT,
    PRIMARY KEY (ip, port, host)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS favicon (ip TEXT NOT NULL, port INTEGER NOT NULL, host BLOB NOT NULL,
    first_idx INTEGER NOT NULL, last_idx INTEGER NOT NULL, outcome TEXT, data TEXT NOT NULL,
    PRIMARY KEY (ip, port, host)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS favicon_first ON favicon (first_idx);
CREATE TABLE IF NOT EXISTS ip_results (ipnum INTEGER NOT NULL, ip TEXT NOT NULL, data TEXT NOT NULL,
    PRIMARY KEY (ipnum, ip)) WITHOUT ROWID;
"""

_SQL = {
    "endpoints": "INSERT OR IGNORE INTO endpoints (ip, port, ipnum) VALUES (?,?,?)",
    "synack": "INSERT OR REPLACE INTO synack (ip, port, window, ttl) VALUES (?,?,?,?)",
    "tls_direct": "INSERT OR REPLACE INTO tls_direct (ip, port, outcome, data) VALUES (?,?,?,?)",
    "http_res": "INSERT OR REPLACE INTO http_res (ip, port, data) VALUES (?,?,?)",
    "ptr": "INSERT OR REPLACE INTO ptr (ip, data) VALUES (?,?)",
    "names": "INSERT OR REPLACE INTO names (ip, port, data) VALUES (?,?,?)",
    "name_index": "INSERT OR IGNORE INTO name_index (host) VALUES (?)",
    "resolutions": "INSERT OR REPLACE INTO resolutions (host, status, data) VALUES (?,?,?)",
    "sni_res": "INSERT OR REPLACE INTO sni_res (ip, port, host, ok, data) VALUES (?,?,?,?,?)",
    "sni_skipped": "INSERT OR REPLACE INTO sni_skipped (ip, port, host, reason) VALUES (?,?,?,?)",
    # A dict assigned in job order keeps the position of the first assignment and the value of the last one.
    "ip_results": "INSERT OR REPLACE INTO ip_results (ipnum, ip, data) VALUES (?,?,?)",
    "favicon": ("INSERT INTO favicon (ip, port, host, first_idx, last_idx, outcome, data) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT (ip, port, host) DO UPDATE SET "
                "first_idx = MIN(first_idx, excluded.first_idx), "
                "outcome = CASE WHEN excluded.last_idx >= last_idx THEN excluded.outcome ELSE outcome END, "
                "data = CASE WHEN excluded.last_idx >= last_idx THEN excluded.data ELSE data END, "
                "last_idx = MAX(last_idx, excluded.last_idx)"),
}


class ShardStore:
    """Facts of one shard run on disk. Safe to call from any number of threads."""

    def __init__(self, path: str | os.PathLike[str], *, reset: bool = False, batch_size: int = 200) -> None:
        self.path = Path(path)
        self._batch = max(1, batch_size)
        self._lock = threading.RLock()
        self._buf: dict[str, list[tuple[Any, ...]]] = {}
        self._pending = 0
        self._retry = False
        self.dropped_rows = 0          # buffered rows that could not be written
        self.errors: list[str] = []    # why, for the pipeline to record
        self._closed = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if reset:
            self._remove_files()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None, timeout=30)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA cache_size=-16384")
        self._db.execute("PRAGMA temp_store=FILE")
        self._db.executescript(_SCHEMA)

    # -------------------------------------------------------------- lifecycle

    def _remove_files(self) -> None:
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                os.remove(str(self.path) + suffix)
            except FileNotFoundError:
                pass

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _transaction(self, work: Any) -> None:
        """Run ``work(db)`` in one transaction; any exception, KeyboardInterrupt included, rolls it back first."""
        db = self._db
        db.execute("BEGIN")
        try:
            work(db)
            db.execute("COMMIT")
        except BaseException:
            try:
                db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    def _flush_locked(self) -> None:
        if not self._pending:
            return
        buf = self._buf
        items = [(key, row) for key, rows in buf.items() for row in rows]

        def write(db: sqlite3.Connection) -> None:
            for key, rows in buf.items():
                if rows:
                    db.executemany(_SQL[key], rows)

        try:
            self._transaction(write)
        except Exception as e:
            if _transient(e):
                if self._retry:
                    self._retry = False
                    self._drop(len(items), e)
                    return
                self._retry = True
                raise
            self._salvage(items)
            return
        self._retry = False
        self._buf = {}
        self._pending = 0

    def _drop(self, n: int, err: BaseException) -> None:
        self._buf, self._pending = {}, 0
        self.dropped_rows += n
        if len(self.errors) < 50:
            self.errors.append(f"{type(err).__name__}: {err}")

    def _salvage(self, items: list[tuple[str, tuple[Any, ...]]]) -> None:
        """A batch failed for a reason that may sit in one row: write the rows one by one, drop those that fail alone."""
        self._buf, self._pending = {}, 0
        for i, (key, row) in enumerate(items):
            try:
                self._transaction(lambda db, key=key, row=row: db.execute(_SQL[key], row))
            except Exception as e:
                if _transient(e):
                    for k, r in items[i:]:
                        self._buf.setdefault(k, []).append(r)
                    self._pending = len(items) - i
                    self._retry = True
                    raise
                self.dropped_rows += 1
                if len(self.errors) < 50:
                    self.errors.append(f"{type(e).__name__}: {e}")

    def close(self) -> None:
        """Flush and close. A failed final flush is recorded in ``errors`` and ``dropped_rows``, never raised."""
        with self._lock:
            if self._closed:
                return
            try:
                try:
                    self._flush_locked()
                except Exception as e:
                    self._drop(self._pending, e)
                try:
                    self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    pass
            finally:
                self._closed = True
                self._db.close()

    def delete(self) -> None:
        """Close the store and remove its files."""
        with self._lock:
            if not self._closed:
                self._buf, self._pending = {}, 0      # nothing to keep: skip the final flush
            self.close()
            self._remove_files()

    def __enter__(self) -> "ShardStore":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -------------------------------------------------------------- plumbing

    def _add(self, key: str, row: tuple[Any, ...]) -> None:
        with self._lock:
            self._buf.setdefault(key, []).append(row)
            self._pending += 1
            if self._pending >= self._batch:
                self._flush_locked()

    def _add_many(self, key: str, rows: list[tuple[Any, ...]]) -> None:
        if not rows:
            return
        with self._lock:
            self._buf.setdefault(key, []).extend(rows)
            self._pending += len(rows)
            if self._pending >= self._batch:
                self._flush_locked()

    def _query(self, sql: str, params: Sequence[Any] = ()) -> list[tuple[Any, ...]]:
        with self._lock:
            self._flush_locked()
            return self._db.execute(sql, params).fetchall()

    def _query_in(self, sql: str, keys: Sequence[Any], prefix: Sequence[Any] = ()) -> list[tuple[Any, ...]]:
        """``sql`` holds one ``{}`` for the placeholder list; ``keys`` are fed in chunks."""
        out: list[tuple[Any, ...]] = []
        with self._lock:
            self._flush_locked()
            for i in range(0, len(keys), _IN_CHUNK):
                chunk = keys[i:i + _IN_CHUNK]
                out.extend(self._db.execute(sql.format(",".join("?" * len(chunk))), [*prefix, *chunk]).fetchall())
        return out

    def _count(self, table: str) -> int:
        return self._query(f"SELECT COUNT(*) FROM {table}")[0][0]

    # -------------------------------------------------------------- endpoints (the union of the L4 results)

    def put_endpoints(self, endpoints: Iterable[tuple[str, int]]) -> None:
        self._add_many("endpoints", [(_ip(ip), int(port), _ipnum(ip)) for ip, port in endpoints])

    def count_endpoints(self) -> int:
        return self._count("endpoints")

    def count_unique_ips(self) -> int:
        return self._query("SELECT COUNT(*) FROM (SELECT DISTINCT ip FROM endpoints)")[0][0]

    def count_endpoints_by_port(self) -> dict[int, int]:
        return {p: n for p, n in self._query("SELECT port, COUNT(*) FROM endpoints GROUP BY port ORDER BY port")}

    def iter_endpoints(self, port: int | None = None, *, order: str = "string", page: int = 2000) -> Iterator[tuple[str, int]]:
        """(ip, port) pairs, ascending by (ip, port). ``port`` restricts to one port; ``order`` is "string" or "numeric"."""
        if order not in ("string", "numeric"):
            raise ValueError(order)
        if port is not None:
            last = ""
            while True:
                rows = self._query("SELECT ip FROM endpoints WHERE port = ? AND ip > ? ORDER BY ip LIMIT ?", (port, last, page)) \
                    if order == "string" else \
                    self._query("SELECT ip, ipnum FROM endpoints WHERE port = ? AND (ipnum, ip) > (?, ?) ORDER BY ipnum, ip LIMIT ?",
                                (port, *last, page)) if last else \
                    self._query("SELECT ip, ipnum FROM endpoints WHERE port = ? ORDER BY ipnum, ip LIMIT ?", (port, page))
                if not rows:
                    return
                for r in rows:
                    yield r[0], port
                last = rows[-1][0] if order == "string" else (rows[-1][1], rows[-1][0])
        elif order == "string":
            last_ep = ("", -1)
            while True:
                rows = self._query("SELECT ip, port FROM endpoints WHERE (ip, port) > (?, ?) ORDER BY ip, port LIMIT ?", (*last_ep, page))
                if not rows:
                    return
                yield from rows
                last_ep = rows[-1]
        else:
            last_n = (-2, "", -1)
            while True:
                rows = self._query("SELECT ip, port, ipnum FROM endpoints WHERE (ipnum, ip, port) > (?, ?, ?) "
                                   "ORDER BY ipnum, ip, port LIMIT ?", (last_n[0], last_n[1], last_n[2], page))
                if not rows:
                    return
                for ip, p, _n in rows:
                    yield ip, p
                last_n = (rows[-1][2], rows[-1][0], rows[-1][1])

    def iter_ips(self, *, order: str = "string", page: int = 256) -> Iterator[IpFacts]:
        """Every address with an endpoint, with all its facts, in write-out order. Nothing is held open between
        pages, so the stage may add facts (SNI, favicon) for addresses already yielded while it iterates."""
        if order not in ("string", "numeric"):
            raise ValueError(order)
        last: tuple[Any, ...] = ("",) if order == "string" else (-2, "")
        while True:
            if order == "string":
                rows = self._query("SELECT DISTINCT ip FROM endpoints WHERE ip > ? ORDER BY ip LIMIT ?", (*last, page))
                ips = [r[0] for r in rows]
            else:
                rows = self._query("SELECT DISTINCT ipnum, ip FROM endpoints WHERE (ipnum, ip) > (?, ?) ORDER BY ipnum, ip LIMIT ?",
                                   (*last, page))
                ips = [r[1] for r in rows]
            if not rows:
                return
            yield from self.group_many(ips)
            last = tuple(rows[-1])

    def iter_ip_names(self, *, order: str = "string", page: int = 5000) -> Iterator[str]:
        """Distinct addresses with an endpoint, ascending (cheap: no facts loaded)."""
        seen = None
        for ip, _p in self.iter_endpoints(order=order, page=page):
            if ip != seen:
                seen = ip
                yield ip

    # -------------------------------------------------------------- SYN-ACK

    def put_synack(self, ip: str, port: int, window: int | None, ttl: int | None) -> None:
        self._add("synack", (_ip(ip), int(port), window, ttl))

    def put_synack_port(self, port: int, fields_by_ip: Mapping[str, Mapping[str, int | None]]) -> None:
        """Rows of ``enrich.parse_synack_csv`` for one port sweep."""
        self._add_many("synack", [(_ip(ip), int(port), f.get("window"), f.get("ttl")) for ip, f in fields_by_ip.items()])

    def get_synack(self, ip: str, port: int) -> dict[str, int | None]:
        """{"window", "ttl"}, or {} when the endpoint has no entry (as ``synack.get(ep, {})``)."""
        rows = self._query("SELECT window, ttl FROM synack WHERE ip = ? AND port = ?", (ip, port))
        return {"window": rows[0][0], "ttl": rows[0][1]} if rows else {}

    def tarpit_ips(self, tiny_window_below: int) -> set[str]:
        """Addresses with a SYN-ACK window below the threshold on any port (the old ``tarpits()``)."""
        return {r[0] for r in self._query("SELECT DISTINCT ip FROM synack WHERE window IS NOT NULL AND window < ?",
                                          (tiny_window_below,))}

    # -------------------------------------------------------------- direct-IP TLS

    def put_tls(self, r: TlsResult) -> None:
        self._add("tls_direct", (_ip(r.ip), r.port, _label(r.outcome), _dumps(_dump_obj(r))))

    def put_tls_many(self, results: Iterable[TlsResult]) -> None:
        self._add_many("tls_direct", [(_ip(r.ip), r.port, _label(r.outcome), _dumps(_dump_obj(r))) for r in results if r.ip])

    def get_tls(self, ip: str, port: int) -> TlsResult | None:
        rows = self._query("SELECT data FROM tls_direct WHERE ip = ? AND port = ?", (ip, port))
        return _load_obj(TlsResult, json.loads(rows[0][0])) if rows else None

    def count_tls(self) -> int:
        return self._count("tls_direct")

    def delete_tls_for_ips(self, ips: Iterable[str]) -> list[tuple[str, int]]:
        """Drop the direct-IP results of these addresses; returns the (ip, port) pairs removed, ascending."""
        wanted = sorted(set(ips))
        hit = sorted((ip, p) for ip, p in self._query_in("SELECT ip, port FROM tls_direct WHERE ip IN ({})", wanted))
        with self._lock:
            self._transaction(lambda db: db.executemany("DELETE FROM tls_direct WHERE ip = ? AND port = ?", hit))
        return hit

    def iter_endpoints_with_tls_outcome(self, outcomes: Iterable[str], *, page: int = 2000) -> Iterator[tuple[str, int]]:
        """Endpoints whose direct-IP TLS outcome is one of ``outcomes``, in endpoint order (HTTP fallback targets)."""
        marks = sorted({_label(o) for o in outcomes})
        if not marks:
            return
        sql = ("SELECT e.ip, e.port FROM endpoints e JOIN tls_direct t ON t.ip = e.ip AND t.port = e.port "
               f"WHERE t.outcome IN ({','.join('?' * len(marks))}) AND (e.ip, e.port) > (?, ?) ORDER BY e.ip, e.port LIMIT ?")
        last: tuple[str, int] = ("", -1)
        while True:
            rows = self._query(sql, [*marks, *last, page])
            if not rows:
                return
            yield from rows
            last = rows[-1]

    # -------------------------------------------------------------- plain HTTP

    def put_http(self, r: ZGrabResult) -> None:
        self._add("http_res", (_ip(r.target_ip), r.port, _dumps(_dump_obj(r))))

    def put_http_many(self, results: Iterable[ZGrabResult]) -> None:
        self._add_many("http_res", [(_ip(r.target_ip), r.port, _dumps(_dump_obj(r))) for r in results if r.target_ip])

    def get_http(self, ip: str, port: int) -> ZGrabResult | None:
        rows = self._query("SELECT data FROM http_res WHERE ip = ? AND port = ?", (ip, port))
        return _load_obj(ZGrabResult, json.loads(rows[0][0])) if rows else None

    # -------------------------------------------------------------- PTR

    def put_ptr(self, ip: str, names: Sequence[str], status: str) -> None:
        self._add("ptr", (_ip(ip), _dumps({"names": list(names), "status": status})))

    def put_ptr_many(self, rows: Iterable[tuple[str, Sequence[str], str]]) -> None:
        self._add_many("ptr", [(_ip(ip), _dumps({"names": list(n), "status": s})) for ip, n, s in rows])

    def fill_missing_ptr(self, status: str = "NO_OUTPUT") -> int:
        """Give every endpoint address without a PTR entry an empty one (the old ``ans.get(ip)`` of None)."""
        with self._lock:
            self._flush_locked()
            cur = self._db.execute("INSERT OR IGNORE INTO ptr (ip, data) SELECT DISTINCT ip, ? FROM endpoints",
                                   (_dumps({"names": [], "status": status}),))
            return cur.rowcount

    def get_ptr(self, ip: str) -> tuple[list[str], str | None]:
        """(names, status); ([], None) when the stage never produced an entry."""
        rows = self._query("SELECT data FROM ptr WHERE ip = ?", (ip,))
        if not rows:
            return [], None
        d = json.loads(rows[0][0])
        return list(d["names"]), d["status"]

    def mark_ptr_sent(self, ips: Iterable[str]) -> list[str]:
        """Record addresses whose PTR lookup was started; returns those not marked before, in the order given."""
        new: list[str] = []
        wanted = [(ip, _ip(ip)) for ip in ips]

        def work(db: sqlite3.Connection) -> None:
            new.clear()
            for ip, key in wanted:
                if db.execute("INSERT OR IGNORE INTO ptr_sent (ip) VALUES (?)", (key,)).rowcount:
                    new.append(ip)

        with self._lock:
            self._transaction(work)
        return new

    def unmark_ptr_sent(self, ips: Iterable[str]) -> None:
        with self._lock:
            self._db.executemany("DELETE FROM ptr_sent WHERE ip = ?", [(ip,) for ip in ips])

    def iter_unsent_ptr_ips(self, *, page: int = 5000) -> Iterator[str]:
        """Endpoint addresses not marked as sent, ascending (the old ``missing`` list)."""
        last = ""
        while True:
            rows = self._query("SELECT DISTINCT e.ip FROM endpoints e WHERE e.ip > ? AND NOT EXISTS "
                               "(SELECT 1 FROM ptr_sent s WHERE s.ip = e.ip) ORDER BY e.ip LIMIT ?", (last, page))
            if not rows:
                return
            for r in rows:
                yield r[0]
            last = rows[-1][0]

    # -------------------------------------------------------------- candidate names

    def put_names(self, ip: str, port: int, names: EndpointNames) -> None:
        rows = [(_hb(h),) for h in names.names]
        with self._lock:
            self._add("names", (_ip(ip), int(port), _dump_names(names)))
            self._add_many("name_index", rows)

    def get_names(self, ip: str, port: int) -> EndpointNames:
        """The endpoint's names; an empty EndpointNames when none were stored (``names_by_ep.setdefault``)."""
        rows = self._query("SELECT data FROM names WHERE ip = ? AND port = ?", (ip, port))
        return _load_names(rows[0][0]) if rows else EndpointNames()

    def iter_candidate_names(self, *, page: int = 5000) -> Iterator[str]:
        """Distinct candidate hostnames over all endpoints, ascending: ``sorted({n for e in names_by_ep.values() ...})``."""
        last = b""
        while True:
            rows = self._query("SELECT host FROM name_index WHERE host > ? ORDER BY host LIMIT ?", (last, page))
            if not rows:
                return
            for r in rows:
                yield _hs(r[0])
            last = bytes(rows[-1][0])

    def count_candidate_names(self) -> int:
        return self._count("name_index")

    # -------------------------------------------------------------- forward resolutions

    def put_resolutions(self, items: Iterable[Resolution]) -> None:
        self._add_many("resolutions", [(_hb(r.hostname), _label(r.status), _dumps(_dump_obj(r))) for r in items])

    def get_resolutions(self, hosts: Iterable[str]) -> dict[str, Resolution]:
        """Resolutions for the hosts that have one (``resolutions.get(host)`` is None for the others)."""
        keys = sorted({_hb(h) for h in hosts})
        out: dict[str, Resolution] = {}
        for host, data in self._query_in("SELECT host, data FROM resolutions WHERE host IN ({})", keys):
            out[_hs(host)] = _load_obj(Resolution, json.loads(data))
        return out

    def get_resolution(self, host: str) -> Resolution | None:
        return self.get_resolutions([host]).get(host)

    def resolution_status_counts(self) -> dict[str, int]:
        """{status: n}; feeds ``enrich.dns_unknown_share`` without loading the resolutions."""
        return {s: n for s, n in self._query("SELECT status, COUNT(*) FROM resolutions GROUP BY status")}

    def count_resolutions(self) -> int:
        return self._count("resolutions")

    # -------------------------------------------------------------- SNI confirmation

    def put_sni(self, r: TlsResult) -> None:
        self._add("sni_res", (_ip(r.ip), r.port, _hb(r.sni), 1 if r.ok else 0, _dumps(_dump_obj(r))))

    def put_sni_skipped(self, ip: str, port: int, host: str, reason: str) -> None:
        self._add("sni_skipped", (_ip(ip), int(port), _hb(host), _label(reason)))

    def put_sni_skipped_many(self, rows: Iterable[tuple[str, int, str, str]]) -> None:
        self._add_many("sni_skipped", [(_ip(ip), int(port), _hb(h), _label(why)) for ip, port, h, why in rows])

    def get_sni(self, ip: str, port: int, host: str) -> TlsResult | None:
        rows = self._query("SELECT data FROM sni_res WHERE ip = ? AND port = ? AND host = ?", (ip, port, _hb(host)))
        return _load_obj(TlsResult, json.loads(rows[0][0])) if rows else None

    def sni_ok(self, ip: str, port: int) -> bool:
        return bool(self._query("SELECT 1 FROM sni_res WHERE ip = ? AND port = ? AND ok = 1 LIMIT 1", (ip, port)))

    # -------------------------------------------------------------- favicon records

    def put_favicon(self, job_idx: int, rec: Mapping[str, Any]) -> None:
        """``job_idx`` is the record's position in the job list. Two records for one (ip, port, hostname): the later
        job's record wins, and the key keeps the position of the earlier job, as the dict assignment did."""
        self._add("favicon", self._fav_row(job_idx, rec))

    def put_favicon_many(self, items: Iterable[tuple[int, Mapping[str, Any]]]) -> None:
        self._add_many("favicon", [self._fav_row(i, rec) for i, rec in items])

    @staticmethod
    def _fav_row(idx: int, rec: Mapping[str, Any]) -> tuple[Any, ...]:
        return (_ip(rec["ip"]), int(rec["port"]), _hb(rec.get("hostname")), idx, idx, _label(rec.get("favicon_outcome")), _dumps(rec))

    def get_favicon(self, ip: str, port: int, hostname: str | None) -> dict[str, Any] | None:
        rows = self._query("SELECT data FROM favicon WHERE ip = ? AND port = ? AND host = ?", (ip, port, _hb(hostname)))
        return json.loads(rows[0][0]) if rows else None

    def iter_favicons(self, *, page: int = 500) -> Iterator[dict[str, Any]]:
        """Records in job order (the old ``fav_res.values()``); ``IconStore.write_index`` accepts this iterator."""
        last = -1
        while True:
            rows = self._query("SELECT first_idx, data FROM favicon WHERE first_idx > ? ORDER BY first_idx LIMIT ?", (last, page))
            if not rows:
                return
            for _i, data in rows:
                yield json.loads(data)
            last = rows[-1][0]

    def count_favicons(self) -> int:
        return self._count("favicon")

    def count_favicon_outcome(self, outcome: str) -> int:
        return self._query("SELECT COUNT(*) FROM favicon WHERE outcome = ?", (_label(outcome),))[0][0]

    # -------------------------------------------------------------- per-address result rows (spool for ip_results.csv)

    def put_ip_result(self, ip: str, row: Mapping[str, Any]) -> None:
        """Park the finished ip_results row of an address; ``iter_ip_results`` returns them in numeric address order."""
        self._add("ip_results", (_ipnum(ip), _ip(ip), _dumps(row)))

    def iter_ip_results(self, *, page: int = 1000) -> Iterator[tuple[str, dict[str, Any]]]:
        last: tuple[int, str] = (-2, "")
        while True:
            rows = self._query("SELECT ipnum, ip, data FROM ip_results WHERE (ipnum, ip) > (?, ?) ORDER BY ipnum, ip LIMIT ?", (*last, page))
            if not rows:
                return
            for _n, ip, data in rows:
                yield ip, json.loads(data)
            last = (rows[-1][0], rows[-1][1])

    # -------------------------------------------------------------- per-address groups

    def group(self, ip: str) -> IpFacts:
        return self.group_many([ip])[0]

    def group_many(self, ips: Sequence[str]) -> list[IpFacts]:
        """Facts of several addresses in one pass over each table, returned in the order given."""
        ips = list(ips)
        if not ips:
            return []
        eps = self._query_in("SELECT ip, port FROM endpoints WHERE ip IN ({})", ips)
        synack = {(r[0], r[1]): (r[2], r[3]) for r in self._query_in("SELECT ip, port, window, ttl FROM synack WHERE ip IN ({})", ips)}
        tls = {(r[0], r[1]): r[2] for r in self._query_in("SELECT ip, port, data FROM tls_direct WHERE ip IN ({})", ips)}
        http = {(r[0], r[1]): r[2] for r in self._query_in("SELECT ip, port, data FROM http_res WHERE ip IN ({})", ips)}
        names = {(r[0], r[1]): r[2] for r in self._query_in("SELECT ip, port, data FROM names WHERE ip IN ({})", ips)}
        ptr = {r[0]: r[1] for r in self._query_in("SELECT ip, data FROM ptr WHERE ip IN ({})", ips)}
        sni = self._query_in("SELECT ip, port, host, ok, data FROM sni_res WHERE ip IN ({})", ips)
        skipped = self._query_in("SELECT ip, port, host, reason FROM sni_skipped WHERE ip IN ({})", ips)
        fav = self._query_in("SELECT ip, port, host, data FROM favicon WHERE ip IN ({})", ips)

        by_ep: dict[tuple[str, int], EndpointFacts] = {}
        out: dict[str, IpFacts] = {ip: IpFacts(ip) for ip in ips}
        for ip, port in sorted(eps):
            ef = EndpointFacts(ip, port)
            if (ip, port) in synack:
                ef.synack_window, ef.synack_ttl = synack[(ip, port)]
            if (ip, port) in tls:
                ef.tls = _load_obj(TlsResult, json.loads(tls[(ip, port)]))
            if (ip, port) in http:
                ef.http = _load_obj(ZGrabResult, json.loads(http[(ip, port)]))
            if (ip, port) in names:
                ef.names = _load_names(names[(ip, port)])
            by_ep[(ip, port)] = ef
            out[ip].endpoints.append(ef)
        for ip, port, host, ok, data in sni:
            ef = by_ep.get((ip, port))
            if ef is not None:
                ef.sni[_hs(host)] = _load_obj(TlsResult, json.loads(data))
                ef.sni_ok = ef.sni_ok or bool(ok)
        for ip, port, host, reason in skipped:
            ef = by_ep.get((ip, port))
            if ef is not None:
                ef.sni_skipped[_hs(host)] = reason
        for ip, port, host, data in fav:
            ef = by_ep.get((ip, port))
            if ef is not None:
                ef.favicons[_hs(host) or None] = json.loads(data)
        for ip, text in ptr.items():
            d = json.loads(text)
            out[ip].ptr_names, out[ip].ptr_status = list(d["names"]), d["status"]
        hosts = {h for ef in by_ep.values() for h in ef.names.names}
        if hosts:
            res = self.get_resolutions(hosts)
            for g in out.values():
                g.resolutions = {h: res[h] for ef in g.endpoints for h in ef.names.names if h in res}
        return [out[ip] for ip in ips]


__all__ = ["ShardStore", "IpFacts", "EndpointFacts"]
