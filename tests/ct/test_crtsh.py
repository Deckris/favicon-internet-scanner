import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from scanner.ct import crtsh
from scanner.ct.crtsh import CrtShWindows, StatementCapReached, StatementFailed

ROOT = Path(__file__).resolve().parents[2]
UA = "ct-reader/1.0 (+mailto:ops@example.test)"
T0 = datetime(2025, 3, 1, 10, 0, tzinfo=UTC)


class OperationalError(Exception):
    """Same class name as the driver's connection-level error."""


class InterfaceError(Exception):
    """Same class name as the driver's closed-connection error."""


class QueryCanceled(OperationalError):
    """Same class name and base as the driver's statement-timeout error."""


class SqlError(Exception):
    pass


class FakeClock:
    def __init__(self):
        self.now = 100.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows


class FakeConn:
    def __init__(self, db):
        self.db = db
        self.closed = False

    def execute(self, sql, params):
        return FakeCursor(self.db.run(sql, params))

    def close(self):
        self.closed = True


class FakeDb:
    """Serves one entry row per window start and a fixed set of name rows; can fail on chosen calls."""

    def __init__(self, fail=None, entries=None, names=None):
        self.calls = []
        self.fail = dict(fail or {})
        self.entries = entries if entries is not None else {1: datetime(2025, 3, 1, 10, 0, 5), 2: datetime(2025, 3, 1, 10, 0, 9)}
        self.names = names if names is not None else [
            (1, "Test CA One", "www.one.example"),
            (1, "Test CA One", "*.one.example"),
            (1, "Test CA One", "one.example"),
            (2, "Test CA Two", "two.invalid"),
            (2, "Test CA Two", "192.0.2.5"),
            (2, "Test CA Two", None),
        ]
        self.connects = 0
        self.served = 0

    def connect(self):
        self.connects += 1
        return FakeConn(self)

    def run(self, sql, params):
        self.calls.append((sql, params))
        n = len(self.calls)
        if n in self.fail:
            raise self.fail[n]
        if sql == crtsh.ENTRIES_SQL:
            self.served += 1
            return list(self.entries.items()) if self.served == 1 else []
        return self.names


def make(db, clock, **kw):
    return CrtShWindows(connect=db.connect, user_agent=UA, clock=clock, sleep=clock.sleep, rng=lambda: 0.0, **kw)


def test_import_does_not_load_psycopg():
    code = "import sys, scanner.ct.crtsh; sys.exit(1 if 'psycopg' in sys.modules else 0)"
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    assert subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env).returncode == 0


def test_default_dsn():
    assert crtsh.DEFAULT_DSN == "postgresql://guest@crt.sh:5432/certwatch"


def test_default_connect_options(monkeypatch):
    seen = {}

    class Fake:
        @staticmethod
        def connect(dsn, **kw):
            seen.update(dsn=dsn, **kw)
            return "conn"

    monkeypatch.setitem(sys.modules, "psycopg", Fake)
    assert crtsh.default_connect("Scan Tool/2.0 (+mailto:a@example.test)") == "conn"
    assert seen["dsn"] == crtsh.DEFAULT_DSN
    assert seen["autocommit"] is True
    assert seen["prepare_threshold"] is None
    assert seen["application_name"] == "Scan Tool/2.0 (+mailto:a@example.test)"
    assert seen["options"] == "-c timezone=UTC"


@pytest.mark.parametrize("text, expected", [
    ("tester (mailto:ops@example.com)", "tester (mailto:ops@example.com)"),
    ("tool/1.0\t(+https://example.test/c)\n", "tool/1.0 (+https://example.test/c)"),
    ("a\x00b  c ops@example.test", "ab c ops@example.test"),
])
def test_application_name_keeps_the_contact_characters(text, expected):
    assert crtsh.application_name(text) == expected


def test_application_name_truncation_prefers_the_contact():
    contact = "ops@mail.example.test"
    name = crtsh.application_name("very-long-tool-name-" * 5 + "/1.0 " + contact)
    assert len(name.encode()) <= 63 and name.endswith(" " + contact)
    long_contact = "x" * 70 + "@example.test"
    assert len(crtsh.application_name("t " + long_contact).encode()) == 63


@pytest.mark.parametrize("kw", [
    {"min_gap_s": 0.5},
    {"user_agent": ""},
    {"user_agent": "   "},
    {"user_agent": "plain-agent/1.0"},
    {"user_agent": "httpx"},
    {"user_agent": "a@"},
    {"user_agent": "name@localhost"},
    {"user_agent": "https://"},
    {"statement_cap": 0},
    {"statement_cap": float("inf")},
    {"min_gap_s": float("nan")},
    {"min_gap_s": float("inf")},
    {"backoff_base_s": float("nan")},
    {"backoff_base_s": float("inf")},
    {"backoff_base_s": -1.0},
    {"max_retries": -1},
])
def test_guards(kw):
    args = {"connect": lambda: None, "user_agent": UA, **kw}
    with pytest.raises(ValueError):
        CrtShWindows(**args)


@pytest.mark.parametrize("agent", [
    "tool/1.0 (+https://example.test/contact)",
    "tool ops@example.test",
    "http://example.test",
])
def test_contacts_are_accepted(agent):
    CrtShWindows(connect=lambda: None, user_agent=agent)


def test_yields_normalized_observations():
    clock, db = FakeClock(), FakeDb()
    out = list(make(db, clock).iter_window(T0, T0 + timedelta(minutes=1)))
    assert [(o.name, o.cert_id, o.issuer) for o in out] == [
        ("www.one.example", "1", "Test CA One"),
        ("one.example", "1", "Test CA One"),
        ("two.invalid", "2", "Test CA Two"),
    ]
    assert {o.source for o in out} == {"crtsh"}
    assert [o.seen_at for o in out] == ["2025-03-01T10:00:05Z", "2025-03-01T10:00:05Z", "2025-03-01T10:00:09Z"]


def test_windows_cover_range_in_steps():
    clock, db = FakeClock(), FakeDb()
    list(make(db, clock).iter_window(T0, T0 + timedelta(minutes=2, seconds=30)))
    windows = [params for sql, params in db.calls if sql == crtsh.ENTRIES_SQL]
    naive = T0.replace(tzinfo=None)
    assert windows == [
        (naive, naive + timedelta(minutes=1)),
        (naive + timedelta(minutes=1), naive + timedelta(minutes=2)),
        (naive + timedelta(minutes=2), naive + timedelta(minutes=2, seconds=30)),
    ]


def test_names_are_read_in_chunks():
    entries = {i: datetime(2025, 3, 1, 10, 0, 0) for i in range(1, 1001)}
    clock, db = FakeClock(), FakeDb(entries=entries, names=[])
    list(make(db, clock).iter_window(T0, T0 + timedelta(minutes=1)))
    name_calls = [p for s, p in db.calls if s == crtsh.NAMES_SQL]
    assert [len(p[0]) for p in name_calls] == [400, 400, 200]


def test_statements_are_spaced():
    clock, db = FakeClock(), FakeDb()
    list(make(db, clock, min_gap_s=2.0).iter_window(T0, T0 + timedelta(minutes=3)))
    assert len(db.calls) >= 4
    assert clock.sleeps and all(abs(s - 2.0) < 1e-9 for s in clock.sleeps)
    assert len(clock.sleeps) == len(db.calls) - 1


def test_no_sleep_when_gap_already_elapsed():
    clock, db = FakeClock(), FakeDb()
    gen = make(db, clock).iter_window(T0, T0 + timedelta(minutes=2))
    next(gen)
    clock.now += 50
    before = len(clock.sleeps)
    next(gen)  # the next statement goes out after a long pause: no sleep for it
    assert len(clock.sleeps) == before


def test_statement_cap():
    clock, db = FakeClock(), FakeDb()
    client = make(db, clock, statement_cap=3)
    with pytest.raises(StatementCapReached):
        list(client.iter_window(T0, T0 + timedelta(minutes=10)))
    assert len(db.calls) == 3
    assert issubclass(StatementCapReached, RuntimeError)


def test_retry_with_exponential_backoff_and_jitter():
    clock = FakeClock()
    db = FakeDb(fail={1: OperationalError("busy"), 2: OperationalError("busy"), 3: OperationalError("busy")})
    client = CrtShWindows(connect=db.connect, user_agent=UA, clock=clock, sleep=clock.sleep, rng=lambda: 0.5,
                          backoff_base_s=2.0)
    out = list(client.iter_window(T0, T0 + timedelta(minutes=1)))
    assert len(out) == 3
    backoffs = [s for s in clock.sleeps if s > 1.0 + 1e-9]
    assert backoffs == [3.0, 6.0, 12.0]   # base * 2**n * (1 + jitter)
    assert db.connects == 4               # the connection is reopened after each failure
    assert client.statements == 5         # three failed attempts count against the cap too


def test_retries_exhausted():
    clock = FakeClock()
    db = FakeDb(fail={n: OperationalError("down") for n in range(1, 20)})
    client = make(db, clock, max_retries=2)
    with pytest.raises(StatementFailed):
        list(client.iter_window(T0, T0 + timedelta(minutes=1)))
    assert len(db.calls) == 3


def test_connection_error_is_retried_and_sql_error_is_not():
    clock = FakeClock()
    db = FakeDb(fail={1: ConnectionResetError("reset")})
    assert len(list(make(db, clock).iter_window(T0, T0 + timedelta(minutes=1)))) == 3
    db = FakeDb(fail={1: SqlError("bad sql")})
    with pytest.raises(SqlError):
        list(make(db, FakeClock()).iter_window(T0, T0 + timedelta(minutes=1)))
    assert len(db.calls) == 1


def test_retries_hit_the_cap():
    clock = FakeClock()
    db = FakeDb(fail={n: OperationalError("down") for n in range(1, 20)})
    with pytest.raises(StatementCapReached):
        list(make(db, clock, statement_cap=2, max_retries=10).iter_window(T0, T0 + timedelta(minutes=1)))
    assert len(db.calls) == 2


def test_window_bounds_are_sent_as_naive_utc():
    clock, db = FakeClock(), FakeDb()
    plus_two = timezone(timedelta(hours=2))
    start = datetime(2025, 3, 1, 12, 0, tzinfo=plus_two)   # 10:00 UTC
    list(make(db, clock).iter_window(start, start + timedelta(minutes=1)))
    (params,) = [p for s, p in db.calls if s == crtsh.ENTRIES_SQL]
    assert params == (datetime(2025, 3, 1, 10, 0), datetime(2025, 3, 1, 10, 1))
    assert all(p.tzinfo is None for p in params)


def test_naive_window_bounds_are_rejected():
    client = make(FakeDb(), FakeClock())
    with pytest.raises(ValueError):
        list(client.iter_window(datetime(2025, 3, 1), T0))
    with pytest.raises(ValueError):
        list(client.iter_window(T0, datetime(2025, 3, 2)))


def test_sql_text_is_pinned():
    assert crtsh.ENTRIES_SQL == (
        "SELECT certificate_id, min(entry_timestamp) FROM ct_log_entry "
        "WHERE entry_timestamp >= %s AND entry_timestamp < %s GROUP BY certificate_id")
    assert crtsh.NAMES_SQL == (
        "SELECT c.id, ca.name, x509_altNames(c.certificate, 2, TRUE) FROM certificate c "
        "LEFT JOIN ca ON ca.id = c.issuer_ca_id WHERE c.id = ANY(%s) "
        "UNION "
        "SELECT c.id, ca.name, x509_nameAttributes(c.certificate, 'commonName', TRUE) FROM certificate c "
        "LEFT JOIN ca ON ca.id = c.issuer_ca_id WHERE c.id = ANY(%s)")


def test_names_query_gets_the_chunk_for_both_halves():
    clock, db = FakeClock(), FakeDb()
    list(make(db, clock).iter_window(T0, T0 + timedelta(minutes=1)))
    (params,) = [p for s, p in db.calls if s == crtsh.NAMES_SQL]
    assert params == ([1, 2], [1, 2])


class TimeoutDb:
    """Cancels entry queries over a window longer than ``max_span`` and name queries over more than ``max_ids`` ids."""

    def __init__(self, max_span=timedelta(minutes=1), max_ids=1000, entries=None):
        self.max_span, self.max_ids = max_span, max_ids
        self.entries = entries or {1: datetime(2025, 3, 1, 10, 0, 5)}
        self.calls = []
        self.connects = 0

    def connect(self):
        self.connects += 1
        return FakeConn(self)

    def run(self, sql, params):
        self.calls.append((sql, params))
        if sql == crtsh.ENTRIES_SQL:
            lo, hi = params
            if hi - lo > self.max_span:
                raise QueryCanceled("canceling statement due to statement timeout")
            return [(cid, ts) for cid, ts in self.entries.items() if lo <= ts < hi]
        if len(params[0]) > self.max_ids:
            raise QueryCanceled("canceling statement due to statement timeout")
        return [(cid, "Test CA", f"host{cid}.example.test") for cid in params[0]]


def test_window_timeout_halves_the_window_without_retrying_or_reconnecting():
    clock, db = FakeClock(), TimeoutDb(max_span=timedelta(seconds=20), entries={1: datetime(2025, 3, 1, 10, 0, 5), 2: datetime(2025, 3, 1, 10, 0, 50)})
    client = make(db, clock)
    out = list(client.iter_window(T0, T0 + timedelta(minutes=1)))
    assert sorted(o.name for o in out) == ["host1.example.test", "host2.example.test"]
    spans = [(p[1] - p[0]).total_seconds() for s, p in db.calls if s == crtsh.ENTRIES_SQL]
    assert spans == [60, 30, 15, 15, 30, 15, 15]
    assert db.connects == 1 and client.errors == []
    assert not [s for s in clock.sleeps if s > 1.0 + 1e-9]   # no back-off sleeps: a timeout is not a connection error


def test_window_that_always_times_out_is_given_up_and_recorded():
    clock, db = FakeClock(), TimeoutDb(max_span=timedelta(0))
    client = make(db, clock, statement_cap=500)
    assert list(client.iter_window(T0, T0 + timedelta(seconds=4))) == []
    spans = {(p[1] - p[0]).total_seconds() for s, p in db.calls if s == crtsh.ENTRIES_SQL}
    assert spans == {4.0, 2.0, 1.0}
    assert len(client.errors) == 4 and "timed out" in client.errors[0]


def test_names_chunk_timeout_halves_the_chunk():
    entries = {i: datetime(2025, 3, 1, 10, 0, 0) for i in range(1, 9)}
    clock, db = FakeClock(), TimeoutDb(max_ids=3, entries=entries)
    out = list(make(db, clock).iter_window(T0, T0 + timedelta(minutes=1)))
    assert sorted(o.cert_id for o in out) == [str(i) for i in range(1, 9)]
    sizes = [len(p[0]) for s, p in db.calls if s == crtsh.NAMES_SQL]
    assert sizes == [8, 4, 2, 2, 4, 2, 2]


def test_single_certificate_that_times_out_is_skipped_and_recorded():
    clock, db = FakeClock(), TimeoutDb(max_ids=0, entries={7: datetime(2025, 3, 1, 10, 0, 1)})
    client = make(db, clock)
    assert list(client.iter_window(T0, T0 + timedelta(minutes=1))) == []
    assert len(client.errors) == 1 and "7" in client.errors[0]


def test_timeouts_count_against_the_statement_cap():
    clock, db = FakeClock(), TimeoutDb(max_span=timedelta(0))
    with pytest.raises(StatementCapReached):
        list(make(db, clock, statement_cap=4).iter_window(T0, T0 + timedelta(minutes=1)))
    assert len(db.calls) == 4


def test_closed_connection_is_retried_with_a_new_connection():
    clock = FakeClock()
    db = FakeDb(fail={1: InterfaceError("connection is closed")})
    client = make(db, clock)
    assert len(list(client.iter_window(T0, T0 + timedelta(minutes=1)))) == 3
    assert db.connects == 2


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_cli_style_non_finite_gap_is_rejected(value):
    with pytest.raises(ValueError):
        CrtShWindows(connect=lambda: None, user_agent=UA, min_gap_s=value)
