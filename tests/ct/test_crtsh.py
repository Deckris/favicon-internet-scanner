import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest

from scanner.ct import crtsh
from scanner.ct.crtsh import CrtShWindows, StatementCapReached, StatementFailed

UA = "ct-reader/1.0 (+mailto:ops@example.test)"
T0 = datetime(2025, 3, 1, 10, 0, tzinfo=UTC)


class OperationalError(Exception):
    """Same class name as the driver's connection-level error."""


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
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0


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
    assert seen["application_name"] == "Scan-Tool-2.0"


@pytest.mark.parametrize("kw", [
    {"min_gap_s": 0.5},
    {"user_agent": ""},
    {"user_agent": "   "},
    {"user_agent": "plain-agent/1.0"},
    {"statement_cap": 0},
])
def test_guards(kw):
    args = {"connect": lambda: None, "user_agent": UA, **kw}
    with pytest.raises(ValueError):
        CrtShWindows(**args)


def test_url_contact_is_accepted():
    CrtShWindows(connect=lambda: None, user_agent="tool/1.0 (+https://example.test/contact)")


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
    assert windows == [
        (T0, T0 + timedelta(minutes=1)),
        (T0 + timedelta(minutes=1), T0 + timedelta(minutes=2)),
        (T0 + timedelta(minutes=2), T0 + timedelta(minutes=2, seconds=30)),
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
