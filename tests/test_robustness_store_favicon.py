"""Failure handling of the shard store, the favicon stage driver and the tool runner."""
import sqlite3
import sys
import threading
import time

import pytest

from scanner.internet import favicon as fav
from scanner.internet import shardstore
from scanner.internet.config import load_config
from scanner.internet.runner import ManagedExecutor
from scanner.internet.shardstore import ShardStore
from tests.helpers import write_config


def _job(ip, port=80):
    return {"scheme": "http", "ip": ip, "port": port, "hostname": None}


# ------------------------------------------------------------------ shard store

def test_failed_mark_ptr_sent_leaves_no_open_transaction(tmp_path):
    s = ShardStore(tmp_path / "f.sqlite", reset=True)
    s.put_endpoints([("1.1.1.1", 80)])
    with pytest.raises(ValueError):
        s.mark_ptr_sent(["1.1.1.2", "\u00e9"])
    assert s.mark_ptr_sent(["1.1.1.2"]) == ["1.1.1.2"]       # nothing of the failed call was kept
    s.put_endpoints([("1.1.1.3", 80)] * 300)
    assert s.count_endpoints() == 2
    s.close()


def test_interrupt_inside_a_transaction_rolls_back(tmp_path, monkeypatch):
    s = ShardStore(tmp_path / "f.sqlite", reset=True)
    s.put_endpoints([("1.1.1.1", 80)])
    real = s._db

    class Boom:
        def __getattr__(self, name):
            return getattr(real, name)

        def executemany(self, *a):
            raise KeyboardInterrupt

    s._db = Boom()
    with pytest.raises(KeyboardInterrupt):
        s.delete_tls_for_ips(["1.1.1.1"])
    s._db = real
    assert s.count_endpoints() == 1
    s.close()


def test_poison_row_is_dropped_and_counted_not_repeated(tmp_path):
    s = ShardStore(tmp_path / "f.sqlite", reset=True)
    s.put_endpoints([("1.1.1.1", 80)])
    s.put_synack("1.1.1.1", 80, 2 ** 70, 1)      # does not fit an SQLite integer
    s.put_synack("1.1.1.1", 81, 5, 1)
    assert s.count_endpoints() == 1               # reading flushes: no exception, store still usable
    assert s.dropped_rows == 1 and len(s.errors) == 1
    assert s._query("SELECT port, window FROM synack") == [(81, 5)]
    s.close()
    assert s.dropped_rows == 1


def test_transient_disk_error_surfaces_once_and_does_not_poison(tmp_path, monkeypatch):
    s = ShardStore(tmp_path / "f.sqlite", reset=True)
    s.put_endpoints([("1.1.1.1", 80)])
    real = s._db
    state = {"fail": True}

    class Flaky:
        def __getattr__(self, name):
            return getattr(real, name)

        def executemany(self, *a):
            if state["fail"]:
                raise sqlite3.OperationalError("disk I/O error")
            return real.executemany(*a)

    s._db = Flaky()
    with pytest.raises(sqlite3.OperationalError):
        s.flush()
    state["fail"] = False
    s.flush()                                      # the retry succeeds, rows were kept
    s._db = real
    assert s.count_endpoints() == 1 and s.dropped_rows == 0
    s.close()


def test_persistent_disk_error_drops_after_one_retry_and_close_never_raises(tmp_path):
    s = ShardStore(tmp_path / "f.sqlite", reset=True)
    real = s._db

    class Dead:
        def __getattr__(self, name):
            return getattr(real, name)

        def executemany(self, *a):
            raise sqlite3.OperationalError("database or disk is full")

    s._db = Dead()
    s.put_endpoints([("1.1.1.1", 80)])
    with pytest.raises(sqlite3.OperationalError):
        s.flush()
    s.close()                                      # second failure: dropped and recorded
    assert s.dropped_rows == 1 and s.errors


# ------------------------------------------------------------------ favicon stage driver

def test_stage_stops_probing_after_a_sink_failure():
    calls = []

    class F:
        def fetch(self, url, *, connect_ip, kind, context=""):
            calls.append(url)
            raise RuntimeError("x")

    jobs = [_job(f"10.0.{i // 250}.{i % 250 + 1}") for i in range(200)]

    def bad_sink(i, rec):
        raise OSError("disk full")

    with pytest.raises(OSError):
        fav.run_favicon_stage(F(), jobs, workers=4, max_icons=2, record_sink=bad_sink, grace=0.5)
    assert len(calls) < 40


def test_abandoned_lookup_is_sunk_once():
    seen, lock = {}, threading.Lock()

    class Slow:
        def fetch(self, url, *, connect_ip, kind, context=""):
            time.sleep(0.6)
            raise RuntimeError

    def sink(i, rec):
        with lock:
            seen.setdefault(i, []).append(rec["favicon_outcome"])

    flag = {"k": False}
    threading.Timer(0.2, lambda: flag.__setitem__("k", True)).start()
    jobs = [_job("10.1.0.1"), _job("10.1.0.1", 81)]
    fav.run_favicon_stage(Slow(), jobs, workers=2, max_icons=2, killed=lambda: flag["k"], grace=0.01, record_sink=sink)
    time.sleep(1.2)
    assert {i: len(v) for i, v in seen.items()} == {0: 1, 1: 1}


def test_kill_during_request_marks_timeout_as_skipped():
    flag = {"k": False}

    class F:
        def fetch(self, url, *, connect_ip, kind, context=""):
            flag["k"] = True
            from types import SimpleNamespace
            return SimpleNamespace(outcome="timeout", http_status=None, final_url=None, content_type=None), None

    out = fav.run_favicon_stage(F(), [_job("10.2.0.1")], workers=1, max_icons=1, killed=lambda: flag["k"], grace=1.0)
    assert out[0]["favicon_outcome"] == "skipped_kill_switch"


def test_record_log_refuses_appends_after_close(tmp_path):
    log = fav.RecordLog(tmp_path / "log.jsonl")
    log.append({"ip": "1.1.1.1", "port": 80})
    log.close()
    log.append({"ip": "1.1.1.2", "port": 80})
    assert log.dropped == 1
    assert len(log.load()) == 1


# ------------------------------------------------------------------ tool runner

def test_failed_pump_start_kills_tool_and_clears_active_count(tmp_path, monkeypatch):
    ex = ManagedExecutor(load_config(write_config(tmp_path)), tmp_path, lambda: False)
    started = []
    real_start = threading.Thread.start

    def start(self):
        if self.daemon and self._target is not None and self._target.__name__.startswith("_pump"):
            raise RuntimeError("can't start new thread")
        return real_start(self)

    import subprocess
    real_popen = subprocess.Popen

    def popen(*a, **kw):
        p = real_popen(*a, **kw)
        started.append(p)
        return p

    monkeypatch.setattr(threading.Thread, "start", start)
    monkeypatch.setattr(subprocess, "Popen", popen)
    with pytest.raises(RuntimeError):
        ex([sys.executable, "-c", "import time; time.sleep(60)"])
    assert ex.active_tools == 0
    assert started[0].poll() is not None
