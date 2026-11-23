"""A limiter that stays away must end the favicon stage, not turn every lookup into an error record."""
import json
from pathlib import Path

import pytest

from scanner.internet import __main__ as cli
from scanner.internet import favicon, limiterclient, pacing, pipeline
from scanner.internet.config import load_config
from scanner.internet.limiterclient import LimiterClient, LimiterOutage, LimiterRefused
from tests.helpers import FakeFetcher, ProcessFetcherFactory
from tests.test_coordinator import _worker_args
from tests.limiter_support import Server, deadline  # noqa: F401
from tests.test_favicon_processes import make_jobs
from tests.test_limiterd import NET, unix_only
from tests.test_scale import _cfg


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setenv("SCANNER_LIMITER_START_WAIT", "0")
    limiterclient.reset_failures()
    yield
    limiterclient.reset_failures()


class Raising:
    def __init__(self, exc):
        self.exc = exc

    def fetch(self, url, *, connect_ip, kind, context=""):
        raise self.exc


def probe(exc):
    return favicon.probe_identity(Raising(exc), scheme="http", ip=f"{NET}.1", port=80, hostname=None, max_icons=2)


def test_the_record_builder_lets_a_limiter_failure_through():
    for exc in (LimiterOutage("gone for 601 s"), LimiterRefused("cap too low")):
        with pytest.raises(type(exc)):
            probe(exc)


@pytest.mark.parametrize("exc", [RuntimeError("boom"), ValueError("bad"), OSError("reset"), limiterclient.LimiterUnavailable("no daemon")])
def test_the_record_builder_still_records_any_other_failure_as_an_error(exc):
    rec = probe(exc)
    assert rec["favicon_outcome"] == "error" and type(exc).__name__ in rec["error"]


class PacedFetcher(FakeFetcher):
    """A fetcher that asks the limiter before every request, as the favicon fetchers do."""

    def __init__(self, pacer):
        super().__init__()
        self.pacer = pacer

    def fetch(self, url, *, connect_ip, kind, context=""):
        favicon._admit(self.pacer, connect_ip)
        try:
            return super().fetch(url, connect_ip=connect_ip, kind=kind, context=context)
        finally:
            self.pacer.done(connect_ip)


def goes_quiet_after_hello(tmp_path, answered=0):
    """A daemon that answers the hello (and ``answered`` claims) and then says nothing."""
    s = Server(tmp_path / "quiet.sock", cap=4, gap=0.0).start()
    real, seen = s.core.handle, {"claims": 0}

    def handle(conn, req):
        if req.get("op") == "claim":
            seen["claims"] += 1
            if seen["claims"] > answered:
                s.mute.set()
        return real(conn, req)
    s.core.handle = handle
    return s


@unix_only
def test_a_stage_with_a_limiter_that_stays_quiet_ends_with_the_outage_and_records_no_errors(tmp_path):
    s = goes_quiet_after_hello(tmp_path)
    client = LimiterClient(s.path, 4, 0.0, outage_limit=1.0, io_timeout=0.4, retry_after=0.05)
    pacer = pacing.IpPacer(0.0, limiter=client, max_wait=30, poll=0.05)
    records = []
    try:
        with pytest.raises(LimiterOutage, match="unreachable"):
            favicon.run_favicon_stage(PacedFetcher(pacer), make_jobs(12), workers=4, max_icons=2, on_record=records.append)
    finally:
        s.mute.clear()
        client.close()
        s.stop()
    assert not [r for r in records if r["favicon_outcome"] == "error"]
    assert limiterclient.failure_kinds().get("limiter", 0) >= 1


@unix_only
def test_the_stage_worker_exits_77_for_that_outage_and_5_when_something_else_failed_too(tmp_path, monkeypatch):
    path = _cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 3})
    cfg = load_config(path)
    argv = _worker_args(path, cfg, "favicon")[0]

    def outage(c, run_dir, **kw):
        limiterclient.note_failure("limiter")
        raise LimiterOutage("limiter at x unreachable for 601 s (limit 600 s)")
    monkeypatch.setattr(pipeline, "run_favicon_only", outage)
    assert cli.main(argv) == 77
    mixed = {"stage_errors": {"favicon_workers": "1 favicon worker process(es) failed, 3 of 9 lookups lost; first: favicon worker process 0: "
                                                  "LimiterOutage: unreachable", "favicon_records_missing": "7 favicon records stored for 9 lookups"}}
    assert not cli._limiter_failure_only(mixed)

    def unfinished(c, run_dir, **kw):
        Path(run_dir).mkdir(parents=True, exist_ok=True)
        (Path(run_dir) / "manifest.json").write_text(json.dumps(mixed))
        limiterclient.note_failure("limiter")
        limiterclient.note_failure("other")
        return Path(run_dir)
    monkeypatch.setattr(pipeline, "run_favicon_only", unfinished)
    assert cli.main(argv) == 5


@unix_only
def test_favicon_worker_processes_report_a_quiet_limiter_by_name(tmp_path, monkeypatch):
    monkeypatch.setenv("SCANNER_LIMITER_OUTAGE_LIMIT", "1")
    s = goes_quiet_after_hello(tmp_path)
    failures = []
    try:
        records = favicon.run_favicon_stage_processes(ProcessFetcherFactory(), make_jobs(12), processes=2, workers=4, pace=0.0, max_icons=2,
                                                      subnet_cap=4, limiter_socket=s.path,
                                                      on_failure=lambda why, lost: failures.append((why, lost)))
    finally:
        s.mute.clear()
        s.stop()
    assert failures and all(("LimiterOutage" in why or "LimiterUnavailable" in why) for why, _ in failures), failures
    assert cli._limiter_failure_only({"stage_errors": {"favicon_workers": failures[0][0]}})


def test_the_pacer_callers_in_the_fetchers_do_not_swallow_the_outage(tmp_path):
    """``admit`` is asked outside the fetchers' catch-all, so an outage reaches the record builder, which lets it through."""
    class Gone:
        def admit(self, ip):
            raise LimiterOutage("gone")
    with pytest.raises(LimiterOutage):
        favicon._admit(Gone(), f"{NET}.1")
