"""Limiter behaviour that is easy to get wrong at the seams: the exit code of a favicon stage whose worker processes failed for
different reasons, a client that has been closed, a drain that arrives while a stage is parked, and a clock that is set back."""
import json
import threading
import time
from pathlib import Path

import pytest

from scanner.internet import __main__ as cli
from scanner.internet import campaign, coordinator, favicon as fav, limiterclient, pacing, pipeline
from scanner.internet.config import load_config
from scanner.internet.limiterclient import LimiterClient, LimiterClosed, LimiterOutage, LimiterUnavailable
from scanner.safety import TargetPolicy
from tests.helpers import FakeFetcher, ProcessFetcher
from tests.limiter_support import Server, deadline, server  # noqa: F401
from tests.test_coordinator import _worker_args, state_of
from tests.test_limiter_outage_policy import START, Recorder, WallClock, drive, make_cfg, with_socket
from tests.test_limiterd import NET, unix_only
from tests.test_pipeline import tools
from tests.test_scale import _cfg

OUTAGE_TEXT = "limiter at /run/x.sock unreachable for 601 s (limit 600 s)"
NET_A, NET_B = "198.51.100", "203.0.113"          # two /24 networks, so two worker processes each own one


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setenv("SCANNER_LIMITER_START_WAIT", "0")
    limiterclient.reset_failures()
    yield
    limiterclient.reset_failures()


# -------------------------------------------------------------------- worker processes that fail for different reasons

class FailingFactory:
    """Builds the fetcher of a worker process. A process that owns an address of ``limiter_nets`` fails with a limiter
    outage while it is set up; one that owns an address of ``other_nets`` fails as ``other`` says: ``exit`` ends the
    process, ``raise`` makes building the fetcher raise. Picklable, so the spawned workers can use it."""

    def __init__(self, limiter_nets=(), other_nets=(), other="exit", when="setup"):
        self.limiter_nets, self.other_nets, self.other, self.when = tuple(limiter_nets), tuple(other_nets), other, when

    def __call__(self, pacer, owned=None, killed=None):
        mine = {ip.rsplit(".", 1)[0] for ip in (owned or ())}
        if mine & set(self.other_nets):
            if self.other == "raise":
                raise RuntimeError("cannot build a fetcher")
            return ProcessFetcher(pacer, None, next(ip for ip in owned), None, 0.0)       # exits the process on the first request
        if mine & set(self.limiter_nets):
            if self.when == "lookup":
                return _RaisesMidStage()               # the outage comes up in the middle of the stage, in a lookup
            raise LimiterOutage(OUTAGE_TEXT)           # what a worker reports when its limiter client cannot reach the daemon
        return ProcessFetcher(pacer, None, None, None, 0.0)


def _stage_cfg(tmp_path):
    """A sharded config with two favicon worker processes, and the run directory its favicon stage worker uses."""
    path = _cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 3})
    cfg = load_config(path)
    argv, run_dir = _worker_args(path, cfg, "favicon", extra=("--favicon-workers", "4", "--favicon-processes", "2"))
    return cfg, argv, run_dir


def _real_favicon_stage(monkeypatch, run_dir, factory):
    """Make the favicon stage worker run the real favicon stage, over worker processes built by ``factory``, on two
    networks. The manifest the worker then judges is the one the pipeline wrote."""
    ips = [f"{NET_A}.10", f"{NET_B}.10"]
    seen = {}

    def stage(cfg, directory, **kw):
        assert cfg.favicon.processes == 2
        run = pipeline.run(cfg, run_id=Path(directory).name, executor=tools(l4={443: ips}, tls={(ip, 443): "ok" for ip in ips}, tls_sni={},
                                                                         http={}, ptr={}, a={}),
                           fetcher_factory=factory, skip_preflight=True, offline_preflight=True)
        seen["manifest"] = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
        return run
    real_policy = pipeline.build_policy

    def policy(cfg):
        _, splan, exclusions = real_policy(cfg)
        return TargetPolicy.for_tests([f"{NET_A}.0/24", f"{NET_B}.0/24"]), splan, exclusions       # the documentation networks are special-use
    monkeypatch.setattr(pipeline, "build_policy", policy)
    monkeypatch.setattr(fav, "fetch_policy", lambda cfg, sampled: TargetPolicy.for_tests([f"{NET_A}.0/24", f"{NET_B}.0/24"]))
    monkeypatch.setattr(pipeline, "run_favicon_only", stage)
    return seen


@pytest.mark.parametrize("other", ["exit", "raise"])
def test_a_limiter_failure_next_to_another_worker_failure_is_not_a_limiter_failure(tmp_path, monkeypatch, other):
    """Mutation considered: classifying a worker failure as 'other' only by its text being empty, or dropping the
    ``favicon_workers_other`` entry, would let this stage exit 77 and be parked as if the limiter alone were at fault."""
    cfg, argv, run_dir = _stage_cfg(tmp_path)
    seen = _real_favicon_stage(monkeypatch, run_dir, FailingFactory(limiter_nets=[NET_A], other_nets=[NET_B], other=other))
    code = cli.main(argv)
    errors = seen["manifest"]["stage_errors"]
    assert errors["favicon_workers"].startswith("2 favicon worker process(es) failed, 2 of 2 lookups lost")
    assert "favicon_workers_other" in errors and "not caused by the limiter" in errors["favicon_workers_other"]
    assert not cli._limiter_failure_only(seen["manifest"])
    assert code == 5 and code != coordinator.EXIT_LIMITER


def test_workers_that_all_fail_for_the_limiter_end_the_stage_with_77(tmp_path, monkeypatch):
    """Mutation considered: counting every worker failure as 'other' would turn this into 5."""
    cfg, argv, run_dir = _stage_cfg(tmp_path)
    seen = _real_favicon_stage(monkeypatch, run_dir, FailingFactory(limiter_nets=[NET_A, NET_B]))
    code = cli.main(argv)
    errors = seen["manifest"]["stage_errors"]
    assert "2 favicon worker process(es) failed" in errors["favicon_workers"] and "LimiterOutage" in errors["favicon_workers"]
    assert "favicon_workers_other" not in errors
    assert not seen["manifest"].get("complete")
    if cli._limiter_failure_only(seen["manifest"]):
        assert code == coordinator.EXIT_LIMITER == 77
    else:                                   # any other error the stage recorded for the lost lookups must then be what decides it
        pytest.fail(f"a stage whose workers all failed for the limiter is not a pure limiter failure: {errors}")


class _RaisesMidStage(FakeFetcher):
    def fetch(self, url, *, connect_ip, kind, context=""):
        raise LimiterOutage(OUTAGE_TEXT)


class _MidStageFactory:
    def __call__(self, pacer, owned=None, killed=None):
        return _RaisesMidStage()


def test_a_worker_whose_lookups_meet_a_limiter_outage_is_reported_as_failed():
    jobs = [{"scheme": "https", "ip": f"{NET_A}.10", "port": 443, "hostname": None}, {"scheme": "https", "ip": f"{NET_B}.10", "port": 443, "hostname": None}]
    failures = []
    records = fav.run_favicon_stage_processes(_MidStageFactory(), jobs, processes=2, workers=4, pace=0.0, max_icons=2,
                                              on_failure=lambda why, lost: failures.append((why, lost)))
    assert failures and all("LimiterOutage" in why for why, _ in failures), (failures, [r["favicon_outcome"] for r in records])


@pytest.mark.parametrize("nets, other, code", [([NET_A, NET_B], None, 77), ([NET_A], "exit", 5), ([NET_A], "raise", 5)])
def test_a_limiter_outage_in_the_middle_of_the_stage_is_named_and_mapped_to_the_exit_code(tmp_path, monkeypatch, nets, other, code):
    """Mutation considered: not reporting a worker whose lookups were all settled before its error arrived, which leaves the
    manifest without ``favicon_workers`` and the stage looking finished."""
    cfg, argv, run_dir = _stage_cfg(tmp_path)
    others = [NET_B] if other else []
    seen = _real_favicon_stage(monkeypatch, run_dir, FailingFactory(limiter_nets=nets, other_nets=others, other=other or "exit", when="lookup"))
    assert cli.main(argv) == code
    errors = seen["manifest"]["stage_errors"]
    assert "favicon worker process(es) failed" in errors["favicon_workers"]
    assert ("favicon_workers_other" in errors) == bool(other)
    if not other:
        assert "LimiterOutage" in errors["favicon_workers"]


# -------------------------------------------------------------------- a closed client

def _connected(server, **kw):
    client = LimiterClient(server.path, 4, 0.4, retry_after=0.05, **kw)
    assert client.ping()
    return client


def _connections(server):
    return len(server._conns)


@unix_only
def test_a_closed_client_raises_on_a_claim_or_query_and_sends_nothing(server):
    """Mutation considered: letting ``_after_close`` return None for a strict call (a refusal that ``max_wait`` would
    count), or dropping the closed check so the call reconnects."""
    s = server(cap=4, gap=0.4)
    client = _connected(s)
    ip = f"{NET}.5"
    client.close()
    sent, conns = len(s.seen), _connections(s)
    assert issubclass(LimiterClosed, LimiterOutage)
    strict = [lambda: client.try_acquire(client.counts([ip]), ips=[ip]),
              lambda: client.try_acquire_hint(client.counts([ip]), ips=[ip]),
              lambda: client.try_acquire_some([ip]),
              lambda: client.acquire(client.counts([ip])),
              lambda: client.limit_for(ip),
              lambda: client.in_flight(ip)]
    for call in strict:
        with pytest.raises(LimiterClosed):
            call()
    time.sleep(0.3)
    assert len(s.seen) == sent, "a closed client sent a request"
    assert _connections(s) == conns, "a closed client connected again"
    assert limiterclient.failure_kinds() == {}


@unix_only
def test_a_closed_client_answers_release_observe_ping_and_withdraw_quietly(server):
    """Mutation considered: making the non-strict calls raise (a teardown would then fail), or letting them reconnect."""
    s = server(cap=4, gap=0.4)
    client = _connected(s)
    ip = f"{NET}.6"
    counts = client.counts([ip])
    assert client.try_acquire(counts, ips=[ip])
    ticket = client.ticket()
    assert not client.try_acquire(counts, ticket, ips=[ip])         # inside the pause of the address: queued under the ticket
    client.close()
    sent, conns = len(s.seen), _connections(s)
    assert client.release(counts, [ip]) is None
    assert client.withdraw(ticket) is None
    assert client.observe(ip, timeout=True) is None
    assert client.ping() is False
    time.sleep(0.3)
    assert len(s.seen) == sent and _connections(s) == conns
    assert limiterclient.failure_kinds() == {}


class _ClosesThenAsks(FakeFetcher):
    """The pacer of a fetcher whose client is closed, as at the end of a run while a lookup is still going."""

    def __init__(self, client):
        super().__init__()
        self.pacer = pacing.IpPacer(0.0, limiter=client, max_wait=30, poll=0.05)

    def fetch(self, url, *, connect_ip, kind, context=""):
        fav._admit(self.pacer, connect_ip)
        return super().fetch(url, connect_ip=connect_ip, kind=kind, context=context)


@unix_only
def test_a_lookup_that_meets_a_closed_client_is_not_a_limiter_failure(server, tmp_path, monkeypatch):
    """Mutation considered: noting a limiter failure (or naming LimiterOutage in the stage error) when the client was
    closed, which would park the stage for a cooldown at the end of every run that closes the client early."""
    s = server(cap=4, gap=0.0)
    client = LimiterClient(s.path, 4, 0.0, retry_after=0.05)
    assert client.ping()
    client.close()
    jobs = [{"scheme": "http", "ip": f"{NET}.{i}", "port": 80, "hostname": None} for i in range(1, 5)]
    records = []
    with pytest.raises(LimiterClosed) as caught:
        fav.run_favicon_stage(_ClosesThenAsks(client), jobs, workers=2, max_icons=2, on_record=records.append)
    assert not [r for r in records if r["favicon_outcome"] == "error"]
    assert limiterclient.failure_kinds() == {}
    text = f"{type(caught.value).__name__}: {caught.value}"
    assert not cli._limiter_failure_only({"stage_errors": {"favicon": text}})
    # a stage worker whose stage ended on it fails the attempt as an ordinary error: it is neither parked (77) nor reported finished
    path = _cfg(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 3})
    argv = _worker_args(path, load_config(path), "favicon")[0]

    def unfinished(cfg, run_dir, **kw):
        Path(run_dir).mkdir(parents=True, exist_ok=True)
        (Path(run_dir) / "manifest.json").write_text(json.dumps({"stage_errors": {"favicon": text}}))
        return Path(run_dir)
    monkeypatch.setattr(pipeline, "run_favicon_only", unfinished)
    assert cli.main(argv) == 5

    def raises(cfg, run_dir, **kw):
        raise caught.value
    monkeypatch.setattr(pipeline, "run_favicon_only", raises)
    assert cli.main(argv) == 3


# -------------------------------------------------------------------- require() while the client is closed

@unix_only
def test_require_returns_promptly_when_the_client_is_closed_during_the_wait(tmp_path):
    """Mutation considered: dropping the closed check in ``require`` (or sleeping instead of waiting on the closed
    event) would keep it polling for the whole 30 s."""
    client = LimiterClient(str(tmp_path / "absent.sock"), 4, 0.4, retry_after=0.05)
    timer = threading.Timer(0.3, client.close)
    timer.start()
    began = time.monotonic()
    try:
        with pytest.raises(LimiterUnavailable):
            client.require(30.0)
    finally:
        timer.cancel()
    assert time.monotonic() - began < 5.0


# -------------------------------------------------------------------- the coordinator: drain, parks and the clock

def _park_then_drain(tmp_path, *, daemon_up):
    """Shard 0's network stage is parked (exit 77) and a DRAIN appears while it waits. ``daemon_up(clock)`` is the probe."""
    cfg = with_socket(make_cfg(tmp_path, shards=3), tmp_path / "limiter.sock")
    clock = WallClock()
    cluster = Recorder(cfg, clock, fail={("network", 0): [77, 0]}, durations={("network", 0): 1})
    drain = campaign.campaign_dir(cfg) / "DRAIN"
    real = cluster.spawn
    state = {}

    def spawn(cmd, fds):
        if cmd[cmd.index("--stage") + 1] == "zmap" and cmd[cmd.index("--shard") + 1] == "1":
            drain.parent.mkdir(parents=True, exist_ok=True)
            drain.write_text("")
            state["drained_at"] = clock.t
        return real(cmd, fds)
    cluster.spawn = spawn
    result, log = drive(cfg, cluster, tmp_path, clock, limiter_probe=lambda c: daemon_up(clock, state))
    return cfg, cluster, clock, result, log


def test_a_drain_during_a_park_waits_for_the_cooldown_and_halts_when_the_daemon_is_still_down(tmp_path, monkeypatch):
    """Mutation considered: halting for the drain as soon as nothing runs, ignoring a stage whose ``not_before`` is still
    ahead (the park would be abandoned at once instead of at the end of its cooldown)."""
    monkeypatch.setattr(coordinator, "LIMITER_PROBE_FRESH", 0.0)
    monkeypatch.setattr(coordinator, "LIMITER_PROBE_RETRY", 0.0)
    monkeypatch.setattr(coordinator, "LIMITER_PROBE_ALERT", 10 ** 9)
    cfg, cluster, clock, result, log = _park_then_drain(tmp_path, daemon_up=lambda c, st: "down" if "drained_at" in st else None)
    assert result["stopped"]["reason"] == "drain"
    parked = [line for line in log if "trying again in" in line]
    assert parked and "30 s" in parked[0]
    started = cluster.starts_of("network", 0)
    assert len(started) == 1, "the parked stage must not start again while the daemon is down"
    assert clock.t >= started[0] + coordinator.LIMITER_COOLDOWNS[0], "the drain ended the campaign before the cooldown was over"
    assert ("done", "network", 0) not in cluster.events
    stage = state_of(cfg)["shard_states"]["0"]["stages"]["network"]
    assert stage["status"] == "pending" and stage["limiter_parks"] == 1


def test_a_drain_during_a_park_lets_the_stage_run_again_when_the_daemon_is_back(tmp_path):
    """The same drain with the daemon answering once the cooldown is over: the parked stage finishes, then the drain halts."""
    cfg, cluster, clock, result, log = _park_then_drain(tmp_path, daemon_up=lambda c, st: None)
    assert result["stopped"]["reason"] == "drain"
    assert len(cluster.starts_of("network", 0)) == 2 and ("done", "network", 0) in cluster.events
    assert cluster.starts_of("network", 0)[1] - cluster.starts_of("network", 0)[0] >= coordinator.LIMITER_COOLDOWNS[0]


class _Interrupted(Exception):
    pass


def test_a_clock_set_back_after_a_park_cannot_stretch_the_cooldown_beyond_the_longest_one(tmp_path):
    """Mutation considered: removing the cut of ``not_before`` when a campaign is resumed (a park recorded under a clock a
    day ahead would then hold the stage for a day of the new clock)."""
    cfg = make_cfg(tmp_path, shards=2)
    clock = WallClock()
    step = clock.sleep
    first = Recorder(cfg, clock, fail={("network", 0): [77, 0]}, durations={("network", 0): 1})
    log = []

    def sleep(seconds):
        if any("trying again in" in line for line in log):
            raise _Interrupted()
        step(seconds)
    clock.sleep = sleep
    with pytest.raises(_Interrupted):
        drive(cfg, first, tmp_path, clock, log=log)
    parked_until = state_of(cfg)["shard_states"]["0"]["stages"]["network"]["not_before"]
    assert parked_until and parked_until > clock.t              # the cooldown was recorded and is still ahead
    back = WallClock()
    back.t = START - 86400.0                                    # the clock was set back by a day before the campaign was resumed
    second = Recorder(cfg, back)
    result, _ = drive(cfg, second, tmp_path, back)
    assert result["complete"]
    earliest = START - 86400.0
    assert second.starts_of("network", 0)[0] <= earliest + max(coordinator.LIMITER_COOLDOWNS) + 60
