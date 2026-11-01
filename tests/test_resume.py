"""Resume of the network stages: units on file, reuse after a crash, partial units, identity and the pause."""
import json
import sqlite3
import time
from pathlib import Path

import pytest

from scanner.internet import outputs, pacing, pipeline
from scanner.internet import resume as resume_mod
from scanner.internet.config import load_config
from scanner.internet.shardstore import ShardStore
from scanner.models import ToolJob
from tests.helpers import FakeFetcher, FakeTools, write_config
from tests.test_pipeline import tools


class Crash(BaseException):
    """The process dies: not an Exception, so no stage's failure isolation sees it."""


class Interrupt(KeyboardInterrupt):
    pass


class Dying:
    """Wraps the fake tools and raises on the n-th real invocation (the sample listing is not counted).

    A crash in one thread must not leave the other threads running on: from the n-th invocation every tool call fails."""

    def __init__(self, inner, n, exc=Crash):
        self.inner, self.n, self.exc, self.calls = inner, n, exc, 0

    def __call__(self, command, **kw):
        if scans(command):
            self.calls += 1
            if 0 < self.n <= self.calls:
                raise self.exc("simulated")
        return self.inner(command, **kw)


def scans(command):
    return Path(command[0]).name in ("zmap", "zgrab2", "zdns") and "--dryrun" not in command


def real_calls(fake):
    return [c for c in fake.commands if scans(c)]


def run(cfg, run_id, executor, **kw):
    return pipeline.run(cfg, run_id=run_id, executor=executor, fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True, **kw)


def tables(run_dir):
    """What the run wrote about the sample, without the times and tool job ids that differ between attempts."""
    def steady(row):
        return json.dumps({k: v for k, v in row.items() if not k.endswith("age_seconds")}, sort_keys=True)     # how old a page was when read
    ep = [steady(r) for r in outputs.iter_endpoint_rows(run_dir)]
    hosts = [steady(r) for r in outputs.iter_hostname_rows(run_dir)]
    jobs = [(j["tool"], j["purpose"], j["input_count"], j["output_count"], j["raw_sha256"])
            for j in (json.loads(x) for x in outputs.iter_lines(outputs.resolve(run_dir / "normalized" / "tool_jobs.jsonl")) if x.strip())]
    ips = (run_dir / "ip_results.csv").read_text(encoding="utf-8")
    return ep, hosts, jobs, ips


@pytest.fixture
def cfg(tmp_path):
    return load_config(write_config(tmp_path))


@pytest.fixture
def clean(cfg):
    """An uninterrupted run, and how many tool invocations it took."""
    fake = tools()
    d = run(cfg, "clean", fake)
    return d, len(real_calls(fake))


def manifest(d):
    return json.loads((d / "manifest.json").read_text(encoding="utf-8"))


def units(d):
    db = sqlite3.connect(str(d / "work" / "facts.sqlite"))
    try:
        return db.execute("SELECT stage, port, unit FROM units ORDER BY stage, port, unit").fetchall()
    finally:
        db.close()


# ------------------------------------------------------------------ crash and resume


def test_the_clean_run_takes_enough_invocations_to_cut_at_several_points(clean):
    assert clean[1] >= 10


@pytest.mark.parametrize("cut", [2, 4, 5, 7, 9, 11])
@pytest.mark.parametrize("how", [Crash, Interrupt])
def test_a_run_killed_after_n_invocations_resumes_to_the_tables_of_an_uninterrupted_run(tmp_path, cfg, clean, cut, how):
    first_fake = tools()
    try:
        first = run(cfg, "dead", Dying(first_fake, cut, how))
    except Crash:
        first = Path(cfg.output_dir) / "dead"
    assert not (first / "manifest.json").exists() or not manifest(first)["complete"]
    assert (first / "work" / "facts.sqlite").is_file()                  # an unfinished attempt keeps its store
    done_before = len(units(first))

    second_fake = tools()
    second = run(cfg, "dead-a2", second_fake, resume_from=first)
    assert tables(second) == tables(clean[0])
    assert manifest(second)["complete"]
    reused = manifest(second)["stage_counts"]["resume"]
    assert sum(reused["units_reused"].values()) == done_before
    assert done_before > 0 and len(real_calls(second_fake)) < clean[1]
    assert not (first / "work" / "facts.sqlite").exists()               # the store moved on to the attempt that continued it
    assert not (second / "work").exists()                               # and a finished run removes it


def test_reused_units_send_nothing_and_their_raw_files_come_along(tmp_path, cfg, clean):
    try:
        run(cfg, "dead", Dying(tools(), 6))
    except Crash:
        pass
    first = Path(cfg.output_dir) / "dead"
    kept = units(first)
    fake = tools()
    second = run(cfg, "dead-a2", fake, resume_from=first)
    assert len(real_calls(fake)) < clean[1]
    listed = [json.loads(x) for x in outputs.iter_lines(outputs.resolve(second / "normalized" / "tool_jobs.jsonl")) if x.strip()]
    assert all(outputs.resolve(second / j["raw_path"]).is_file() for j in listed)      # reused jobs point at files this run owns
    assert kept


def test_a_unit_that_did_not_finish_is_run_again_and_its_rows_are_replaced(tmp_path, cfg, clean):
    try:
        run(cfg, "dead", Dying(tools(), 13))        # after most units
    except Crash:
        pass
    first = Path(cfg.output_dir) / "dead"
    db = sqlite3.connect(str(first / "work" / "facts.sqlite"))
    try:
        had = db.execute("SELECT COUNT(*) FROM units WHERE stage = 'tls_direct' AND port = 443").fetchone()[0]
        assert had == 1
        db.execute("DELETE FROM units WHERE stage = 'tls_direct' AND port = 443")      # as if it died before its record
        db.execute("UPDATE tls_direct SET outcome = 'bogus', data = '{}' WHERE port = 443")       # and left a damaged half behind
        db.commit()
    finally:
        db.close()
    fake = tools()
    direct = []

    def spy(command, **kw):
        if command[0].endswith("zgrab2") and command[1] == "tls" and not any(row.split(",")[1] for row in kw["input"].splitlines()):
            direct.append(command[command.index("--port") + 1])
        return fake(command, **kw)
    second = run(cfg, "dead-a2", spy, resume_from=first)
    assert direct == ["443"]                  # the one batch without a record, and nothing else without a name
    assert tables(second) == tables(clean[0])           # no bogus row, no duplicate
    assert manifest(second)["stage_counts"]["resume"]["units_reused"].get("tls_direct", 0) >= 1


def test_a_crash_inside_a_batch_leaves_no_record_of_that_batch(tmp_path, cfg):
    fake = tools()
    seen = []

    class AtTls(Dying):
        def __call__(self, command, **kw):
            if len(command) > 1 and command[1] == "tls" and scans(command):
                seen.append(command)
                raise Crash("simulated")
            return self.inner(command, **kw)
    with pytest.raises(Crash):
        run(cfg, "dead", AtTls(fake, 0))
    first = Path(cfg.output_dir) / "dead"
    stages = {s for s, _p, _u in units(first)}
    assert "zmap" in stages and "tls_direct" not in stages and seen


# ------------------------------------------------------------------ identity


def test_a_different_config_does_not_take_over_the_store(tmp_path, cfg):
    try:
        run(cfg, "dead", Dying(tools(), 8))
    except Crash:
        pass
    first = Path(cfg.output_dir) / "dead"
    other = load_config(write_config(tmp_path, sample={"fraction": 0.0001, "seed": 5}))
    assert other.checksum != cfg.checksum
    fake = tools()
    second = run(other, "other-a2", fake, resume_from=first)
    info = manifest(second)["stage_counts"]["resume"]
    assert info["units_reused"] == {} and "different" in info["not_reused"]
    assert (first / "work" / "facts.sqlite").is_file()          # left where it was
    assert manifest(second)["complete"]


def test_a_store_of_another_shard_is_not_taken_over(tmp_path):
    cfg = load_config(write_config(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 2}))
    from dataclasses import replace
    c0, c1 = replace(cfg, shard=0), replace(cfg, shard=1)
    try:
        run(c0, "dead", Dying(tools(), 8))
    except Crash:
        pass
    first = Path(cfg.output_dir) / "dead"
    second = run(c1, "dead-a2", tools(), resume_from=first)
    assert "shard" in manifest(second)["stage_counts"]["resume"]["not_reused"]


def test_unit_keys_depend_on_the_run_identity_the_stage_and_the_targets(tmp_path):
    with ShardStore(tmp_path / "a.sqlite") as store:
        ident = {"config_checksum": "x", "shard": 0}
        a = resume_mod.UnitBook(store, ident)
        b = resume_mod.UnitBook(store, {**ident, "shard": 1})
        batch = [("1.1.1.1", 443, None), ("1.1.1.2", 443, None)]
        assert a.unit_id("tls_direct", items=batch) == a.unit_id("tls_direct", items=list(batch))
        assert a.unit_id("tls_direct", items=batch) != b.unit_id("tls_direct", items=batch)
        assert a.unit_id("tls_direct", items=batch) != a.unit_id("http_direct", items=batch)
        assert a.unit_id("tls_direct", items=batch) != a.unit_id("tls_direct", items=batch[:1])
        assert a.unit_id("tls_direct", items=batch) != a.unit_id("tls_direct", items=batch[::-1])


def _job(error=None, raw="raw/zgrab/x.jsonl"):
    return ToolJob(job_id="J", tool="zgrab2", purpose="p", command=("zgrab2", "tls"), input_count=1, output_count=1, exit_code=0,
                   raw_path=raw, raw_sha256="0" * 64, error=error)


def test_a_unit_whose_tool_failed_is_not_recorded_and_a_good_one_round_trips(tmp_path):
    with ShardStore(tmp_path / "a.sqlite") as store:
        book = resume_mod.UnitBook(store, {"k": 1})
        assert book.commit("u1", "tls_direct", [_job(error="exit 2")]) is False
        assert store.get_unit("u1") is None
        assert book.commit("u2", "tls_direct", [_job()], port=443, size=1) is True
        back = book.reuse("u2")
        assert back == [_job()] and book.reused_by_stage == {"tls_direct": 1}


def test_a_reused_unit_whose_raw_file_is_gone_runs_again(tmp_path):
    src, dst = tmp_path / "old", tmp_path / "new"
    (src / "raw" / "zgrab").mkdir(parents=True)
    dst.mkdir()
    with ShardStore(tmp_path / "a.sqlite") as store:
        book = resume_mod.UnitBook(store, {"k": 1}, source=src, run_dir=dst)
        book.commit("u", "tls_direct", [_job()])
        assert book.reuse("u") is None and store.get_unit("u") is None
        (src / "raw" / "zgrab" / "x.jsonl").write_text("{}\n")
        book.commit("u", "tls_direct", [_job()])
        assert book.reuse("u") is not None and (dst / "raw" / "zgrab" / "x.jsonl").read_text() == "{}\n"


def test_disabled_book_records_and_reuses_nothing(tmp_path):
    with ShardStore(tmp_path / "a.sqlite") as store:
        book = resume_mod.UnitBook(store, {"k": 1}, enabled=False)
        assert book.commit("u", "x", [_job()]) is False and store.count_units() == 0


# ------------------------------------------------------------------ escape hatch


def test_no_resume_reuses_nothing_and_leaves_no_store_behind(tmp_path, cfg, clean):
    fake_a = tools()
    first = run(cfg, "stopped", Dying(fake_a, 8, Interrupt), resume=False)
    assert not manifest(first)["complete"] and not (first / "work").exists()
    fake = tools()
    second = run(cfg, "stopped-a2", fake, resume_from=first, resume=False)
    assert len(real_calls(fake)) == clean[1]
    assert manifest(second)["stage_counts"]["resume"]["units_reused"] == {}


def test_an_interrupted_attempt_keeps_its_store_when_resume_is_on(tmp_path, cfg):
    first = run(cfg, "stopped", Dying(tools(), 8, Interrupt))
    assert not manifest(first)["complete"] and (first / "work" / "facts.sqlite").is_file()


def test_an_uninterrupted_run_has_no_resume_section_and_no_store(clean):
    assert "resume" not in manifest(clean[0])["stage_counts"] and not (clean[0] / "work").exists()


# ------------------------------------------------------------------ the pause


def test_no_address_is_contacted_before_a_full_pause_has_passed_after_a_resume(tmp_path):
    cfg = load_config(write_config(tmp_path, measurement={
        "ports": [80, 443, 8080], "zmap_rate": 100, "zmap_max_runtime": 100000, "zmap_cooldown": 8, "zmap_probes": 2,
        "zgrab_connect_timeout": 4.0, "zgrab_target_timeout": 8.0, "zgrab_senders": 10, "zgrab_batch_size": 500,
        "min_seconds_between_probes_per_ip": 1.0}))
    assert cfg.measurement.min_seconds_between_probes_per_ip == 1.0

    class Timed(Dying):
        def __init__(self, inner, n):
            super().__init__(inner, n)
            self.listed = None
            self.first_contact = None

        def __call__(self, command, **kw):
            now = time.monotonic()
            if "--dryrun" in command:
                self.listed = now
            elif scans(command) and Path(command[0]).name != "zdns" and self.first_contact is None:     # resolvers are not targets
                self.first_contact = now
            return super().__call__(command, **kw)
    try:
        run(cfg, "dead", Dying(tools(), 6))
    except Crash:
        pass
    first = Path(cfg.output_dir) / "dead"
    timed = Timed(tools(), 0)
    run(cfg, "dead-a2", timed, resume_from=first)
    assert timed.first_contact - timed.listed >= 0.95
    fresh = Timed(tools(), 0)
    run(cfg, "fresh", fresh)
    assert fresh.first_contact - fresh.listed < 0.9


def test_a_taken_over_sweep_counts_as_just_ended_for_the_overlap_gate():
    from scanner.internet.overlap import ZmapProgress
    t = [100.0]
    progress = ZmapProgress(1, now=lambda: t[0])
    progress.add_finished_sweep()
    sweeps, _ = progress.snapshot()
    assert sweeps[0]["start"] == sweeps[0]["end"] == 100.0 and sweeps[0]["obs"] == []


# ------------------------------------------------------------------ store plumbing


def test_clear_port_drops_one_sweeps_rows_only(tmp_path):
    with ShardStore(tmp_path / "a.sqlite") as store:
        store.put_endpoints([("1.1.1.1", 80), ("1.1.1.1", 443)])
        store.put_synack_port(80, {"1.1.1.1": {"window": 0, "ttl": 64}})
        store.put_synack_port(443, {"1.1.1.1": {"window": 0, "ttl": 64}})
        store.flag_tarpits(10)
        store.clear_port(80)
        assert list(store.iter_endpoints()) == [("1.1.1.1", 443)]
        assert store.get_synack("1.1.1.1", 80) == {} and store.get_synack("1.1.1.1", 443) != {}
        assert [r[0] for r in store.iter_tarpit_rejections()] == ["1.1.1.1"]
        store.reset_tarpits()
        assert store.rejected_ips() == set()


def test_put_unit_refuses_when_rows_were_lost(tmp_path):
    with ShardStore(tmp_path / "a.sqlite") as store:
        store.dropped_rows = 1
        assert store.put_unit("u", "x", None, 1, "[]") is False and store.count_units() == 0


# ------------------------------------------------------------------ batching


def test_paced_batches_are_port_pure_and_reused_batches_claim_nothing():
    ledger = pacing.ContactLedger(0.0)
    items = [(f"10.0.{i // 250}.{i % 250}", port) for port in (80, 443) for i in range(7)] + [("10.0.0.0", 443)]
    seen = []

    def run_batch(batch):
        seen.append(batch)
        return len(batch)
    out = pacing.paced_batches(items, lambda t: t[0], ledger, run_batch, batch_size=3, group_of=lambda t: t[1])
    assert all(len({p for _, p in b}) == 1 for b in seen) and sum(out) == len(items)
    assert [b[0][1] for b in seen] == sorted(b[0][1] for b in seen)           # ascending ports
    claimed = []
    ledger.claim = lambda ips, extra=None: claimed.append(ips) or True        # a batch that runs claims; a reused one does not
    reused = pacing.paced_batches(items, lambda t: t[0], ledger, run_batch, batch_size=3, group_of=lambda t: t[1],
                                  reuse=lambda b: "kept" if b[0][1] == 80 else None)
    assert reused.count("kept") == 3 and len(claimed) == len(reused) - 3


# ------------------------------------------------------------------ campaign and supervisor


def test_the_overlapped_launcher_passes_no_resume_to_the_child(tmp_path):
    from scanner.internet import supervisor
    cfg = load_config(write_config(tmp_path, sample={"fraction": 0.0001, "seed": 4, "shards": 3}))
    cmd = supervisor.child_command(cfg, tmp_path / "c.yaml", 1, "r-a2", None, tmp_path / "earlier", resume=False)
    assert "--no-resume" in cmd
    assert "--no-resume" not in supervisor.child_command(cfg, tmp_path / "c.yaml", 1, "r-a2", None, tmp_path / "earlier")


def test_forward_lookups_resume_per_batch(tmp_path, cfg, monkeypatch):
    monkeypatch.setattr(pipeline, "DNS_BATCH", 1)
    fake = tools()
    whole = run(cfg, "whole", fake)
    total = len(real_calls(fake))
    try:
        run(cfg, "dead", Dying(tools(), total - 2))         # dies among the last lookups
    except Crash:
        pass
    first = Path(cfg.output_dir) / "dead"
    kept = [stage for stage, _p, _u in units(first)]
    assert kept.count("dns_forward") >= 1
    again = tools()
    second = run(cfg, "dead-a2", again, resume_from=first)
    assert tables(second) == tables(whole)
    assert manifest(second)["stage_counts"]["resume"]["units_reused"]["dns_forward"] == kept.count("dns_forward")
    assert [c for c in real_calls(again) if c[0].endswith("zdns") and c[1] in ("A", "AAAA")] != []


def test_delete_rows_removes_only_the_named_keys(tmp_path):
    with ShardStore(tmp_path / "a.sqlite") as store:
        store.put_doc("1.1.1.1", 80, {"t": 1})
        store.put_doc("1.1.1.2", 80, {"t": 2})
        store.delete_rows("docs", [("1.1.1.1", 80)])
        assert [(ip, port) for ip, port, _d in store.iter_docs()] == [("1.1.1.2", 80)]
        with pytest.raises(KeyError):
            store.delete_rows("endpoints", [("1.1.1.2", 80)])
