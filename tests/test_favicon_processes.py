"""The favicon stage over several worker processes: same records, one process per address, stop and crash handling."""
from __future__ import annotations

import json
import time

import pytest

from scanner.internet import favicon as fav
from scanner.internet import icon_store, pacing, pipeline
from scanner.internet.config import ConfigError, load_config
from scanner.safety import TargetPolicy
from tests.helpers import FakeFetcher, GuardedStubFactory, ProcessFetcherFactory, make_png, write_config
from tests.test_config import _rewrite
from tests.test_pipeline import tools


def make_jobs(addresses: int = 24, hostnames: bool = True) -> list[dict]:
    jobs = []
    for i in range(1, addresses + 1):
        ip = f"198.51.{100 + i % 5}.{i}"       # several /24 networks, so there is more than one unit to partition
        jobs.append({"scheme": "http", "ip": ip, "port": 80, "hostname": None})
        if i % 3 == 0:
            jobs.append({"scheme": "https", "ip": ip, "port": 443, "hostname": None})
        if hostnames and i % 4 == 0:
            jobs.append({"scheme": "http", "ip": ip, "port": 80, "hostname": f"h{i}.example.com"})
    return jobs


def bare(records):
    """The records without the request times, which come from the clock of the process that made the request."""
    return [{k: v for k, v in rec.items() if k not in ("captured_at", "favicon_at")} for rec in records]


def run(jobs, processes, **over):
    args = dict(processes=processes, workers=8, pace=0.0, max_icons=2)
    args.update(over)
    factory = args.pop("factory", ProcessFetcherFactory())
    return fav.run_favicon_stage_processes(factory, jobs, **args)


def test_partition_never_splits_an_address_and_covers_every_job():
    jobs = make_jobs(60)
    for parts in (1, 2, 3, 7):
        split = fav.partition_by_ip(jobs, parts)
        assert sorted(i for p in split for i in p) == list(range(len(jobs)))
        owner = {}
        for n, p in enumerate(split):
            assert p == sorted(p)
            for i in p:
                assert owner.setdefault(jobs[i]["ip"], n) == n, "an address landed in two partitions"
        assert fav.partition_by_ip(jobs, parts) == split


def test_partition_keeps_a_network_in_one_part():
    jobs = [{"scheme": "http", "ip": f"203.0.{n}.{i}", "port": 80, "hostname": None} for n in (1, 2, 3) for i in range(1, 9)]
    jobs += [{"scheme": "http", "ip": f"2001:db8:{n}::{i}", "port": 80, "hostname": None} for n in (1, 2) for i in range(1, 5)]
    split = fav.partition_by_ip(jobs, 4)
    owner = {}
    for n, p in enumerate(split):
        for i in p:
            assert owner.setdefault(pacing.network_key(jobs[i]["ip"]), n) == n, "a network landed in two partitions"
    assert len(split) == 4 and max(map(len, split)) <= 8


def test_partition_balances_and_never_makes_empty_parts():
    jobs = make_jobs(40)
    sizes = [len(p) for p in fav.partition_by_ip(jobs, 2)]
    largest = max(len([j for j in jobs if pacing.network_key(j["ip"]) == k]) for k in {pacing.network_key(j["ip"]) for j in jobs})
    assert abs(sizes[0] - sizes[1]) <= largest        # a network is never cut, so the greedy placement is off by at most one network
    assert len(fav.partition_by_ip(jobs[:1], 4)) == 1
    assert fav.partition_by_ip([], 2) == []


def test_records_equal_a_single_process_in_order_and_content():
    jobs = make_jobs()
    single = fav.run_favicon_stage(FakeFetcher(), jobs, workers=8, max_icons=2)
    for processes in (1, 2, 3):
        assert bare(run(jobs, processes)) == bare(single)


def test_records_stream_to_the_sinks_as_they_finish():
    jobs = make_jobs(12)
    single = fav.run_favicon_stage(FakeFetcher(), jobs, workers=8, max_icons=2)
    logged, sunk = [], {}
    assert run(jobs, 3, on_record=logged.append, record_sink=sunk.__setitem__) == []
    assert bare([sunk[i] for i in range(len(jobs))]) == bare(single)
    assert sorted(map(json.dumps, bare(logged))) == sorted(map(json.dumps, bare(single)))


def test_records_of_an_earlier_attempt_are_reused_not_fetched():
    jobs = make_jobs(8, hostnames=False)
    single = fav.run_favicon_stage(FakeFetcher(), jobs, workers=8, max_icons=2)
    earlier = {(r["ip"], r["port"], r.get("hostname")): r for r in single[:4]}
    logged = []
    assert bare(run(jobs, 2, done=earlier, on_record=logged.append)) == bare(single)
    assert len(logged) == len(jobs) - 4, "only the lookups that were not done before are logged again"


def test_icon_store_is_rebuilt_in_the_parent_and_files_are_whole(tmp_path):
    jobs = make_jobs()
    ref_store = icon_store.IconStore(tmp_path / "ref" / "favicons")
    ref = fav.run_favicon_stage(FakeFetcher(), jobs, workers=8, max_icons=2, icon_store=ref_store)
    store = icon_store.IconStore(tmp_path / "multi" / "favicons")
    out = run(jobs, 3, icon_store=store)
    assert bare(out) == bare(ref) and len(store) == len(ref_store) == 1
    (sha,) = ref_store.files()
    assert store.path_for(sha) == ref_store.path_for(sha)
    assert sorted(p.name for p in (tmp_path / "multi" / "favicons").iterdir()) == [f"{sha}.png"], "no temporary file is left behind"
    assert store.write_index(out) == ref_store.write_index(ref) == 1
    assert (tmp_path / "multi" / "favicons" / "index.jsonl").read_text() == (tmp_path / "ref" / "favicons" / "index.jsonl").read_text()


def test_concurrent_saves_of_one_image_through_separate_stores_are_safe(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    png = make_png()
    stores = [icon_store.IconStore(tmp_path / "favicons") for _ in range(4)]      # as if from four processes
    with ThreadPoolExecutor(16) as pool:
        paths = list(pool.map(lambda n: stores[n % 4].save("a" * 64, png), range(200)))
    assert set(paths) == {f"favicons/{'a' * 64}.png"}
    assert [p.name for p in (tmp_path / "favicons").iterdir()] == [f"{'a' * 64}.png"]


def test_stored_documents_reach_the_process_that_owns_the_address():
    from tests.test_http_document_reuse import stored
    jobs = [{"scheme": "http", "ip": f"198.51.{100 + i % 3}.{i}", "port": 80, "hostname": None} for i in range(1, 7)]
    docs = {(j["ip"], 80): stored() for j in jobs}
    single = fav.run_favicon_stage(FakeFetcher(), jobs, workers=2, max_icons=4, documents=docs, max_document_bytes=1 << 20)
    multi = run(jobs, 2, max_icons=4, documents=docs, max_document_bytes=1 << 20)
    aged = lambda recs: [{k: v for k, v in r.items() if k not in ("document_age_seconds", "captured_at", "favicon_at")} for r in recs]      # the age follows the clock
    assert aged(multi) == aged(single) and {r["document_source"] for r in multi} == {"reused"}
    assert all(r["document_age_seconds"] >= 0 for r in multi)


def test_pause_between_requests_to_one_address_holds_across_processes(tmp_path):
    interval = 0.25
    log = tmp_path / "contacts.log"
    jobs = make_jobs(16)
    out = run(jobs, 2, pace=interval, workers=16, factory=ProcessFetcherFactory(log=str(log)))
    assert len(out) == len(jobs) and all(r["favicon_outcome"] == "image" for r in out)
    stamps: dict[str, list[float]] = {}
    files = list(tmp_path.glob("contacts.log.*"))
    assert len(files) == 2, "each process logged its own contacts"
    for path in files:
        for line in path.read_text().splitlines():
            ip, t = line.split()
            stamps.setdefault(ip, []).append(float(t))
    assert len(stamps) == 16
    gaps = [b - a for s in stamps.values() for a, b in zip(sorted(s), sorted(s)[1:])]
    # the times are the pacer's own releases on its monotonic clock, which it keeps at least ``interval`` (less its 1e-6 s rounding) apart
    assert gaps and min(gaps) >= interval - 1e-5, f"two requests to one address {min(gaps):.6f} s apart"


def test_stop_reaches_every_process_quickly():
    jobs = make_jobs(24)
    begin = time.monotonic()
    out = run(jobs, 2, pace=30.0, workers=24, killed=lambda: time.monotonic() - begin > 3.0)
    assert time.monotonic() - begin < 40
    assert len(out) == len(jobs)
    assert "skipped_kill_switch" in {r["favicon_outcome"] for r in out}


def test_stop_before_start_skips_the_jobs_and_keeps_their_order():
    jobs = make_jobs(10)
    out = run(jobs, 2, killed=lambda: True)
    assert [(r["ip"], r["port"]) for r in out] == [(j["ip"], j["port"]) for j in jobs]
    assert {r["favicon_outcome"] for r in out} == {"skipped_kill_switch"}


def test_a_process_that_ignores_the_stop_is_terminated_after_the_grace_period(monkeypatch):
    monkeypatch.setattr(fav, "_BACKSTOP_SECONDS", 1.0)
    jobs = make_jobs(8, hostnames=False)
    hang = jobs[0]["ip"]
    begin = time.monotonic()
    out = run(jobs, 2, factory=ProcessFetcherFactory(hang_ip=hang), killed=lambda: time.monotonic() - begin > 1.0, grace=1.0)
    assert time.monotonic() - begin < 60
    assert len(out) == len(jobs)
    assert next(r for r in out if r["ip"] == hang)["favicon_outcome"] == "skipped_kill_switch"


def test_a_crashed_process_gives_error_records_for_its_jobs_and_not_a_hung_stage():
    jobs = make_jobs(12)
    crash = jobs[0]["ip"]
    doomed = next(p for p in fav.partition_by_ip(jobs, 2) if any(jobs[i]["ip"] == crash for i in p))
    begin = time.monotonic()
    out = run(jobs, 2, factory=ProcessFetcherFactory(crash_ip=crash))
    assert time.monotonic() - begin < 60
    assert len(out) == len(jobs)
    for i, rec in enumerate(out):
        if i in doomed:
            assert rec["favicon_outcome"] == "error" and "exited with code 3" in rec["error"]
        else:
            assert rec["favicon_outcome"] == "image"


def test_the_stop_flag_has_the_interface_of_an_event_and_survives_a_pickle_into_a_child():
    import multiprocessing
    ctx = multiprocessing.get_context("spawn")
    flag = fav.SharedFlag(ctx)
    assert not flag.is_set() and not flag.wait(0.05)
    flag.set()
    assert flag.is_set() and flag.wait(0.05)
    flag.clear()
    assert not flag.is_set()


def test_a_crashing_process_never_hangs_the_stage_however_often_it_is_repeated():
    jobs = make_jobs(6, hostnames=False)
    crash = jobs[0]["ip"]
    doomed = next(p for p in fav.partition_by_ip(jobs, 2) if any(jobs[i]["ip"] == crash for i in p))
    for attempt in range(60):
        begin = time.monotonic()
        out = run(jobs, 2, workers=4, factory=ProcessFetcherFactory(crash_ip=crash))
        assert time.monotonic() - begin < 60, f"attempt {attempt} took too long"
        assert len(out) == len(jobs)
        assert all(out[i]["favicon_outcome"] == "error" for i in doomed), f"attempt {attempt}"


def test_a_worker_that_cannot_build_its_fetcher_reports_error_records():
    jobs = make_jobs(6)
    out = run(jobs, 2, factory=ProcessFetcherFactory(broken=True))
    assert len(out) == len(jobs)
    assert {r["favicon_outcome"] for r in out} == {"error"} and all("cannot build a fetcher" in r["error"] for r in out)


def test_no_jobs_start_no_processes():
    assert run([], 4) == []


def test_processes_setting_is_validated(tmp_path):
    assert load_config(write_config(tmp_path)).favicon.processes == 1
    assert load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(processes=64, workers=64, max_active_requests=64))).favicon.processes == 64
    for bad in (0, 65, "two", True, 1.5):
        with pytest.raises(ConfigError, match="favicon.processes"):
            load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(processes=bad)))


def test_pipeline_outputs_match_between_one_and_two_processes(tmp_path):
    one, two = tmp_path / "one", tmp_path / "two"
    one.mkdir()
    two.mkdir()
    a = pipeline.run(load_config(write_config(one)), run_id="r1", executor=tools(), fetcher=FakeFetcher(),
                     skip_preflight=True, offline_preflight=True)
    cfg2 = load_config(_rewrite(two, lambda d: d["favicon"].update(processes=2)))
    b = pipeline.run(cfg2, run_id="r2", executor=tools(), fetcher_factory=ProcessFetcherFactory(),
                     skip_preflight=True, offline_preflight=True)
    # the age of a reused page follows the clock, which the worker processes do not share with this test
    def same(x, y):
        strip = lambda rows: [{k: v for k, v in r.items() if not k.endswith(("document_age_seconds", "favicon_at", "captured_at"))} for r in rows]
        assert strip(x) == strip(y) and x
    same(list(pipeline.outputs.iter_hostname_rows(a)), list(pipeline.outputs.iter_hostname_rows(b)))
    same(*[[json.loads(l) for l in (d / "normalized" / "endpoints.jsonl").read_text().splitlines()] for d in (a, b)])
    assert (a / "favicons" / "index.jsonl").read_text() == (b / "favicons" / "index.jsonl").read_text()
    assert sorted(p.name for p in (a / "favicons").iterdir()) == sorted(p.name for p in (b / "favicons").iterdir())
    ca, cb = (json.loads((d / "manifest.json").read_text())["stage_counts"] for d in (a, b))
    for key in ("favicon_images_stored", "favicon_images_indexed", "favicon_documents_reused"):
        assert ca.get(key) == cb.get(key)
    assert (a / "raw" / "favicon_records.jsonl").exists() and (b / "raw" / "favicon_records.jsonl").exists()
    same(*[sorted((json.loads(l) for l in (d / "raw" / "favicon_records.jsonl").read_text().splitlines()), key=lambda r: json.dumps(r["url"]))
           for d in (a, b)])


def test_a_redirect_into_another_partition_is_refused_before_any_connection(tmp_path):
    a, b = "198.51.100.1", "198.51.101.2"
    jobs = [{"scheme": "http", "ip": a, "port": 80, "hostname": None}, {"scheme": "http", "ip": b, "port": 80, "hostname": None}]
    assert len(fav.partition_by_ip(jobs, 2)) == 2
    log = tmp_path / "contacts.log"
    out = run(jobs, 2, factory=GuardedStubFactory({(a, 80), (b, 80)}, {a: b}, str(log)), workers=2)
    rec = {r["ip"]: r for r in out}
    assert "policy_refused" in json.dumps(rec[a]) and "policy_refused" not in json.dumps(rec[b])
    contacts: dict[str, set[str]] = {}
    for path in tmp_path.glob("contacts.log.*"):
        contacts[path.suffix] = {line.split()[0] for line in path.read_text().splitlines()}
    owners = [ips for ips in contacts.values() if b in ips]
    assert len(owners) == 1 and owners[0] == {b}, "only the process that owns B contacted B"
    assert [ips for ips in contacts.values() if a in ips] == [{a}]


def test_the_fetcher_factory_approves_only_the_endpoints_of_the_process(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(fav, "fetch_policy", lambda cfg, ips: seen.append(list(ips)) or TargetPolicy.for_tests(["198.51.100.0/24"]))
    cfg = load_config(write_config(tmp_path))
    endpoints = {("198.51.100.1", 80), ("198.51.100.2", 80), ("198.51.100.2", 443)}
    factory = fav.FetcherFactory(cfg, ["198.51.100.1", "198.51.100.2"], endpoints)
    mine = factory(None, frozenset({"198.51.100.2"}))
    assert mine.allowed_endpoints == {("198.51.100.2", 80), ("198.51.100.2", 443)}
    assert seen == [["198.51.100.2"]]
    assert factory(None).allowed_endpoints == endpoints


def test_the_global_caps_are_divided_rounding_down_and_never_exceeded():
    for total in (1, 3, 7, 64, 512):
        for parts in range(1, min(total, 64) + 1):
            share = fav.split_cap(total, parts)
            assert share >= 1 and share * parts <= total


def test_the_pipeline_hands_each_process_its_share_of_the_request_cap(tmp_path, monkeypatch):
    seen = {}

    class Recorder:
        def __init__(self, cfg, ips, endpoints, max_active_requests=None):
            seen["cap"] = max_active_requests

    def stage(factory, jobs, **kw):
        seen["workers"] = kw["workers"]
        for i, rec in enumerate(fav.run_favicon_stage(FakeFetcher(), jobs, workers=2, max_icons=2)):
            kw["record_sink"](i, rec)
        return []
    monkeypatch.setattr(fav, "FetcherFactory", Recorder)
    monkeypatch.setattr(fav, "run_favicon_stage_processes", stage)
    cfg = load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(processes=3, workers=10, max_active_requests=10)))
    pipeline.run(cfg, run_id="r", executor=tools(), skip_preflight=True, offline_preflight=True)
    assert seen == {"cap": 3, "workers": 10}


def test_more_processes_than_workers_or_active_requests_is_rejected(tmp_path):
    for key in ("workers", "max_active_requests"):
        with pytest.raises(ConfigError, match="favicon.processes"):
            load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(processes=4, **{key: 3})))
    cfg = load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(processes=4, workers=4, max_active_requests=4)))
    assert cfg.favicon.processes == 4


def test_temporary_files_of_a_terminated_process_are_removed(tmp_path):
    root = tmp_path / "favicons"
    store = icon_store.IconStore(root)
    root.mkdir()
    (root / f"{'a' * 64}.png.123.456.tmp").write_bytes(b"half")
    (root / f"{'b' * 64}.png").write_bytes(b"whole")
    jobs = make_jobs(6, hostnames=False)
    run(jobs, 2, icon_store=store)
    assert [p.name for p in root.iterdir() if p.name.endswith(".tmp")] == []
    assert (root / f"{'b' * 64}.png").exists()


def test_a_stop_is_noticed_while_dead_processes_are_being_collected(monkeypatch):
    monkeypatch.setattr(fav, "_BACKSTOP_SECONDS", 1.0)
    jobs = make_jobs(12)
    begin = time.monotonic()
    out = run(jobs, 4, factory=ProcessFetcherFactory(crash_ip=jobs[0]["ip"], hang_ip=jobs[-1]["ip"]), grace=1.0,
              killed=lambda: time.monotonic() - begin > 0.5)
    assert time.monotonic() - begin < 30 and len(out) == len(jobs)


def test_the_settings_file_validates_the_process_count(tmp_path, capsys):
    from tests.test_settings import _approve, _init
    from scanner.internet.__main__ import main
    path = _init(tmp_path)
    _approve(path)
    import yaml
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    for bad in ("abc", 0, 65, True):
        data["scope"]["favicon_processes"] = bad
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        assert main(["apply", "--workdir", str(tmp_path)]) == 2
        assert "scope.favicon_processes" in capsys.readouterr().err
    data["scope"].update(favicon_processes=4, favicon_workers=3)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert main(["apply", "--workdir", str(tmp_path)]) == 2
    assert "cannot exceed" in capsys.readouterr().err
    data["scope"].update(favicon_processes=2, favicon_workers=64)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert main(["apply", "--workdir", str(tmp_path)]) == 0
    assert load_config(tmp_path / "config.yaml").favicon.processes == 2
