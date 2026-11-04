"""Bounded memory of the favicon stage: worker replacement, keys instead of records, capped refusal lists."""
from __future__ import annotations

import os
import threading
import time

from scanner.internet import favicon as fav
from scanner.internet.config import load_config
from scanner.safety import TargetPolicy
from tests.helpers import FakeFetcher, ProcessFetcherFactory, write_config
from tests.test_favicon_processes import bare, make_jobs, run


def contacts_by_process(tmp_path):
    owners: dict[str, set[str]] = {}
    for path in tmp_path.glob("contacts.log.*"):
        for line in path.read_text().splitlines():
            owners.setdefault(line.split()[0], set()).add(path.suffix)
    return owners


def test_replacing_workers_after_n_lookups_gives_the_same_records(tmp_path):
    jobs = make_jobs(20)
    plain = run(jobs, 2, worker_max_lookups=0)
    envs = tmp_path / "env.log"
    recycled = run(jobs, 2, worker_max_lookups=5, factory=ProcessFetcherFactory(env_log=str(envs)))
    assert len(recycled) == len(jobs) and bare(recycled) == bare(plain)
    lines = envs.read_text().splitlines()
    assert len({line.split()[0] for line in lines}) == len(lines) > 2, "every segment ran in a process of its own"
    owned = [set(line.split()[2].split(",")) for line in lines]
    assert all(len(o) > 1 for o in owned), "a process is approved for its whole partition, not only its segment"


def test_segments_never_split_a_network_and_respect_the_limit():
    jobs = make_jobs(60)
    indexes = list(range(len(jobs)))
    sizes: dict[str, int] = {}
    for job in jobs:
        key = fav.network_key(job["ip"])
        sizes[key] = sizes.get(key, 0) + 1
    for limit in (1, 7, 25, 1000):
        segments = fav.segment_by_network(indexes, jobs, limit)
        assert sorted(k for seg in segments for k in seg) == indexes
        owner: dict[str, int] = {}
        for n, seg in enumerate(segments):
            for k in seg:
                assert owner.setdefault(fav.network_key(jobs[k]["ip"]), n) == n
        assert all(len(seg) <= max(limit, max(sizes.values())) for seg in segments)
    assert fav.segment_by_network(indexes, jobs, 0) == [indexes]
    assert fav.segment_by_network([], jobs, 5) == []


def test_an_address_is_contacted_from_one_process_across_replacements(tmp_path):
    jobs = make_jobs(15, hostnames=False)
    out = run(jobs, 2, worker_max_lookups=3, factory=ProcessFetcherFactory(log=str(tmp_path / "contacts.log")))
    assert len(out) == len(jobs) and {r["favicon_outcome"] for r in out} == {"image"}
    owners = contacts_by_process(tmp_path)
    assert set(owners) == {j["ip"] for j in jobs}
    assert all(len(o) == 1 for o in owners.values()), "an address was contacted from two processes"


def test_workers_get_only_jobs_that_are_not_done_and_the_records_still_come_back(tmp_path):
    jobs = make_jobs(12)
    first = run(jobs, 2)
    done = {(r["ip"], r["port"], r.get("hostname")): r for r in first[::2]}
    seen: list[dict] = []
    out = run(jobs, 2, done=done, worker_max_lookups=2, on_record=seen.append,
              factory=ProcessFetcherFactory(log=str(tmp_path / "contacts.log")))
    assert bare(out) == bare(first)
    assert len(seen) == len(jobs) - len(done), "lookups already done are not fetched again"


def test_a_stop_during_replacements_skips_what_is_left():
    jobs = make_jobs(30, hostnames=False)
    begin = time.monotonic()
    out = run(jobs, 2, worker_max_lookups=3, killed=lambda: time.monotonic() - begin > 0.5,
              factory=ProcessFetcherFactory(delay=0.2), grace=1.0)
    assert len(out) == len(jobs)
    assert {r["favicon_outcome"] for r in out} <= {"image", "skipped_kill_switch"}
    assert any(r["favicon_outcome"] == "skipped_kill_switch" for r in out)


def test_a_crash_in_a_later_segment_fails_only_what_was_left_of_the_partition():
    jobs = make_jobs(12, hostnames=False)
    out = run(jobs, 1, worker_max_lookups=3, factory=ProcessFetcherFactory(crash_ip=jobs[-1]["ip"]))
    assert len(out) == len(jobs)
    bad = [r for r in out if r["favicon_outcome"] == "error"]
    assert bad and len(bad) < len(jobs) and all("exited with code 3" in r["error"] for r in bad)


def test_workers_start_with_a_limited_number_of_malloc_arenas(tmp_path, monkeypatch):
    monkeypatch.delenv("MALLOC_ARENA_MAX", raising=False)
    env = tmp_path / "env.log"
    run(make_jobs(6, hostnames=False), 2, factory=ProcessFetcherFactory(env_log=str(env)))
    assert {line.split()[1] for line in env.read_text().splitlines()} == {fav.WORKER_ARENA_MAX}
    assert "MALLOC_ARENA_MAX" not in os.environ, "the parent's environment is left as it was"


def test_an_arena_setting_of_the_operator_is_kept(tmp_path, monkeypatch):
    monkeypatch.setenv("MALLOC_ARENA_MAX", "5")
    env = tmp_path / "env.log"
    run(make_jobs(6, hostnames=False), 2, factory=ProcessFetcherFactory(env_log=str(env)))
    assert {line.split()[1] for line in env.read_text().splitlines()} == {"5"}
    assert os.environ["MALLOC_ARENA_MAX"] == "5"


def test_a_fetch_policy_keeps_a_bounded_list_of_refusals(tmp_path):
    cfg = load_config(write_config(tmp_path))
    policy = fav.fetch_policy(cfg, ["8.8.8.8"])
    assert policy.max_refusals == fav.FETCH_POLICY_REFUSALS_KEPT
    policy.max_refusals = 5
    for n in range(50):
        assert policy.check_ip("10.0.0.1", stage="fetch", context=str(n)) is not None
    assert len(policy.refusals) == 5 and policy.refusals_total == 50
    assert [r.context for r in policy.refusals] == ["0", "1", "2", "3", "4"], "the first examples are the ones kept"


def test_a_policy_without_a_cap_keeps_every_refusal():
    policy = TargetPolicy.for_tests(["198.51.100.0/24"])
    for _ in range(30):
        policy.check_ip("10.0.0.1", stage="x")
    assert len(policy.refusals) == policy.refusals_total == 30


def test_the_record_index_reads_records_back_from_the_log(tmp_path):
    path = tmp_path / "raw" / "favicon_records.jsonl"
    log = fav.RecordLog(path)
    recs = [{"ip": f"198.51.100.{i}", "port": 80, "hostname": None, "favicon_outcome": "image", "n": i} for i in range(1, 6)]
    for rec in recs:
        log.append(rec)
    log.append({**recs[0], "n": 99})        # a later record of the same lookup wins, as with load()
    log.close()
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"ip": "198.51.100.9", "po')     # cut short by a kill
    index, loaded = fav.RecordLog(path).load_index(), fav.RecordLog(path).load()
    assert len(index) == len(loaded) == 5 and bool(index)
    for key, rec in loaded.items():
        assert key in index and index.get(key) == rec
    missing = ("198.51.100.9", 80, None)
    assert missing not in index and index.get(missing) is None
    extra = ("203.0.113.1", 80, None)
    index.put(extra, {"ip": "203.0.113.1", "port": 80, "hostname": None})
    assert extra in index and len(index) == 6 and index.get(extra)["ip"] == "203.0.113.1"
    assert not fav.RecordLog(tmp_path / "none.jsonl").load_index()


def test_a_resumed_single_process_stage_reads_done_records_from_the_index(tmp_path):
    jobs = make_jobs(10, hostnames=False)
    log = fav.RecordLog(tmp_path / "favicon_records.jsonl")
    first = fav.run_favicon_stage(FakeFetcher(), jobs, workers=4, max_icons=2, on_record=log.append)
    log.close()
    fetcher = FakeFetcher()
    again = fav.run_favicon_stage(fetcher, jobs, workers=4, max_icons=2, done=log.load_index())
    assert again == first and fetcher.calls == []


def test_decodes_are_bounded(monkeypatch):
    active, peak, lock = 0, [0], threading.Lock()

    def slow(data):
        nonlocal active
        with lock:
            active += 1
            peak[0] = max(peak[0], active)
        time.sleep(0.05)
        with lock:
            active -= 1
        return data
    monkeypatch.setattr(fav, "compute_fingerprint", slow)
    cache = fav.FingerprintCache(max_decodes=2)
    threads = [threading.Thread(target=cache, args=(bytes([n]) * 10,)) for n in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak[0] == 2


def test_pipeline_outputs_do_not_change_with_worker_replacement(tmp_path):
    import json
    from scanner.internet import pipeline
    from tests.helpers import ProcessFetcherFactory
    from tests.test_config import _rewrite
    from tests.test_pipeline import tools
    dirs = {}
    for name, extra in (("whole", {}), ("recycled", {"worker_max_lookups": 1})):
        root = tmp_path / name
        root.mkdir()
        cfg = load_config(_rewrite(root, lambda d, extra=extra: d["favicon"].update(processes=2, **extra)))
        dirs[name] = pipeline.run(cfg, run_id="r", executor=tools(), fetcher_factory=ProcessFetcherFactory(),
                                  skip_preflight=True, offline_preflight=True)

    def rows(run_dir):
        strip = lambda r: {k: v for k, v in r.items() if not k.endswith(("document_age_seconds", "favicon_at", "captured_at"))}
        return [strip(r) for r in pipeline.outputs.iter_hostname_rows(run_dir)]
    assert rows(dirs["whole"]) == rows(dirs["recycled"]) and rows(dirs["whole"])
    a, b = (json.loads((dirs[n] / "manifest.json").read_text())["stage_counts"] for n in ("whole", "recycled"))
    for key in ("favicon_images_stored", "favicon_images_indexed", "favicon_documents_reused"):
        assert a.get(key) == b.get(key)


def test_the_replacement_limit_is_a_host_local_setting(tmp_path):
    import pytest
    from scanner.internet.config import ConfigError
    from tests.test_config import _rewrite
    plain = load_config(write_config(tmp_path))
    assert not hasattr(plain.favicon, "worker_max_lookups"), "a config that leaves it out keeps its stored favicon section"
    set_ = load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(worker_max_lookups=1000)))
    assert set_.favicon.worker_max_lookups == 1000 and set_.checksum == plain.checksum
    for bad in (-1, "many", True, 1.5):
        with pytest.raises(ConfigError, match="worker_max_lookups"):
            load_config(_rewrite(tmp_path, lambda d: d["favicon"].update(worker_max_lookups=bad)))
