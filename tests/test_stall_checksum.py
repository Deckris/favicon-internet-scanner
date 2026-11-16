"""``operations.stall_minutes`` is a host-derived setting: it decides when a run is stopped, not what it measures.

Changing it must leave the configuration checksum, the campaign directory, the run ids and the resume identity as they
are, while every other operations key and every politeness limit still changes them.
"""
from __future__ import annotations

import copy
import dataclasses
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scanner.internet import campaign, coordinator, pipeline
from scanner.internet import resume as resume_mod
from scanner.internet.config import (HOST_DERIVED_KEYS, HOST_LOCAL_SECTIONS, ConfigError, ScanConfig, config_checksum,
                                     load_config, shared_config_checksum)
from tests.test_coordinator import Cluster, run as run_decoupled, state_of
from tests.test_scale import _cfg, _fake_run

ROOT = Path(__file__).resolve().parent.parent
STALL_VALUES = [0, 1, 30, 240, 100000]
POLITENESS_KEYS = ("min_seconds_between_probes_per_ip", "max_connections_per_subnet", "retry_after_max_hold_seconds",
                   "subnet_wait_max_seconds", "overlap_tls_with_zmap")
TOP_LEVEL = {"run_label", "vantage", "sample", "measurement", "target_policy", "dns", "hostnames", "sni_confirm", "favicon", "fetch",
             "transparency", "output", "operations", "binaries", "tarpit", "asn", "ct_names"}


# ------------------------------------------------------------------ the checksum code as it was before the change

def _load_head_config():
    """``scanner/internet/config.py`` as committed, loaded as a separate module; the working tree is not touched."""
    try:
        source = subprocess.run(["git", "show", "HEAD:scanner/internet/config.py"], cwd=ROOT, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    name = "scanner.internet._config_at_head"
    spec = importlib.util.spec_from_loader(name, loader=None)
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "scanner.internet"
    sys.modules[name] = module
    try:
        exec(compile(source, "config_at_head.py", "exec"), module.__dict__)
    except Exception:
        sys.modules.pop(name, None)
        return None
    return module


HEAD = _load_head_config()
needs_head = pytest.mark.skipif(HEAD is None or "stall_minutes" in HEAD.HOST_DERIVED_KEYS.get("operations", ()),
                                reason="the committed config.py is not available or already has the change")


# ------------------------------------------------------------------ builders

def build(tmp_path, *, stall="absent", operations=None, sample=None, output=None, mutate=None, name="scale.yaml"):
    """Write a config next to ``tmp_path`` and return its path. ``stall`` is left out of the file when it is ``"absent"``."""
    path = _cfg(tmp_path, sample=sample, output=output, operations=operations)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if stall != "absent":
        data["operations"]["stall_minutes"] = stall
    if mutate:
        mutate(data)
    target = tmp_path / name
    target.write_text(yaml.safe_dump(data), encoding="utf-8")
    return target


def checksum_of(tmp_path, **kw):
    return load_config(build(tmp_path, **kw)).checksum


def base_raw(tmp_path):
    return copy.deepcopy(load_config(build(tmp_path)).raw)


# Several complete configurations, none of which sets stall_minutes.
VARIANTS = {
    "plain": dict(),
    "operations_keys": dict(operations={"egress_check_seconds": 45, "min_free_mib": 2048, "min_free_gb_between_shards": 7.5}),
    "sharded": dict(sample={"fraction": 0.0001, "seed": 4, "shards": 3}),
    "other_seed": dict(sample={"fraction": 0.0001, "seed": 99}),
    "compacting": dict(output={"compact": True, "prune_raw_keep_every": 4}),
    "two_ports": dict(mutate=lambda d: d["measurement"].update(ports=[80, 443])),
    "politeness": dict(mutate=lambda d: d["measurement"].update(max_connections_per_subnet=4, subnet_wait_max_seconds=90)),
    "host_sizing": dict(mutate=lambda d: (d["measurement"].update(zgrab_senders=40), d["dns"].update(threads=33),
                                          d["favicon"].update(workers=6, processes=2, stage_max_seconds=5000))),
}


# ------------------------------------------------------------------ the checksum does not follow stall_minutes

@pytest.mark.parametrize("value", STALL_VALUES)
def test_stall_minutes_does_not_change_the_checksum(tmp_path, value):
    assert checksum_of(tmp_path, stall=value) == checksum_of(tmp_path)


@pytest.mark.parametrize("a,b", [(0, 1), (1, 30), (30, 240), (240, 100000), (0, 100000)])
def test_two_stall_values_give_one_checksum(tmp_path, a, b):
    assert checksum_of(tmp_path, stall=a) == checksum_of(tmp_path, stall=b)


def test_the_default_and_an_explicit_30_are_one_campaign(tmp_path):
    absent = load_config(build(tmp_path))
    explicit = load_config(build(tmp_path, stall=30))
    assert absent.stall_minutes == explicit.stall_minutes == 30
    assert absent.checksum == explicit.checksum


@pytest.mark.parametrize("value", STALL_VALUES)
def test_the_value_is_kept_in_the_loaded_config(tmp_path, value):
    cfg = load_config(build(tmp_path, stall=value))
    assert cfg.stall_minutes == value and cfg.raw["operations"]["stall_minutes"] == value


def test_a_config_without_the_key_loads_with_the_default(tmp_path):
    cfg = load_config(build(tmp_path))
    assert cfg.stall_minutes == 30 and "stall_minutes" not in cfg.raw["operations"]


def test_stall_minutes_does_not_change_the_checksum_with_other_operations_keys_set(tmp_path):
    ops = {"egress_check_seconds": 45, "min_free_mib": 2048, "min_free_gb_between_shards": 7.5}
    base = checksum_of(tmp_path, operations=ops)
    for value in STALL_VALUES:
        assert checksum_of(tmp_path, operations=ops, stall=value) == base


def test_stall_minutes_does_not_change_the_checksum_of_a_sharded_config(tmp_path):
    sample = {"fraction": 0.0001, "seed": 4, "shards": 3}
    assert checksum_of(tmp_path, sample=sample, stall=5) == checksum_of(tmp_path, sample=sample)


# ------------------------------------------------------------------ a config that never set it keeps its old checksum

@needs_head
@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_a_config_without_stall_minutes_keeps_the_checksum_it_had_before(tmp_path, variant):
    path = build(tmp_path, **VARIANTS[variant])
    assert load_config(path).checksum == HEAD.load_config(path).checksum


@needs_head
@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_the_raw_checksum_function_agrees_with_the_one_before_on_the_same_dict(tmp_path, variant):
    raw = load_config(build(tmp_path, **VARIANTS[variant])).raw
    assert "stall_minutes" not in raw["operations"]
    assert config_checksum(raw) == HEAD.config_checksum(raw)
    assert shared_config_checksum(raw) == HEAD.shared_config_checksum(raw)


@needs_head
def test_the_checksum_of_the_plain_sample_config_is_pinned_to_the_one_before(tmp_path):
    path = build(tmp_path)
    old = HEAD.load_config(path).checksum
    assert len(old) == 64 and load_config(path).checksum == old


@needs_head
@pytest.mark.parametrize("value", STALL_VALUES)
def test_a_config_with_stall_minutes_matches_the_old_checksum_of_the_same_config_without_it(tmp_path, value):
    with_key = load_config(build(tmp_path, stall=value, name="with.yaml")).checksum
    without = HEAD.load_config(build(tmp_path, name="without.yaml")).checksum
    assert with_key == without


@needs_head
@pytest.mark.parametrize("value", [1, 240])
def test_the_old_code_did_hash_the_key(tmp_path, value):
    """The contrast that gives the other tests their meaning: before the change the key was part of the checksum."""
    assert HEAD.load_config(build(tmp_path, stall=value, name="a.yaml")).checksum != HEAD.load_config(build(tmp_path, name="b.yaml")).checksum


@needs_head
@pytest.mark.parametrize("value", [0, 1, 240])
def test_a_campaign_started_under_an_explicit_value_before_the_change_has_another_name_now(tmp_path, value):
    """Documented in ``config_checksum``: a config that sets the key now hashes as if it did not, so an earlier directory is not recognised."""
    path = build(tmp_path, stall=value)
    assert load_config(path).checksum != HEAD.load_config(path).checksum


@needs_head
def test_the_old_head_does_not_list_the_key(tmp_path):
    assert "operations" not in HEAD.HOST_DERIVED_KEYS


# ------------------------------------------------------------------ other operations keys still count

OTHER_OPERATIONS = [("kill_switch_file", "elsewhere/KILL"), ("egress_check_seconds", 61), ("min_free_mib", 4096),
                    ("min_free_gb_between_shards", 3.5), ("min_free_gb_between_shards", 0.0)]


@pytest.mark.parametrize("key,value", OTHER_OPERATIONS)
def test_other_operations_keys_still_change_the_checksum(tmp_path, key, value):
    if key == "kill_switch_file":
        value = str(tmp_path / value)
    assert checksum_of(tmp_path, operations={key: value}) != checksum_of(tmp_path)


@pytest.mark.parametrize("key,value", OTHER_OPERATIONS)
def test_other_operations_keys_still_change_the_checksum_when_stall_minutes_is_set(tmp_path, key, value):
    if key == "kill_switch_file":
        value = str(tmp_path / value)
    assert checksum_of(tmp_path, operations={key: value}, stall=45) != checksum_of(tmp_path, stall=45)


@pytest.mark.parametrize("key,value", OTHER_OPERATIONS)
def test_changing_stall_minutes_together_with_another_key_does_not_hide_that_key(tmp_path, key, value):
    if key == "kill_switch_file":
        value = str(tmp_path / value)
    one = checksum_of(tmp_path, operations={key: value}, stall=5)
    two = checksum_of(tmp_path, operations={key: value}, stall=500)
    assert one == two != checksum_of(tmp_path, stall=5)


def test_a_new_operations_key_value_in_a_raw_dict_is_hashed(tmp_path):
    raw = base_raw(tmp_path)
    changed = copy.deepcopy(raw)
    changed["operations"]["egress_check_seconds"] = 7
    assert config_checksum(changed) != config_checksum(raw)


# ------------------------------------------------------------------ politeness limits still count

POLITENESS_CHANGES = [("min_seconds_between_probes_per_ip", 1), ("max_connections_per_subnet", 8),
                      ("retry_after_max_hold_seconds", 300), ("subnet_wait_max_seconds", 600),
                      ("overlap_tls_with_zmap", True), ("zmap_rate", 50)]


@pytest.mark.parametrize("key,value", POLITENESS_CHANGES)
def test_politeness_limits_still_change_the_checksum(tmp_path, key, value):
    changed = checksum_of(tmp_path, mutate=lambda d: d["measurement"].update({key: value}))
    assert changed != checksum_of(tmp_path)


@pytest.mark.parametrize("key,value", POLITENESS_CHANGES)
def test_politeness_limits_still_change_the_checksum_next_to_a_stall_value(tmp_path, key, value):
    changed = checksum_of(tmp_path, stall=3, mutate=lambda d: d["measurement"].update({key: value}))
    assert changed != checksum_of(tmp_path, stall=3)


@pytest.mark.parametrize("key,value", POLITENESS_CHANGES[:4])
def test_politeness_limits_still_change_the_shared_checksum(tmp_path, key, value):
    a = load_config(build(tmp_path, stall=3)).raw
    b = load_config(build(tmp_path, stall=3, mutate=lambda d: d["measurement"].update({key: value}))).raw
    assert shared_config_checksum(a) != shared_config_checksum(b)


@pytest.mark.parametrize("key", POLITENESS_KEYS)
def test_no_politeness_key_is_host_derived(key):
    assert all(key not in keys for keys in HOST_DERIVED_KEYS.values())


# ------------------------------------------------------------------ the other host-derived keys still do not count

GOOD_VALUES = {
    ("measurement", "zgrab_senders"): (11, 12), ("measurement", "zgrab_parallel_batches"): (2, 3),
    ("measurement", "zgrab_batch_size"): (400, 700), ("measurement", "limiter_socket"): ("/run/a.sock", "/run/b.sock"),
    ("measurement", "zmap_source_ports"): ("1024-2000", "3000-9999"), ("dns", "threads"): (5, 50),
    ("dns", "query_resolver_version"): (False, True),
    ("favicon", "workers"): (3, 9), ("favicon", "processes"): (1, 2), ("favicon", "max_active_requests"): (100, 300),
    ("favicon", "stage_max_seconds"): (8000, 9000), ("favicon", "worker_max_lookups"): (10, 20000),
    ("favicon", "prefetch"): (False, True), ("favicon", "fast_jobs"): (False, True),
    ("operations", "stall_minutes"): (2, 600), ("target_policy", "exclusions_overlay_file"): ("a.txt", "b.txt"),
}


def _all_host_derived_pairs():
    return [(s, k) for s, keys in HOST_DERIVED_KEYS.items() for k in keys]


def test_the_table_of_good_values_covers_every_host_derived_key_but_the_ct_list():
    assert set(_all_host_derived_pairs()) - set(GOOD_VALUES) == {("ct_names", "names_file")}


@pytest.mark.parametrize("section,key", sorted(GOOD_VALUES))
def test_every_host_derived_key_still_leaves_the_checksum_alone(tmp_path, section, key):
    one, other = GOOD_VALUES[(section, key)]
    first = checksum_of(tmp_path, mutate=lambda d: d[section].update({key: one}))
    second = checksum_of(tmp_path, mutate=lambda d: d[section].update({key: other}))
    assert first == second == checksum_of(tmp_path)


@pytest.mark.parametrize("section,key", sorted(GOOD_VALUES))
def test_every_host_derived_key_leaves_the_raw_checksum_alone(tmp_path, section, key):
    raw = base_raw(tmp_path)
    one, other = GOOD_VALUES[(section, key)]
    a, b = copy.deepcopy(raw), copy.deepcopy(raw)
    a[section][key], b[section][key] = one, other
    assert config_checksum(a) == config_checksum(b) == config_checksum(raw)


def test_the_ct_name_list_path_is_left_out_only_when_the_list_is_on(tmp_path):
    raw = base_raw(tmp_path)
    on = lambda path: {**raw, "ct_names": {"enabled": True, "names_file": path, "max_names_per_domain": 5}}
    assert config_checksum(on("/a/names.txt")) == config_checksum(on("/b/names.txt"))
    assert config_checksum(on("/a/names.txt")) != config_checksum(raw)
    off = {**raw, "ct_names": {"enabled": False, "names_file": "/a/names.txt"}}
    assert config_checksum(off) == config_checksum(raw)


def test_host_derived_values_do_not_mask_a_politeness_change(tmp_path):
    raw = base_raw(tmp_path)
    a = copy.deepcopy(raw)
    a["operations"]["stall_minutes"] = 9
    a["favicon"]["workers"] = 77
    b = copy.deepcopy(a)
    b["measurement"]["max_connections_per_subnet"] = 12
    assert config_checksum(a) != config_checksum(b)


# ------------------------------------------------------------------ shared checksum

@pytest.mark.parametrize("value", STALL_VALUES)
def test_shared_checksum_is_the_same_for_every_stall_value(tmp_path, value):
    assert shared_config_checksum(load_config(build(tmp_path, stall=value)).raw) == shared_config_checksum(load_config(build(tmp_path)).raw)


@needs_head
def test_shared_checksum_equals_the_one_before_for_the_same_config(tmp_path):
    raw = load_config(build(tmp_path)).raw
    assert shared_config_checksum(raw) == HEAD.shared_config_checksum(raw)


def test_shared_checksum_still_ignores_the_whole_operations_section(tmp_path):
    raw = base_raw(tmp_path)
    moved = copy.deepcopy(raw)
    moved["operations"] = {"kill_switch_file": "/else/KILL", "egress_check_seconds": 1, "min_free_mib": 99, "stall_minutes": 4}
    assert shared_config_checksum(moved) == shared_config_checksum(raw)


def test_pipeline_wrapper_of_the_shared_checksum_ignores_stall_minutes(tmp_path):
    a, b = load_config(build(tmp_path, stall=1)).raw, load_config(build(tmp_path, stall=900)).raw
    assert pipeline.shared_checksum(a) == pipeline.shared_checksum(b)


def test_shared_checksum_still_follows_the_sample(tmp_path):
    a = load_config(build(tmp_path, stall=1)).raw
    b = load_config(build(tmp_path, stall=1, sample={"fraction": 0.0001, "seed": 11})).raw
    assert shared_config_checksum(a) != shared_config_checksum(b)


def test_operations_is_host_local_and_host_derived_at_the_same_time():
    assert "operations" in HOST_LOCAL_SECTIONS and HOST_DERIVED_KEYS["operations"] == ("stall_minutes",)


# ------------------------------------------------------------------ the checksum function on odd input

@pytest.mark.parametrize("odd", ["abc", None, [1, 2], {"nested": 1}, 1.5, True, -5])
def test_the_checksum_ignores_the_key_whatever_its_value(tmp_path, odd):
    raw = base_raw(tmp_path)
    changed = copy.deepcopy(raw)
    changed["operations"]["stall_minutes"] = odd
    assert config_checksum(changed) == config_checksum(raw)


def test_the_checksum_function_does_not_modify_its_input(tmp_path):
    raw = base_raw(tmp_path)
    raw["operations"]["stall_minutes"] = 12
    before = copy.deepcopy(raw)
    config_checksum(raw)
    shared_config_checksum(raw)
    assert raw == before


def test_only_stall_minutes_leaves_the_operations_section():
    from scanner.internet.config import _without_host_derived
    raw = {"operations": {"kill_switch_file": "k", "stall_minutes": 3, "min_free_mib": 100}}
    assert _without_host_derived(raw) == {"operations": {"kill_switch_file": "k", "min_free_mib": 100}}


@pytest.mark.parametrize("operations", [None, "text", ["stall_minutes"], 5])
def test_an_operations_section_that_is_not_a_mapping_does_not_break_the_checksum(operations):
    raw = {"operations": operations, "sample": {"seed": 1}}
    assert config_checksum(raw) == config_checksum({"sample": {"seed": 1}, "operations": operations})
    assert len(config_checksum(raw)) == 64


def test_a_missing_operations_section_is_not_an_empty_one():
    """Pinned behaviour: only the key is dropped, not the section, so a section with nothing else in it still counts as present."""
    assert config_checksum({"sample": {"seed": 1}}) != config_checksum({"sample": {"seed": 1}, "operations": {"stall_minutes": 3}})
    assert config_checksum({"operations": {"stall_minutes": 3}}) == config_checksum({"operations": {}})


def test_key_order_in_the_file_does_not_matter(tmp_path):
    a = {"operations": {"kill_switch_file": "k", "stall_minutes": 3, "min_free_mib": 100}}
    b = {"operations": {"min_free_mib": 100, "stall_minutes": 9, "kill_switch_file": "k"}}
    assert config_checksum(a) == config_checksum(b)


# ------------------------------------------------------------------ validation

BAD_VALUES = [(-1, "negative"), (-100000, "negative"), (100001, "above"), (10**9, "above"), ("30", "string"), ("", "empty string"),
              (30.0, "float"), (0.5, "float"), (True, "bool"), (False, "bool"), (None, "null"), ([30], "list"), ({"a": 1}, "mapping")]


@pytest.mark.parametrize("value", [v for v, _ in BAD_VALUES], ids=[f"{n}-{i}" for i, (_, n) in enumerate(BAD_VALUES)])
def test_a_bad_stall_value_is_refused_and_named(tmp_path, value):
    with pytest.raises(ConfigError, match=r"operations\.stall_minutes"):
        load_config(build(tmp_path, stall=value))


@pytest.mark.parametrize("value", [0, 1, 99999, 100000])
def test_the_bounds_are_accepted(tmp_path, value):
    assert load_config(build(tmp_path, stall=value)).stall_minutes == value


def test_zero_switches_the_check_off_in_the_stage_runner(tmp_path):
    cfg = load_config(build(tmp_path, stall=0))
    assert pipeline._Stages(cfg, tmp_path).stall_seconds == 0


def test_an_unknown_operations_key_is_still_refused(tmp_path):
    with pytest.raises(ConfigError, match="unknown keys in 'operations'"):
        load_config(build(tmp_path, operations={"stall_minute": 3}))


def test_the_error_message_gives_the_range(tmp_path):
    with pytest.raises(ConfigError, match=r"\[0, 100000\]"):
        load_config(build(tmp_path, stall=100001))


# ------------------------------------------------------------------ the value reaches the stage runner

@pytest.mark.parametrize("value", STALL_VALUES)
def test_the_stage_runner_gets_minutes_times_sixty_seconds(tmp_path, value):
    cfg = load_config(build(tmp_path, stall=value))
    st = pipeline._Stages(cfg, tmp_path)
    assert st.stall_seconds == value * 60 and isinstance(st.stall_seconds, float)


def test_the_stage_runner_uses_the_default_when_the_key_is_absent(tmp_path):
    assert pipeline._Stages(load_config(build(tmp_path)), tmp_path).stall_seconds == 1800


def test_replacing_the_value_on_a_loaded_config_reaches_the_runner_and_not_the_checksum(tmp_path):
    cfg = load_config(build(tmp_path))
    other = dataclasses.replace(cfg, stall_minutes=3)
    assert pipeline._Stages(other, tmp_path).stall_seconds == 180 and other.checksum == cfg.checksum


# ------------------------------------------------------------------ snapshot and manifest

def test_the_snapshot_of_the_raw_config_keeps_the_key_and_hashes_to_the_same_checksum(tmp_path):
    cfg = load_config(build(tmp_path, stall=45))
    snapshot = json.loads(json.dumps(cfg.raw, indent=2, sort_keys=True, default=str))
    assert snapshot["operations"]["stall_minutes"] == 45
    assert config_checksum(snapshot) == cfg.checksum
    assert shared_config_checksum(snapshot) == shared_config_checksum(cfg.raw)


def test_a_run_writes_the_key_to_its_snapshot_and_the_same_checksum_to_its_manifest(tmp_path):
    from tests.helpers import FakeFetcher
    from tests.test_pipeline import tools
    cfg = load_config(build(tmp_path, stall=45))
    run_dir = pipeline.run(cfg, run_id="snap", executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)
    snapshot = json.loads((run_dir / "config.snapshot.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert snapshot["operations"]["stall_minutes"] == 45
    assert config_checksum(snapshot) == cfg.checksum == manifest["config_checksum"]
    assert manifest["epoch_id"] == cfg.checksum[:len(manifest["epoch_id"])]
    assert manifest["complete"] is True


def test_a_favicon_only_run_accepts_a_config_that_differs_in_stall_minutes_only(tmp_path):
    from tests.helpers import FakeFetcher
    from tests.test_pipeline import tools
    cfg = load_config(build(tmp_path, stall=45))
    run_dir = pipeline.run(cfg, run_id="split", executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True,
                           network_only=True)
    other = load_config(build(tmp_path, stall=7, name="other.yaml"))
    done = pipeline.run_favicon_only(other, run_dir, executor=tools(), fetcher=FakeFetcher())
    assert json.loads((done / "manifest.json").read_text(encoding="utf-8"))["complete"] is True


# ------------------------------------------------------------------ campaign directory, run ids and identities

@pytest.mark.parametrize("value", STALL_VALUES)
def test_the_campaign_directory_name_does_not_change(tmp_path, value):
    a, b = load_config(build(tmp_path)), load_config(build(tmp_path, stall=value, name="b.yaml"))
    assert campaign.campaign_dir(a) == campaign.campaign_dir(b)
    assert campaign.campaign_dir(b).name == f"campaign-{a.checksum[:12]}"


@pytest.mark.parametrize("value", STALL_VALUES)
def test_run_ids_do_not_change(tmp_path, value):
    sample = {"fraction": 0.0001, "seed": 4, "shards": 3}
    a, b = load_config(build(tmp_path, sample=sample)), load_config(build(tmp_path, sample=sample, stall=value, name="b.yaml"))
    for i in range(3):
        assert campaign._run_id(a, i, 1) == campaign._run_id(b, i, 1)
        assert coordinator.run_id_for(a, i) == coordinator.run_id_for(b, i)


def test_confirm_token_epoch_and_resume_identity_do_not_change(tmp_path):
    a, b = load_config(build(tmp_path)), load_config(build(tmp_path, stall=2, name="b.yaml"))
    assert pipeline.confirm_token(a, pipeline.build_policy(a)[1]) == pipeline.confirm_token(b, pipeline.build_policy(b)[1])
    assert pipeline.epoch_id(a) == pipeline.epoch_id(b)
    assert resume_mod.run_identity(a) == resume_mod.run_identity(b)


def test_a_changed_politeness_limit_does_change_the_campaign_directory(tmp_path):
    a = load_config(build(tmp_path, stall=2))
    b = load_config(build(tmp_path, stall=2, name="b.yaml", mutate=lambda d: d["measurement"].update(max_connections_per_subnet=8)))
    assert campaign.campaign_dir(a) != campaign.campaign_dir(b)


# ------------------------------------------------------------------ resuming under another value

def test_a_state_file_written_under_one_value_loads_under_another(tmp_path):
    first = load_config(build(tmp_path, stall=30))
    state = campaign.load_state(first)
    state["shard_states"]["0"] = {"status": "complete", "run_dir": "x"}
    campaign._write_json(campaign.campaign_dir(first) / "campaign.json", state)
    for value in (0, 1, 240, 100000):
        second = load_config(build(tmp_path, stall=value, name=f"s{value}.yaml"))
        loaded = campaign.load_state(second)
        assert loaded["config_checksum"] == first.checksum and loaded["shard_states"]["0"]["status"] == "complete"


def _copy_state_into_the_directory_of(first, second):
    campaign._write_json(campaign.campaign_dir(first) / "campaign.json", campaign.load_state(first))
    target = campaign.campaign_dir(second)
    target.mkdir(parents=True, exist_ok=True)
    (target / "campaign.json").write_text((campaign.campaign_dir(first) / "campaign.json").read_text(encoding="utf-8"), encoding="utf-8")


def test_a_state_file_is_still_refused_under_a_changed_politeness_limit(tmp_path):
    first = load_config(build(tmp_path))
    second = load_config(build(tmp_path, name="b.yaml", mutate=lambda d: d["measurement"].update(subnet_wait_max_seconds=600)))
    assert campaign.campaign_dir(second) != campaign.campaign_dir(first)
    _copy_state_into_the_directory_of(first, second)
    with pytest.raises(ValueError, match="different configuration"):
        campaign.load_state(second)


def test_a_state_file_is_still_refused_under_a_changed_operations_limit(tmp_path):
    first = load_config(build(tmp_path))
    second = load_config(build(tmp_path, name="b.yaml", operations={"min_free_mib": 9000}))
    assert campaign.campaign_dir(second) != campaign.campaign_dir(first)
    _copy_state_into_the_directory_of(first, second)
    with pytest.raises(ValueError, match="different configuration"):
        campaign.load_state(second)


def test_a_campaign_stopped_under_one_value_is_continued_under_another(tmp_path):
    first = load_config(build(tmp_path, stall=30))
    run_fn, calls = _fake_run(tmp_path, {})
    inner = run_fn

    def drain_after_first(c, **kw):
        out = inner(c, **kw)
        (campaign.campaign_dir(c) / "DRAIN").write_text("")
        return out
    result = campaign.run_campaign(first, run_fn=drain_after_first, log=lambda *_: None)
    assert result["stopped"]["reason"] == "drain" and [c[0] for c in calls] == [0]
    (campaign.campaign_dir(first) / "DRAIN").unlink()
    second = load_config(build(tmp_path, stall=0, name="b.yaml"))
    run_fn2, calls2 = _fake_run(tmp_path, {})
    again = campaign.run_campaign(second, run_fn=run_fn2, log=lambda *_: None)
    assert again["complete"] and [c[0] for c in calls2] == [1, 2]
    assert campaign.campaign_dir(first) == campaign.campaign_dir(second)


def test_a_decoupled_campaign_finished_under_one_value_has_nothing_left_under_another(tmp_path):
    sample = {"fraction": 0.0001, "seed": 4, "shards": 3}
    first = load_config(build(tmp_path, sample=sample, stall=30))
    cluster = Cluster(first)
    assert run_decoupled(first, cluster, tmp_path)["complete"]
    started = len(cluster.events)
    second = load_config(build(tmp_path, sample=sample, stall=2, name="b.yaml"))
    cluster2 = Cluster(second)
    result = run_decoupled(second, cluster2, tmp_path)
    assert result["complete"] and cluster2.events == [] and started > 0
    assert state_of(second)["config_checksum"] == first.checksum


def test_a_decoupled_campaign_with_a_stalled_stage_continues_under_another_value(tmp_path):
    sample = {"fraction": 0.0001, "seed": 4, "shards": 3}
    first = load_config(build(tmp_path, sample=sample, stall=1))
    cluster = Cluster(first, fail={("network", 1): [5]})
    run_decoupled(first, cluster, tmp_path, max_attempts=1)
    second = load_config(build(tmp_path, sample=sample, stall=600, name="b.yaml"))
    cluster2 = Cluster(second)
    result = run_decoupled(second, cluster2, tmp_path, retry_failed=True)
    assert result["complete"] and result["shards_complete"] == 3


# ------------------------------------------------------------------ shape of the table

def test_every_host_derived_section_is_a_section_of_the_config():
    assert set(HOST_DERIVED_KEYS) <= TOP_LEVEL


def test_the_table_holds_tuples_of_distinct_strings():
    for section, keys in HOST_DERIVED_KEYS.items():
        assert isinstance(section, str) and isinstance(keys, tuple) and keys
        assert all(isinstance(k, str) and k for k in keys)
        assert len(set(keys)) == len(keys)


def test_every_host_derived_key_is_a_key_the_loader_accepts(tmp_path):
    for (section, key), (value, _) in GOOD_VALUES.items():
        cfg = load_config(build(tmp_path, mutate=lambda d: d[section].update({key: value})))
        assert cfg.raw[section][key] == value


def test_no_host_derived_key_is_a_politeness_key_or_a_sample_key():
    forbidden = set(POLITENESS_KEYS) | {"zmap_rate", "ports", "fraction", "seed", "shards", "zmap_probes"}
    for keys in HOST_DERIVED_KEYS.values():
        assert not set(keys) & forbidden


def test_stall_minutes_appears_once_and_only_under_operations():
    pairs = [(s, k) for s, keys in HOST_DERIVED_KEYS.items() for k in keys if k == "stall_minutes"]
    assert pairs == [("operations", "stall_minutes")]


def test_the_only_operations_key_in_the_table_is_stall_minutes():
    """Every other operations key (kill switch, egress interval, disk limits) is part of the campaign identity."""
    assert HOST_DERIVED_KEYS["operations"] == ("stall_minutes",)


def test_stall_minutes_is_a_field_of_the_loaded_config():
    assert "stall_minutes" in {f.name for f in dataclasses.fields(ScanConfig)}


def test_the_table_is_exactly_what_the_checksum_function_strips(tmp_path):
    raw = base_raw(tmp_path)
    stripped = copy.deepcopy(raw)
    for section, keys in HOST_DERIVED_KEYS.items():
        for key in keys:
            stripped.setdefault(section, {})[key] = "x"
    stripped["ct_names"] = raw.get("ct_names", {"enabled": False})
    assert config_checksum(stripped) == config_checksum(raw)


# ------------------------------------------------------------------ the README

README = (ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").exists() else ""


def _sentences_with(text, *needles):
    parts = [p.strip() for p in text.replace("\n", " ").split(". ")]
    return [p for p in parts if all(n in p for n in needles)]


def test_the_readme_documents_the_stall_limit_and_its_default():
    hits = _sentences_with(README, "operations.stall_minutes")
    assert hits and any("default 30" in h and "0 = off" in h and "stalled" in h for h in hits)


def test_the_readme_names_the_stall_limit_as_an_operations_key_next_to_the_kill_switch():
    assert "`operations.kill_switch_file`" in README and "`operations.stall_minutes`" in README


def test_the_readme_no_longer_says_that_every_operations_edit_starts_a_new_campaign():
    claim = [s for s in _sentences_with(README, "starts a new campaign") if "operations" in s]
    assert not claim or any("stall_minutes" in s for s in claim)


def test_the_readme_still_says_the_other_operations_edits_start_a_new_campaign():
    assert any("including `operations`" in s or "operations" in s for s in _sentences_with(README, "starts a new campaign"))


def test_the_readme_lists_operations_among_the_sections_that_may_differ_between_hosts():
    assert "vantage, output, operations and binaries" in README


def test_the_readme_says_the_config_checksum_names_the_campaign_directory():
    assert "campaign-<checksum prefix>" in README
