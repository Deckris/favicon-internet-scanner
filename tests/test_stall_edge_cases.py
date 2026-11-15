"""A halt for another reason names the stages that were skipped before it."""
from tests.test_coordinator import make_cfg
from tests.test_coordinator_stall_skip import Sim, coordinator, go


def test_a_refusal_after_a_skipped_failure_lists_the_skipped_stage(tmp_path):
    cfg = make_cfg(tmp_path, shards=4)
    script = {("network", 0): 1, ("network", 3): coordinator.EXIT_REFUSED}
    out = go(cfg, Sim(cfg, script), tmp_path, skip_failed=True)
    assert out.stop["reason"] == "preflight_failed"
    assert out.stop["detail"].count("skipped failures:") == 1
    assert "network of shard 0" in out.stop["detail"]


def test_a_crash_halt_does_not_repeat_the_skipped_list(tmp_path):
    cfg = make_cfg(tmp_path, shards=3)
    out = go(cfg, Sim(cfg, {("network", 0): 1}), tmp_path, skip_failed=True)
    assert out.stop["reason"] == "crashed"
    assert "skipped failures:" not in out.stop["detail"]
