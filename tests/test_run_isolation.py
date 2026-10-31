"""A run ends with a manifest whatever fails between and after its stages; a signal handler takes no lock."""
import json
import os
import signal
import threading
import time
from types import SimpleNamespace

from scanner.internet import icon_store, pipeline
from scanner.internet.shardstore import ShardStore
from tests.helpers import FakeFetcher
from tests.test_pipeline import go, overlap_cfg, tools
from tests.test_stop_monitor import _stages, posix_only


def manifest_of(run_dir):
    return json.loads((run_dir / "manifest.json").read_text())


def boom(*_a, **_k):
    raise RuntimeError("store unreadable")


def test_a_failing_store_read_between_stages_is_recorded_and_the_manifest_written(tmp_path, monkeypatch):
    cfg = overlap_cfg(tmp_path, on=False)
    monkeypatch.setattr(ShardStore, "count_endpoints_by_port", boom)
    monkeypatch.setattr(ShardStore, "count_unique_ips", boom)
    m = manifest_of(go(cfg, tools()))
    assert "RuntimeError" in m["stage_errors"]["store:count_endpoints_by_port"] and "store:count_unique_ips" in m["stage_errors"]
    assert m["complete"] is False and m["status"] == "finished"
    assert m["stage_counts"]["l4_endpoints"] == 5 and m["stage_counts"]["l4_per_port"] == {"80": 0, "443": 0, "8080": 0}


def test_count_tls_failing_in_the_zmap_block_does_not_strand_the_overlap_thread(tmp_path, monkeypatch):
    cfg = overlap_cfg(tmp_path)
    monkeypatch.setattr(ShardStore, "count_tls", boom)
    done = {}

    def work():
        done["dir"] = go(cfg, tools())
    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(60)
    assert not t.is_alive(), "the overlap thread was never told to finish"
    m = manifest_of(done["dir"])
    assert "store:count_tls" in m["stage_errors"] and not m["complete"]
    assert not [th for th in threading.enumerate() if th.name == "tls-overlap"]


def test_unreadable_tarpit_list_stops_the_tls_stage_rather_than_probing_everything(tmp_path, monkeypatch):
    cfg = overlap_cfg(tmp_path, on=False)
    monkeypatch.setattr(ShardStore, "tarpit_ips", boom)
    ft = tools()
    m = manifest_of(go(cfg, ft))
    assert "store:tarpit_ips" in m["stage_errors"] and "tls_direct" in m["stages_skipped"]
    assert ft.zgrab_ips == []                          # nothing was handshaken without knowing the tarpits


def test_a_store_that_cannot_be_created_still_leaves_a_manifest(tmp_path, monkeypatch):
    cfg = overlap_cfg(tmp_path, on=False)

    def broken(*_a, **_k):
        raise OSError("disk full")
    monkeypatch.setattr(pipeline, "ShardStore", broken)
    m = manifest_of(go(cfg, tools()))
    assert "disk full" in m["stage_errors"]["store"] and m["complete"] is False and m["status"] == "finished"


def test_favicon_cleanup_steps_fail_separately_and_keep_the_original_error(tmp_path, monkeypatch):
    cfg = overlap_cfg(tmp_path, on=False)
    saved = []

    def stage_fails(*_a, **_k):
        raise ValueError("fetch layer broke")

    def index_fails(self, *_a, **_k):
        raise OSError("index disk error")
    monkeypatch.setattr(pipeline.fav, "run_favicon_stage", stage_fails)
    monkeypatch.setattr(icon_store.IconStore, "write_index", index_fails)
    fetcher = FakeFetcher()
    fetcher.offhost = SimpleNamespace(save_state=lambda: saved.append(1), log=[
        {"cached": False, "outcome": "ok"}, {"cached": False, "outcome": "policy_refused"}])
    m = manifest_of(go(cfg, tools(), fetcher=fetcher))
    errors = m["stage_errors"]
    assert "fetch layer broke" in errors["favicon"]            # not replaced by the cleanup failure
    assert "index disk error" in errors["favicon_icon_index"]
    assert saved == [1]                                        # still reached
    assert m["stage_counts"]["offhost_icon_logged"] == 2 and m["stage_counts"]["offhost_icon_refused"] == 1


def test_a_failing_offhost_state_save_does_not_skip_the_offhost_counts(tmp_path):
    cfg = overlap_cfg(tmp_path, on=False)

    def save():
        raise OSError("read-only")
    fetcher = FakeFetcher()
    fetcher.offhost = SimpleNamespace(save_state=save, log=[{"cached": False, "outcome": "ok"}])
    m = manifest_of(go(cfg, tools(), fetcher=fetcher))
    assert "read-only" in m["stage_errors"]["favicon_offhost_state"]
    assert m["stage_counts"]["offhost_icon_requests"] == 1


def test_rows_the_store_lost_are_counted_in_the_manifest(tmp_path, monkeypatch):
    cfg = overlap_cfg(tmp_path, on=False)
    real_close = ShardStore.close

    def lossy_close(self):
        if not self._closed:
            self.dropped_rows += 3
            self.errors.append("OperationalError: database or disk is full")
        real_close(self)
    monkeypatch.setattr(ShardStore, "close", lossy_close)
    m = manifest_of(go(cfg, tools()))
    assert m["stage_counts"]["store_dropped_rows"] == 3
    assert "database or disk is full" in m["stage_errors"]["store"] and m["complete"] is False


def test_favicon_records_that_missed_the_resume_log_are_counted(tmp_path, monkeypatch):
    cfg = overlap_cfg(tmp_path, on=False)

    def refused(self, rec):
        self.dropped += 1
    monkeypatch.setattr(pipeline.fav.RecordLog, "append", refused)
    m = manifest_of(go(cfg, tools()))
    assert m["stage_counts"]["favicon_records_dropped"] > 0
    assert "favicon_records" in m["stage_errors"]


@posix_only
def test_a_signal_landing_while_the_event_lock_is_held_cannot_deadlock(tmp_path):
    cfg, st = _stages(tmp_path)
    restore = pipeline._install_signal_handlers(lambda: st.flag_stop("interrupt"))
    result = {}

    def hold_the_lock():
        try:
            with st.stop._cond:                    # the lock Event.set() takes; the handler runs inside this block
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(2)
        except KeyboardInterrupt:
            result["raised"] = True
    try:
        hold_the_lock()
    finally:
        restore()
    assert result.get("raised") and st.pending == "interrupt" and not st.stop.is_set()
    assert st.killed() and st.stop.is_set() and st.reason == "interrupt"      # promoted outside the handler


def test_the_monitor_promotes_a_flagged_stop_to_the_event(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "MONITOR_TICK", 0.05)
    cfg, st = _stages(tmp_path)
    st.start_monitor()
    try:
        st.flag_stop("interrupt")
        assert st.stop.wait(2) and st.reason == "interrupt"
    finally:
        st.stop_monitor()


def test_guard_records_a_failure_and_returns_the_default(tmp_path):
    cfg, st = _stages(tmp_path)
    assert st.guard("step", boom, 7) == 7
    assert "store unreadable" in st.errors["step"]
    assert st.guard("fine", lambda: 3, 0) == 3 and "fine" not in st.errors
