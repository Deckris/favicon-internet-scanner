"""TLS during the ZMap sweep: the gate keeps every address's SYNs and handshakes at least the pause apart."""
from scanner.internet import overlap as ovl

HEADER = "real-time,time-elapsed,time-remaining,percent-complete,active-send-threads,sent-total,sent-last-one-sec\n"
ORDER = {f"10.0.0.{i}": i for i in range(1000)}            # ZMap's send position of each target
RATE = 10.0                                                # targets per second; the gate assumes up to RATE * SLACK
PACE, BATCH = 15.0, 20.0


class Clock:
    def __init__(self):
        self.t = 1000.0

    def now(self):
        return self.t


def setup(tmp_path, sweeps=2, probes=2):
    c = Clock()
    prog = ovl.ZmapProgress(probes, now=c.now)
    gate = ovl.OverlapGate(prog, ORDER, sweeps_total=sweeps, rate_targets=RATE, pace=PACE)
    return c, prog, gate


def status(path, *sent_totals, header=True):
    with open(path, "a", encoding="utf-8") as fh:
        if header:
            fh.write(HEADER)
        for s in sent_totals:
            fh.write(f"2026-10-28 10:00:00,1,1,1.0,1,{s},0\n")


def ok(gate, c, idx):
    return gate.allowed([f"10.0.0.{idx}"], c.t, BATCH)


def test_progress_reads_sent_total_in_targets_and_tolerates_partial_lines(tmp_path):
    c, prog, _ = setup(tmp_path)
    f = tmp_path / "s.csv"
    prog.start_sweep(f)
    status(f, 0, 40)
    with open(f, "a", encoding="utf-8") as fh:
        fh.write("2026-10-28 10:00:01,2,1,1.0,1,6")             # half a line: not read yet
    sweeps, _ = prog.snapshot()
    assert [p for _t, p in sweeps[0]["obs"]] == [0, 20]        # 40 packets, 2 probes each: 20 targets
    with open(f, "a", encoding="utf-8") as fh:
        fh.write("0,0\n")
    c.t += 1
    sweeps, _ = prog.snapshot()
    assert sweeps[0]["obs"][-1] == (c.t, 30)


def test_address_ahead_of_zmap_is_admitted_only_far_enough_ahead(tmp_path):
    c, prog, gate = setup(tmp_path, sweeps=1)
    prog.start_sweep(None)                                     # no status file: speed bound from the sweep start
    needed = (BATCH + PACE) * RATE * ovl.SLACK                 # positions ZMap could cover before the batch ends + pause
    assert not ok(gate, c, int(needed) - 5)
    assert ok(gate, c, int(needed) + 5)
    c.t += 10                                                  # ZMap may have moved 10 s * rate * slack further
    assert not ok(gate, c, int(needed) + 5)


def test_address_just_behind_zmap_waits_the_pause_and_the_next_sweep_is_respected(tmp_path):
    c, prog, gate = setup(tmp_path, sweeps=2)
    f = tmp_path / "s.csv"
    prog.start_sweep(f)
    status(f, 2 * 500)                                         # 500 targets sent by now
    assert not ok(gate, c, 499)                                # its SYN may be a moment old
    c.t += PACE
    assert ok(gate, c, 499)                                    # sent >= 15 s ago, next SYN is a whole sweep away
    # nearly at the end of sweep 1: address 0 is next in sweep 2 and may be reached within the batch + pause
    status(f, 2 * 990, header=False)
    prog.snapshot()
    c.t += PACE
    assert not ok(gate, c, 0)


def test_between_sweeps_the_next_sweep_may_start_at_once(tmp_path):
    c, prog, gate = setup(tmp_path, sweeps=2)
    prog.start_sweep(None)
    c.t += 100
    prog.end_sweep()
    c.t += PACE
    assert not ok(gate, c, 3)                                  # sweep 2 could reach position 3 within the batch
    assert ok(gate, c, 999)                                    # far down sweep 2's order


def test_after_the_last_sweep_everything_is_due_after_the_pause(tmp_path):
    c, prog, gate = setup(tmp_path, sweeps=1)
    prog.start_sweep(None)
    c.t += 100
    prog.end_sweep()
    prog.finish()
    assert not ok(gate, c, 3)
    c.t += PACE
    assert ok(gate, c, 3) and ok(gate, c, 999)


def test_unknown_addresses_wait_and_a_batch_needs_every_address(tmp_path):
    c, prog, gate = setup(tmp_path, sweeps=1)
    prog.start_sweep(None)
    assert not gate.allowed(["192.0.2.1"], c.t, BATCH)
    assert not gate.allowed(["10.0.0.999", "10.0.0.1"], c.t, BATCH)
    assert gate.admit(["10.0.0.999"], BATCH)(c.t)


def test_skipped_sweeps_after_a_stop_release_after_the_pause(tmp_path):
    c, prog, gate = setup(tmp_path, sweeps=3)
    prog.start_sweep(None)
    c.t += 50
    prog.end_sweep()
    prog.finish()                                              # kill switch: sweeps 2 and 3 never start
    c.t += PACE
    assert ok(gate, c, 0)
