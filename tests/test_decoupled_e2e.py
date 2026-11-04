"""End-to-end simulation of ``campaign --decoupled`` with real processes.

The coordinator, its stage workers and the limiter daemon are real child processes. ZMap, ZGrab2 and ZDNS are executables
(``tests/e2e_decoupled_support``) that answer from the scripted fakes of ``tests.helpers`` and append every start, end and
contact to one shared log, so the properties below are read off what the processes did, not off what they report.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import yaml

from scanner.internet import pipeline, outputs, population as pop
from scanner.internet.config import load_config
from tests.e2e_decoupled_support import scenario
from tests.helpers import config_dict, write_approval, write_exclusions

pytestmark = pytest.mark.skipif(sys.platform == "win32" or not hasattr(os, "fork"), reason="needs POSIX processes, flock and Unix sockets")

ROOT = Path(__file__).resolve().parent.parent
SUPPORT = ROOT / "tests" / "e2e_decoupled_support"
PACE = float(os.environ.get("E2E_PACE", "1.0"))       # the approval and the config both name this pause
CAP = 4
SHARDS = scenario.SHARDS
STOP_GRACE = 120.0
TIME_FIELDS = ("time", "_at", "stamp", "elapsed", "seconds", "duration", "started", "finished", "run_id", "path", "dir", "pid", "host_ts")


# ----------------------------------------------------------------------------------------------- the simulated host

class Host:
    """One temporary host: fake tools, config, limiter daemon, and campaign processes started and killed on demand."""

    def __init__(self, label: str) -> None:
        self.root = Path(tempfile.mkdtemp(prefix=f"e2e-{label}-", dir="/tmp"))
        self.marker = f"e2e-{os.getpid()}-{label}-{time.time_ns()}"
        self.log = self.root / "events.log"
        self.log.touch()
        self.out = self.root / "out"
        self.kill_file = self.root / "KILL"
        self.overlay = self.root / "overlay.txt"
        self.overlay.write_text("# opt-outs\n", encoding="utf-8")
        os.utime(self.overlay, ns=(1_000_000_000, 1_000_000_000))
        self.socket = self.root / "lim.sock"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for tool in ("zmap", "zgrab2", "zdns"):
            exe = self.bin / tool
            exe.write_text(f"#!{sys.executable}\nimport sys\nsys.path[:0] = [{str(ROOT)!r}]\n"
                           f"from tests.e2e_decoupled_support.fake_tool import main\nmain({tool!r})\n", encoding="utf-8")
            exe.chmod(0o755)
        self.config = self._write_config()
        self.cfg = load_config(self.config)
        self.token = pipeline.confirm_token(self.cfg, pipeline.build_policy(self.cfg)[1])
        self.env = {**os.environ, "E2E_LOG": str(self.log), "E2E_RUN": self.marker, "PYTHONPATH": f"{SUPPORT}{os.pathsep}{ROOT}",
                    "E2E_ZMAP_SECONDS": "1.5", "E2E_CONNECT_SECONDS": "0.4", "SCANNER_BUILD_INFO": str(self.root / "BUILD_INFO")}
        self.coordinator: subprocess.Popen | None = None
        self.limiter: subprocess.Popen | None = None
        self.coordinator_out = self.root / "coordinator.out"

    def _write_config(self) -> Path:
        excl = write_exclusions(self.root)
        approval = write_approval(self.root, excl, min_seconds_between_probes_per_ip=PACE, max_sample_fraction=0.0001)
        allowed = pop.allowed_addresses(pop.population_cidrs(), [l.strip() for l in excl.read_text().splitlines() if l.strip() and not l.startswith("#")])
        total = len(scenario.all_ips())
        cfg = config_dict(self.root, excl, approval)
        cfg["sample"] = {"fraction": (total + 0.5) / allowed, "seed": 4, "shards": SHARDS}
        cfg["measurement"].update(min_seconds_between_probes_per_ip=PACE, max_connections_per_subnet=CAP, limiter_socket=str(self.socket),
                                  zmap_cooldown=1, zgrab_senders=10)
        cfg["target_policy"]["exclusions_overlay_file"] = str(self.overlay)
        cfg["vantage"]["egress_check"] = "off"
        cfg["binaries"] = {tool: str(self.bin / tool) for tool in ("zmap", "zgrab2", "zdns")}
        cfg["output"] = {"dir": str(self.out), "compact": False}
        cfg["operations"]["kill_switch_file"] = str(self.kill_file)
        cfg["favicon"].update(workers=2, processes=1)
        path = self.root / "scanner.yaml"
        path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        return path

    # -- processes
    def start_limiter(self) -> None:
        self.limiter = subprocess.Popen([sys.executable, "-m", "scanner.internet", "limiterd", "--config", str(self.config), "--startup-hold-seconds", "1"],
                                        cwd=ROOT, env=self.env, stdout=subprocess.DEVNULL, stderr=(self.root / "limiter.err").open("ab"))
        wait_for(lambda: self.socket.exists(), 20, "the limiter socket")
        time.sleep(1.5)

    def start_campaign(self) -> subprocess.Popen:
        self.coordinator = subprocess.Popen(
            [sys.executable, "-m", "scanner.internet", "campaign", "--config", str(self.config), "--confirm", self.token, "--decoupled",
             "--network-workers", "2", "--favicon-workers", "2"],
            cwd=ROOT, env=self.env, stdout=self.coordinator_out.open("ab"), stderr=subprocess.STDOUT)
        return self.coordinator

    def finish(self, timeout: float = 600.0) -> int:
        try:
            return self.coordinator.wait(timeout)
        except subprocess.TimeoutExpired:
            pytest.fail(f"the campaign did not end within {timeout:.0f} s\n{self.tail()}")

    def tail(self) -> str:
        try:
            return self.coordinator_out.read_text(errors="replace")[-3000:]
        except OSError:
            return ""

    def members(self) -> list[int]:
        """Every live campaign process of this host, the limiter daemon excepted (they carry the marker in their environment)."""
        found = []
        for p in Path("/proc").iterdir():
            if p.name.isdigit() and int(p.name) not in (os.getpid(), self.limiter.pid if self.limiter else 0):
                try:
                    if self.marker.encode() in (p / "environ").read_bytes():
                        state = (p / "stat").read_text().rsplit(")", 1)[1].split()[0]
                        if state != "Z":
                            found.append(int(p.name))
                except OSError:
                    continue
        return found

    def stage_workers(self) -> dict[int, str]:
        out = {}
        for pid in self.members():
            try:
                parts = (Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0")
            except OSError:
                continue
            if b"stage-worker" in parts:
                out[pid] = parts[parts.index(b"--stage") + 1].decode()
        return out

    def teardown(self) -> None:
        for proc in (self.coordinator, self.limiter):
            if proc is not None and proc.poll() is None:
                proc.kill()
        for pid in self.members():
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        shutil.rmtree(self.root, ignore_errors=True)

    # -- reading what happened
    def events(self) -> list[list[str]]:
        return [l.split() for l in self.log.read_text().splitlines() if l.strip()]

    def state(self) -> dict:
        p = Path(self.cfg.output_dir) / f"campaign-{self.cfg.checksum[:12]}" / "campaign.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}

    def run_dirs(self) -> list[Path]:
        return sorted(p for p in self.out.glob("scanner-*-s*of*") if p.is_dir())


def wait_for(cond, timeout: float, what: str, poll: float = 0.1):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        got = cond()
        if got:
            return got
        time.sleep(poll)
    pytest.fail(f"timed out after {timeout:.0f} s waiting for {what}")


def make_host(label: str, request) -> Host:
    host = Host(label)
    request.addfinalizer(host.teardown)
    host.start_limiter()
    return host


# ----------------------------------------------------------------------------------------------- reading the log

def sweeps(events) -> list[dict]:
    """Every fake ZMap sweep as {pid, port, out, start, end|None, stage}."""
    by_pid: dict[tuple[str, str], dict] = {}
    for e in events:
        if e[0] == "ZMAP_START":
            by_pid[(e[1], e[4])] = {"pid": e[1], "port": int(e[3]), "out": e[4], "start": float(e[2]), "end": None, "stage": e[5], "rc": None}
        elif e[0] == "ZMAP_END":
            rec = by_pid.get((e[1], e[4]))
            if rec:
                rec["end"], rec["rc"] = float(e[2]), int(e[5])
    return sorted(by_pid.values(), key=lambda r: r["start"])


def contacts(events) -> list[dict]:
    """Every connection a fake ZGrab2 or the fake fetcher made: ip, start, end (a connection cut off by a kill ends at start + hold)."""
    open_: dict[tuple[str, str, str, str], dict] = {}
    done = []
    for e in events:
        if e[0] == "CONNECT_START":
            open_[(e[1], e[2], e[3], e[5])] = {"ip": e[1], "port": e[2], "start": float(e[4]), "end": None, "stage": e[5]}
        elif e[0] == "CONNECT_END":
            rec = open_.pop((e[1], e[2], e[3], e[5]), None)
            if rec:
                rec["end"] = float(e[4])
                done.append(rec)
    for rec in open_.values():
        rec["end"] = rec["start"] + 0.4
        done.append(rec)
    return sorted(done, key=lambda r: r["start"])


def assert_one_zmap_at_a_time(events) -> None:
    assert not [e for e in events if e[0] == "ZMAP_OVERLAP"], "a ZMap sweep started while another one was alive"
    swept = sweeps(events)
    assert swept, "no sweep ran"
    assert {s["stage"] for s in swept} == {"zmap"}, "a ZMap sweep was sent by a worker that is not the ZMap worker"
    for a, b in zip(swept, swept[1:]):
        assert a["end"] is not None and a["end"] <= b["start"] + 1e-3 or a["end"] is None and a["rc"] is None, \
            f"sweeps overlap: {a} then {b}"
    ends = [s for s in swept if s["end"] is not None]
    for i, a in enumerate(ends):
        for b in ends[i + 1:]:
            assert a["end"] <= b["start"] or b["end"] <= a["start"], f"sweeps overlap: {a} and {b}"


def assert_polite(events, *, pace: float = PACE, cap: int = CAP, slack: float = 0.25) -> dict:
    cs = contacts(events)
    assert cs, "nothing was contacted"
    by_ip: dict[str, list[dict]] = {}
    for c in cs:
        by_ip.setdefault(c["ip"], []).append(c)
    closest = min((b["start"] - a["start"] for v in by_ip.values() for a, b in zip(v, v[1:])), default=float("inf"))
    for ip, v in by_ip.items():
        for a, b in zip(v, v[1:]):
            assert b["start"] - a["start"] >= pace - slack, f"{ip} contacted twice within {pace} s: {a} then {b}"
    peak = 0
    edges = sorted([(c["start"], 1) for c in cs] + [(c["end"], -1) for c in cs], key=lambda x: (x[0], x[1]))
    # per /24: the same sweep over the contacts of that network
    nets: dict[str, list[tuple[float, int]]] = {}
    for c in cs:
        net = c["ip"].rsplit(".", 1)[0]
        nets.setdefault(net, []).extend([(c["start"], 1), (c["end"], -1)])
    for net, ev in nets.items():
        level = 0
        for _, d in sorted(ev, key=lambda x: (x[0], x[1])):
            level += d
            peak = max(peak, level)
    assert peak <= cap, f"{peak} simultaneous connections to one /24 (cap {cap})"
    return {"contacts": len(cs), "peak_per_24": peak, "closest_gap": closest}


# ----------------------------------------------------------------------------------------------- outputs

def _norm(value):
    if isinstance(value, dict):
        return {k: _norm(v) for k, v in sorted(value.items()) if not any(t in k.lower() for t in TIME_FIELDS)}
    if isinstance(value, list):
        return [_norm(v) for v in value]
    return value


def normalized_outputs(host: Host) -> dict:
    """The data of every shard (hostname and endpoint rows, favicon records) without time, path or process fields."""
    out = {}
    for run_dir in host.run_dirs():
        shard = run_dir.name.rsplit("-", 1)[1]
        rows = sorted(json.dumps(_norm(r), sort_keys=True) for r in outputs.iter_hostname_rows(run_dir))
        eps = sorted(json.dumps(_norm(r), sort_keys=True) for r in outputs.iter_endpoint_rows(run_dir))
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        out[shard] = {"hostname_rows": rows, "endpoint_rows": eps, "complete": manifest.get("complete"),
                      "summary": _norm(manifest.get("summary", {}))}
    return out


def assert_complete(host: Host, rc: int) -> None:
    assert rc == 0, f"the campaign ended with {rc}\n{host.tail()}"
    state = host.state()
    shards = state["shard_states"]
    assert len(shards) == SHARDS
    for i in range(SHARDS):
        entry = shards[str(i)]
        assert entry["status"] == "complete", (i, entry)
        assert all(s["status"] == "done" for s in entry["stages"].values()), (i, entry["stages"])
    dirs = host.run_dirs()
    assert len(dirs) == SHARDS, [d.name for d in dirs]
    for d in dirs:
        manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["complete"] is True and manifest.get("status") == "finished", (d.name, manifest.get("status"))
        rows = list(outputs.iter_hostname_rows(d))
        assert rows, f"{d.name} has no hostname rows"
        assert (d / "scanned_ips.txt").is_file()


# ----------------------------------------------------------------------------------------------- tests

@pytest.fixture(scope="module")
def clean(request):
    """One uninterrupted campaign; the reference for the other runs and the subject of the first three properties."""
    host = make_host("clean", request)
    started = time.monotonic()
    host.start_campaign()
    rc = host.finish()
    host.elapsed = time.monotonic() - started
    host.rc = rc
    return host


def test_clean_run_completes_every_shard(clean):
    assert_complete(clean, clean.rc)
    stats = clean.state()["shard_states"]
    assert [stats[str(i)]["stages"]["zmap"]["attempts"] for i in range(SHARDS)] == [0] * SHARDS      # nothing was retried
    ends = [s for s in sweeps(clean.events()) if s["end"] is not None]
    assert len(ends) == SHARDS * 3        # the three configured ports of every shard


def test_clean_run_never_runs_two_zmaps_at_once(clean):
    assert_one_zmap_at_a_time(clean.events())


def test_clean_run_keeps_the_subnet_cap_and_the_pause(clean):
    report = assert_polite(clean.events())
    print("politeness:", report, "elapsed", round(clean.elapsed, 1))
    # the stages really did overlap: network and favicon contacts of different shards happened side by side
    stages = {c["stage"] for c in contacts(clean.events())}
    assert {"network", "favicon"} <= stages, stages


def wait_for_zmap_start(host: Host, n: int) -> None:
    wait_for(lambda: len([e for e in host.events() if e[0] == "ZMAP_START"]) >= n, 120, f"sweep number {n}")


def alive_workers(host: Host, stage: str) -> list[int]:
    return [pid for pid, s in host.stage_workers().items() if s == stage]


def test_crash_of_coordinator_and_worker_resumes_to_the_same_outputs(request, clean):
    host = make_host("crash", request)
    host.start_campaign()
    # kill -9 the coordinator while a later sweep is on the wire and a network stage is running
    wait_for(lambda: any(c["stage"] == "network" for c in contacts(host.events())) and
             len([e for e in host.events() if e[0] == "ZMAP_START"]) >= 3, 180, "a network contact and the third sweep")
    host.coordinator.send_signal(signal.SIGKILL)
    host.coordinator.wait()
    wait_for(lambda: not host.members(), 60, "the stage workers to follow the coordinator")
    before = host.state()
    assert any(s["status"] == "running" for e in before["shard_states"].values() for s in e["stages"].values()), "nothing was running at the kill"
    # restart; kill -9 one stage worker once it has contacted something
    host.start_campaign()
    mark = len(host.events())
    victim = wait_for(lambda: (alive_workers(host, "network") or [None])[0], 120, "a network worker")
    wait_for(lambda: any(e[0] == "CONNECT_START" and e[5] == "network" for e in host.events()[mark:]), 120, "its first contact")
    os.kill(victim, signal.SIGKILL)
    rc = host.finish()
    assert_complete(host, rc)
    events = host.events()
    assert_one_zmap_at_a_time(events)
    # no sweep that finished was sent a second time
    done = [s["out"] for s in sweeps(events) if s["end"] is not None]
    assert len(done) == len(set(done)), f"a finished sweep was sent again: {sorted(x for x in done if done.count(x) > 1)}"
    assert len(set(done)) == SHARDS * 3
    assert normalized_outputs(host) == normalized_outputs(clean)
    assert_polite(events)


def test_kill_switch_stops_everything_and_a_restart_resumes(request, clean):
    host = make_host("kill", request)
    host.start_campaign()
    wait_for(lambda: any(c["stage"] == "network" for c in contacts(host.events())), 180, "a network contact")
    t0 = time.monotonic()
    host.kill_file.write_text("stop\n", encoding="utf-8")
    rc = host.coordinator.wait(STOP_GRACE + 30)
    took = time.monotonic() - t0
    print("kill switch: coordinator ended after", round(took, 1), "s with", rc)
    assert took <= STOP_GRACE, f"stopping took {took:.0f} s"
    assert rc != 0
    assert not host.members(), "processes are left behind after the stop"
    after = len(host.events())
    time.sleep(3)
    assert len(host.events()) == after, "something kept working after the stop"
    state = host.state()
    assert not any(s["status"] == "running" for e in state["shard_states"].values() for s in e["stages"].values())
    assert not all(e["status"] == "complete" for e in state["shard_states"].values())
    host.kill_file.unlink()
    host.start_campaign()
    rc = host.finish()
    assert_complete(host, rc)
    events = host.events()
    assert_one_zmap_at_a_time(events)
    assert normalized_outputs(host) == normalized_outputs(clean)
    assert_polite(events)


def test_opt_out_added_mid_run_is_never_contacted_afterwards(request):
    host = make_host("optout", request)
    swept_early = scenario.shard_ips(2)[1]       # its sweep is done (or running) when the opt-out arrives
    not_yet = scenario.shard_ips(SHARDS - 1)[1]   # its shard has not started
    host.start_campaign()
    wait_for(lambda: len([e for e in host.events() if e[0] == "ZMAP_END"]) >= 5, 180, "the third shard's sweep")
    stamp = time.monotonic()
    st = host.overlay.stat().st_mtime_ns
    host.overlay.write_text(f"# opt-outs\n{swept_early}\n{not_yet}\n", encoding="utf-8")
    os.utime(host.overlay, ns=(st + 5_000_000_000, st + 5_000_000_000))
    rc = host.finish()
    events = host.events()
    margin = 3.0       # a batch already handed to ZGrab2 when the file was read may still be on the wire
    late = [c for c in contacts(events) if c["ip"] in (swept_early, not_yet) and c["start"] > stamp + margin]
    assert not late, f"contacted after the opt-out was loaded: {late}"
    assert not [c for c in contacts(events) if c["ip"] == not_yet], "an address of a shard that had not started was contacted"
    others = [c for c in contacts(events) if c["start"] > stamp + margin]
    assert others, "nothing else was contacted after the opt-out (the test did not exercise the overlay)"
    print("opt-out: contacts of the opted-out address before the file changed:",
          len([c for c in contacts(events) if c["ip"] == swept_early]), "campaign rc", rc)
