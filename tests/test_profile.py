"""Resource profile: concurrency derived from cores, RAM and open files, and overridden from the command line."""
import pytest
import yaml

from scanner.internet import pipeline
from scanner.internet import preflight as pre
from scanner.internet import profile as prof
from scanner.internet import settings as st
from scanner.internet.__main__ import main
from scanner.internet.config import load_config

GB = 2**30


def _in_range(plan):
    for name, (low, high) in prof.RANGES.items():
        assert low <= plan[name] <= high, name
    assert plan["favicon_processes"] <= plan["favicon_workers"]
    assert plan["favicon_processes"] <= plan["favicon_max_active_requests"]


@pytest.mark.parametrize("cores", [2, 4, 64, 1000])
def test_plan_stays_in_range_and_fits_for_any_core_count(cores):
    plan = prof.derive(cores, 4096, 1 << 20)
    _in_range(plan)
    assert prof.fits_open_files(plan, 1 << 20)
    assert plan["favicon_processes"] == min(cores, 64)


def test_two_cores_is_a_small_sequential_plan():
    plan = prof.derive(2, 8, 65536)
    assert plan["zgrab_parallel_batches"] == 1 and plan["favicon_processes"] == 2
    assert plan["overlap_tls_with_zmap"] is False
    assert plan["connection_budget"] == 2 * prof.PER_CORE_CONNECTIONS


def test_more_cores_give_more_concurrency_until_a_range_caps_it():
    small, mid, big = (prof.derive(c, 4096, 1 << 20) for c in (2, 8, 1000))
    assert small["zgrab_senders"] * small["zgrab_parallel_batches"] < mid["zgrab_senders"] * mid["zgrab_parallel_batches"]
    assert mid["overlap_tls_with_zmap"] is True
    assert big["zgrab_senders"] <= 1000 and big["zgrab_parallel_batches"] == prof.MAX_PARALLEL_BATCHES
    assert big["favicon_max_active_requests"] <= 8192 and big["dns_threads"] <= 1000


def test_low_memory_limits_the_connections():
    roomy = prof.derive(64, 256, 1 << 20)
    tight = prof.derive(64, 2, 1 << 20)
    assert tight["connection_budget"] == int(1 * GB / prof.PER_CONNECTION_BYTES)
    assert tight["connection_budget"] < roomy["connection_budget"]
    assert prof.file_demand(tight) <= tight["connection_budget"]
    _in_range(tight)


def test_unknown_memory_is_not_a_limit():
    assert prof.derive(4, None, 1 << 20)["connection_budget"] == 4 * prof.PER_CORE_CONNECTIONS


def test_low_open_file_limit_limits_the_connections():
    plan = prof.derive(64, 256, 1024)
    assert plan["connection_budget"] == int(prof.OPEN_FILE_FRACTION * 1024)
    assert prof.fits_open_files(plan, 1024)
    _in_range(plan)


def test_tiny_host_still_gets_a_valid_plan():
    _in_range(prof.derive(1, 0.5, 64))


def test_explicit_values_win_over_derived_ones():
    plan = prof.derive(2, 4, 4096, overrides={"zgrab_senders": 900, "zgrab_parallel_batches": 7, "dns_threads": 3,
                                              "favicon_processes": 1, "overlap_tls_with_zmap": True,
                                              "favicon_stage_max_seconds": 600})
    assert (plan["zgrab_senders"], plan["zgrab_parallel_batches"], plan["dns_threads"]) == (900, 7, 3)
    assert plan["favicon_processes"] == 1 and plan["overlap_tls_with_zmap"] is True and plan["favicon_stage_max_seconds"] == 600
    assert not prof.fits_open_files(plan, 4096)     # an override may exceed the host; preflight refuses it


def test_none_means_not_set():
    assert prof.derive(8, 16, 65536, overrides={"zgrab_senders": None}) == prof.derive(8, 16, 65536)


@pytest.mark.parametrize("name, value", [("zgrab_senders", 1001), ("zgrab_senders", 0), ("zgrab_parallel_batches", 65),
                                         ("zgrab_batch_size", 100_001), ("dns_threads", 1001), ("favicon_workers", 8193),
                                         ("favicon_processes", 65), ("favicon_max_active_requests", 0),
                                         ("favicon_stage_max_seconds", 86401), ("zgrab_senders", "many")])
def test_overrides_outside_the_validated_ranges_are_refused(name, value):
    with pytest.raises(ValueError, match=name):
        prof.derive(8, 16, 65536, overrides={name: value})


def test_offhost_icons_no_longer_limit_the_favicon_processes():
    assert prof.derive(16, 64, 65536, offhost_icons=True)["favicon_processes"] == 16


def test_detect_prefers_given_values():
    r = prof.detect(cores=6, memory_gb=12, open_files=5000)
    assert (r.cores, r.memory_gb, r.open_files) == (6, 12.0, 5000)


def test_meminfo_is_read_in_gib(tmp_path):
    f = tmp_path / "meminfo"
    f.write_text("MemTotal:       16777216 kB\nMemFree: 1 kB\n", encoding="ascii")
    assert prof.detect_memory_gb(f) == 16.0


GOOD = ["--contact", "optout@uni.example", "--info-url", "https://uni.example/scan", "--egress-ip", "93.184.216.34",
        "--interface", "eth0", "--resolver", "192.0.2.53"]


def _workdir(tmp, *extra):
    (tmp / "owner.txt").write_text("10.0.0.0/8\n", encoding="utf-8")
    assert main(["init", "--workdir", str(tmp), "--exclusions", str(tmp / "owner.txt"), *GOOD, *extra]) == 0
    path = tmp / "settings.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["approval"].update(status="approved", reference="A-1", valid_until="2999-01-01T00:00:00+00:00", data_handling="DH-1")
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def test_apply_writes_the_derived_values(tmp_path):
    _workdir(tmp_path, "--cores", "8", "--memory-gb", "32", "--max-open-files", "65536")
    result = st.apply(tmp_path)
    cfg = load_config(tmp_path / "config.yaml")
    expected = prof.derive(8, 32, 65536)
    assert result["derived_plan"] == expected
    assert cfg.measurement.zgrab_senders == expected["zgrab_senders"]
    assert cfg.measurement.zgrab_batch_size == expected["zgrab_batch_size"]
    assert cfg.dns.threads == expected["dns_threads"]
    assert cfg.favicon.processes == expected["favicon_processes"] == 8
    assert cfg.favicon.max_active_requests == expected["favicon_max_active_requests"]
    assert cfg.measurement.overlap_tls_with_zmap is True


def test_command_line_beats_settings_beats_derived(tmp_path):
    path = _workdir(tmp_path, "--cores", "8", "--memory-gb", "32", "--max-open-files", "65536", "--zgrab-senders", "123")
    assert st.apply(tmp_path)["derived_plan"]["zgrab_senders"] == 123
    assert main(["apply", "--workdir", str(tmp_path), "--zgrab-senders", "77", "--favicon-processes", "2",
                 "--overlap-tls-with-zmap", "false"]) == 0
    cfg = load_config(tmp_path / "config.yaml")
    assert cfg.measurement.zgrab_senders == 77 and cfg.favicon.processes == 2
    assert cfg.measurement.overlap_tls_with_zmap is False
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["scope"]["zgrab_senders"] == 123


def test_out_of_range_flag_is_refused_by_apply(tmp_path, capsys):
    _workdir(tmp_path, "--cores", "2", "--memory-gb", "4", "--max-open-files", "4096")
    assert main(["apply", "--workdir", str(tmp_path), "--zgrab-senders", "5000"]) == 2
    assert "zgrab_senders" in capsys.readouterr().err


def test_plan_shows_the_resource_plan(tmp_path, capsys):
    _workdir(tmp_path, "--cores", "4", "--memory-gb", "8", "--max-open-files", "65536")
    st.apply(tmp_path)
    capsys.readouterr()
    main(["plan", "--config", str(tmp_path / "config.yaml"), "--cores", "4", "--memory-gb", "8", "--max-open-files", "65536"])
    out = capsys.readouterr().out
    shown = yaml.safe_load(out[:out.index("\n\nNothing was sent")])["resource_plan"]
    assert shown["host"] == {"cores": 4, "memory_gb": 8.0, "max_open_files": 65536}
    assert shown["configured"]["zgrab_senders"] == prof.derive(4, 8, 65536)["zgrab_senders"]
    assert shown["fits_open_files"] is True


def test_kernel_limit_checks_read_proc_and_skip_when_absent(tmp_path):
    assert pre._kernel_limit_checks(1000, tmp_path) == []
    (tmp_path / "net/ipv4").mkdir(parents=True)
    (tmp_path / "net/netfilter").mkdir(parents=True)
    (tmp_path / "net/ipv4/ip_local_port_range").write_text("32768\t60999\n")
    (tmp_path / "net/netfilter/nf_conntrack_max").write_text("65536\n")
    (tmp_path / "net/netfilter/nf_conntrack_count").write_text("60000\n")
    ok = {c["name"]: c["status"] for c in pre._kernel_limit_checks(1000, tmp_path)}
    assert ok == {"ephemeral_ports": "pass", "conntrack_limit": "pass"}
    low = {c["name"]: c["status"] for c in pre._kernel_limit_checks(40000, tmp_path)}
    assert low == {"ephemeral_ports": "warn", "conntrack_limit": "warn"}


def test_preflight_fails_when_the_plan_cannot_fit_the_open_files(tmp_path):
    _workdir(tmp_path, "--cores", "8", "--memory-gb", "32", "--max-open-files", "65536")
    st.apply(tmp_path)
    cfg = load_config(tmp_path / "config.yaml")
    _, splan, _ = pipeline.build_policy(cfg)
    run_dir = tmp_path / "doctor"
    run_dir.mkdir()
    few = pre.run_preflight(cfg, splan, run_dir=run_dir, offline=True, resources=prof.Resources(8, 32.0, 1024))
    many = pre.run_preflight(cfg, splan, run_dir=run_dir, offline=True, resources=prof.Resources(8, 32.0, 1 << 20))

    def status(report):
        return {c["name"]: c["status"] for c in report["checks"]}["plan_fits_open_files"]
    assert status(few) == "fail" and status(many) == "pass"


# ------------------------------------------------------------------ the shape of the derived network plan

@pytest.mark.parametrize("cores, parallel, connections", [(2, 1, 500), (4, 2, 1000), (8, 4, 2000), (64, 32, 16000)])
def test_the_derived_zgrab_plan_has_the_intended_shape_on_2_4_8_and_64_cores(cores, parallel, connections):
    plan = prof.derive(cores, cores * 2.0, 1 << 20)
    assert plan["zgrab_senders"] == prof.SENDERS_PER_PROCESS == 500
    assert plan["zgrab_parallel_batches"] == parallel
    assert plan["zgrab_batch_size"] == 20000
    assert plan["zgrab_senders"] * plan["zgrab_parallel_batches"] == connections
    assert plan["overlap_tls_with_zmap"] is (cores >= prof.OVERLAP_MIN_CORES)
    _in_range(plan)


def test_the_eight_core_plan_is_what_the_plan_asked_for():
    plan = prof.derive(8, 16, 65536)
    assert (plan["zgrab_senders"], plan["zgrab_parallel_batches"], plan["zgrab_batch_size"]) == (500, 4, 20000)


def test_batches_are_large_relative_to_the_senders_whenever_the_budget_allows_it():
    for cores in (1, 2, 4, 8, 16, 64, 256):
        plan = prof.derive(cores, 4 * cores, 1 << 20)
        assert plan["zgrab_batch_size"] == plan["zgrab_senders"] * prof.BATCH_PER_SENDER
        assert plan["zgrab_batch_size"] >= 20 * plan["zgrab_senders"]


@pytest.mark.parametrize("cores", [1, 2, 4, 8, 16, 64])
@pytest.mark.parametrize("memory", [1, 4, 64, None])
@pytest.mark.parametrize("files", [1024, 4096, 65536, 1 << 20])
def test_processes_times_senders_never_exceed_the_open_file_budget(cores, memory, files):
    plan = prof.derive(cores, memory, files)
    assert plan["zgrab_senders"] * plan["zgrab_parallel_batches"] <= prof.OPEN_FILE_FRACTION * files
    assert prof.fits_open_files(plan, files)
    _in_range(plan)


def test_a_small_budget_gives_fewer_senders_not_a_larger_batch_per_sender():
    plan = prof.derive(1, 2, 400)
    assert plan["zgrab_senders"] < prof.SENDERS_PER_PROCESS
    assert plan["zgrab_batch_size"] == plan["zgrab_senders"] * prof.BATCH_PER_SENDER


def test_the_overlap_batch_never_exceeds_the_senders_and_the_sequential_one_is_the_configured_size():
    assert pipeline.overlap_batch_size(20000, 500) == 500
    assert pipeline.overlap_batch_size(100, 500) == 100
    assert pipeline.overlap_batch_size(1, 1) == 1


def test_the_tool_timeout_of_a_batch_covers_its_drain_and_stays_finite():
    from types import SimpleNamespace
    from scanner.internet.runner import ManagedExecutor
    m = SimpleNamespace(zgrab_senders=500, zgrab_target_timeout=8.0, zgrab_connect_timeout=4.0)
    holder = SimpleNamespace(cfg=SimpleNamespace(measurement=m))
    text = "".join(f"10.0.{i // 250}.{i % 250},,,443\n" for i in range(20000))
    limit = ManagedExecutor.timeout_for(holder, "zgrab2", ["zgrab2", "tls"], text)
    rounds = 20000 // 500
    assert limit >= rounds * (m.zgrab_connect_timeout + m.zgrab_target_timeout)       # every sender busy to the end of every round
    assert limit < 3600                                                                # a hung batch is killed within the hour


@pytest.mark.parametrize("kwargs", [{"cores": 0}, {"cores": -2}, {"memory_gb": 0}, {"memory_gb": -1.5}, {"open_files": 0},
                                    {"open_files": -1}, {"cores": "many"}, {"cores": True}, {"memory_gb": float("nan")}])
def test_detect_refuses_values_that_are_not_positive_numbers(kwargs):
    with pytest.raises(ValueError):
        prof.detect(**kwargs)


def test_settings_resources_that_are_not_positive_are_refused_by_apply(tmp_path):
    path = _workdir(tmp_path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    for bad in (0, -4, "lots", True):
        data["resources"] = {"cores": bad, "memory_gb": 8, "max_open_files": 65536}
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        with pytest.raises(st.SettingsError, match="cores"):
            st.apply(tmp_path)


def test_flags_that_are_not_positive_are_refused_by_the_parser(capsys):
    for flag, value in (("--cores", "0"), ("--memory-gb", "-1"), ("--max-open-files", "0")):
        with pytest.raises(SystemExit):
            main(["plan", "--config", "x.yaml", flag, value])
    assert "above zero" in capsys.readouterr().err


def test_apply_refuses_a_plan_that_exceeds_the_descriptor_budget(tmp_path):
    _workdir(tmp_path, "--cores", "8", "--memory-gb", "32", "--max-open-files", "65536")
    with pytest.raises(st.SettingsError, match="open descriptors"):
        st.apply(tmp_path, {"zgrab_senders": 1000, "zgrab_parallel_batches": 64, "max_open_files": 4096})


def test_cgroup_limits_lower_the_detected_resources(tmp_path):
    v2 = tmp_path / "v2"
    v2.mkdir()
    (v2 / "cpu.max").write_text("150000 100000\n")
    (v2 / "memory.max").write_text(str(4 * GB) + "\n")
    assert prof.cgroup_cpu_limit(v2) == 1.5 and prof.detect_cores(v2) <= 2
    assert prof.cgroup_memory_limit_gb(v2) == 4.0
    assert prof.detect_memory_gb(tmp_path / "no-meminfo", v2) == 4.0
    free = tmp_path / "free"
    free.mkdir()
    (free / "cpu.max").write_text("max 100000\n")
    (free / "memory.max").write_text("max\n")
    assert prof.cgroup_cpu_limit(free) is None and prof.cgroup_memory_limit_gb(free) is None
    v1 = tmp_path / "v1"
    (v1 / "cpu").mkdir(parents=True)
    (v1 / "memory").mkdir()
    (v1 / "cpu" / "cpu.cfs_quota_us").write_text("200000\n")
    (v1 / "cpu" / "cpu.cfs_period_us").write_text("100000\n")
    (v1 / "memory" / "memory.limit_in_bytes").write_text(str(2 * GB) + "\n")
    assert prof.cgroup_cpu_limit(v1) == 2.0 and prof.cgroup_memory_limit_gb(v1) == 2.0
    (v1 / "memory" / "memory.limit_in_bytes").write_text("9223372036854771712\n")
    (v1 / "cpu" / "cpu.cfs_quota_us").write_text("-1\n")
    assert prof.cgroup_cpu_limit(v1) is None and prof.cgroup_memory_limit_gb(v1) is None
    assert prof.cgroup_cpu_limit(tmp_path / "missing") is None
