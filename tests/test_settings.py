"""settings.yaml -> config.yaml + approval.yaml, the exclusions command and the init command."""
from pathlib import Path

import pytest
import yaml

from scanner.internet import settings as st
from scanner.internet.__main__ import main
from scanner.internet.config import load_config

GOOD = ["--contact", "optout@uni.example", "--info-url", "https://uni.example/scan", "--egress-ip", "93.184.216.34",
        "--interface", "eth0", "--resolver", "192.0.2.53"]


def _init(tmp: Path, *extra: str) -> Path:
    (tmp / "owner.txt").write_text("# owner list\n10.0.0.0/8\n198.51.100.0/24\n", encoding="utf-8")
    assert main(["init", "--workdir", str(tmp), "--exclusions", str(tmp / "owner.txt"), *GOOD, *extra]) == 0
    return tmp / "settings.yaml"


def _approve(path: Path) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["approval"].update(status="approved", reference="APPR-1", valid_until="2999-01-01T00:00:00+00:00",
                            data_handling="DH-1: scanner host only, deleted after 90 days")
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def test_fresh_settings_need_attention(tmp_path, capsys):
    _init(tmp_path)
    assert main(["apply", "--workdir", str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "approval.reference" in err and "approval.valid_until" in err


def test_apply_generates_a_loadable_config_and_approval(tmp_path):
    path = _init(tmp_path, "--cores", "2", "--memory-gb", "4", "--max-open-files", "65536")
    _approve(path)
    assert main(["apply", "--workdir", str(tmp_path)]) == 0
    cfg = load_config(tmp_path / "config.yaml")
    assert cfg.transparency.contact == "optout@uni.example"
    assert cfg.measurement.min_seconds_between_probes_per_ip == 5
    assert cfg.measurement.zmap_probes == 1
    assert cfg.measurement.overlap_tls_with_zmap is False and cfg.measurement.zgrab_parallel_batches == 1
    first = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    assert main(["apply", "--workdir", str(tmp_path)]) == 0
    assert (tmp_path / "config.yaml").read_text(encoding="utf-8") == first


def test_rate_above_the_approved_cap_is_refused(tmp_path, capsys):
    path = _init(tmp_path)
    _approve(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["scope"]["rate_pps"] = 5000
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert main(["apply", "--workdir", str(tmp_path)]) == 2
    assert "approval.max_rate_pps" in capsys.readouterr().err


def test_bad_contact_and_bad_exclusions_are_explained(tmp_path, capsys):
    path = _init(tmp_path)
    _approve(path)
    text = path.read_text(encoding="utf-8").replace("optout@uni.example", "not-an-email")
    path.write_text(text, encoding="utf-8")
    assert main(["apply", "--workdir", str(tmp_path)]) == 2
    assert "e-mail" in capsys.readouterr().err
    path.write_text(text.replace("not-an-email", "optout@uni.example"), encoding="utf-8")
    (tmp_path / "exclusions.txt").write_text("10.0.0.0/8\nnonsense\n", encoding="utf-8")
    assert main(["apply", "--workdir", str(tmp_path)]) == 2
    assert "line 2" in capsys.readouterr().err


def test_exclusions_add_changes_the_checksum_everywhere(tmp_path):
    path = _init(tmp_path)
    _approve(path)
    main(["apply", "--workdir", str(tmp_path)])
    before = yaml.safe_load((tmp_path / "approval.yaml").read_text(encoding="utf-8"))["exclusions_checksum"]
    assert main(["exclusions", "--workdir", str(tmp_path), "--add", "203.0.113.0/24", "10.0.0.0/8"]) == 0
    assert (tmp_path / "exclusions.txt").read_text(encoding="utf-8").count("203.0.113.0/24") == 1
    assert main(["apply", "--workdir", str(tmp_path)]) == 0
    after = yaml.safe_load((tmp_path / "approval.yaml").read_text(encoding="utf-8"))["exclusions_checksum"]
    cfg = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert after != before and cfg["target_policy"]["exclusions_sha256"] == after
    load_config(tmp_path / "config.yaml")


def test_init_does_not_overwrite_without_force(tmp_path, capsys):
    _init(tmp_path)
    assert main(["init", "--workdir", str(tmp_path), *GOOD]) == 2
    assert "already exists" in capsys.readouterr().err
    assert main(["init", "--workdir", str(tmp_path), "--force", *GOOD]) == 0


def test_nic_check_when_no_nat_and_url_check_behind_nat(tmp_path):
    path = _init(tmp_path)
    _approve(path)
    assert st.apply(tmp_path)["egress_check"] == "nic"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["host"]["source_ip"] = "192.168.1.5"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert st.apply(tmp_path)["egress_check"] == "url"


def test_missing_settings_file_points_to_init(tmp_path):
    with pytest.raises(st.SettingsError, match="scanner init"):
        st.load_settings(tmp_path)


def _edit(path: Path, **changes) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    for dotted, value in changes.items():
        section, key = dotted.split(".")
        data[section][key] = value
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


@pytest.mark.parametrize("change, message", [
    ({"scope.min_seconds_between_probes_per_ip": 4}, "below the approved 5"),
    ({"approval.min_seconds_between_probes_per_ip": 4, "scope.min_seconds_between_probes_per_ip": 4}, "below the minimum of 5"),
    ({"host.public_ip": "10.1.2.3"}, "not a public address"),
    ({"scope.ports": ["80", "443"]}, "scope.ports must be a list of port numbers"),
    ({"approval.valid_until": "2020-01-01T00:00:00+00:00"}, "has passed"),
    ({"approval.valid_until": "next year"}, "ISO 8601"),
])
def test_unsafe_or_malformed_settings_are_refused(tmp_path, capsys, change, message):
    path = _init(tmp_path)
    _approve(path)
    _edit(path, **change)
    assert main(["apply", "--workdir", str(tmp_path)]) == 2
    assert message in capsys.readouterr().err


def test_the_approval_carries_the_pause_and_a_config_below_it_is_not_authorized(tmp_path):
    path = _init(tmp_path)
    _approve(path)
    assert main(["apply", "--workdir", str(tmp_path)]) == 0
    approval = yaml.safe_load((tmp_path / "approval.yaml").read_text(encoding="utf-8"))
    assert approval["min_seconds_between_probes_per_ip"] == 5
    config = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    config["measurement"]["min_seconds_between_probes_per_ip"] = 0
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    from scanner.internet.config import ConfigError
    with pytest.raises(ConfigError, match="below the approved 5"):
        load_config(tmp_path / "config.yaml")


def test_ipv6_lines_in_the_exclusion_list_are_ignored_not_fatal(tmp_path):
    path = _init(tmp_path)
    _approve(path)
    with (tmp_path / "exclusions.txt").open("a", encoding="utf-8") as f:
        f.write("2001:db8::/32\r\n192.0.2.0/25\r\n")
    assert main(["apply", "--workdir", str(tmp_path)]) == 0
    from scanner.internet import pipeline
    cfg = load_config(tmp_path / "config.yaml")
    pipeline.build_policy(cfg)


def test_sharding_a_partial_sample_is_refused_with_zmap_4_4_0(tmp_path):
    path = _init(tmp_path)
    _approve(path)
    assert main(["apply", "--workdir", str(tmp_path)]) == 0
    config = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    config["sample"]["shards"] = 2
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    from scanner.internet.config import ConfigError
    with pytest.raises(ConfigError, match="needs sample.fraction 1.0"):
        load_config(tmp_path / "config.yaml")


def test_settings_example_matches_what_init_writes(tmp_path):
    written = st.write_settings(tmp_path, {})
    example = Path(__file__).resolve().parent.parent / "run" / "settings.example.yaml"
    assert example.read_text(encoding="utf-8") == written.read_text(encoding="utf-8")


def test_shards_in_settings_reach_the_config(tmp_path):
    import yaml
    path = _init(tmp_path)
    _approve(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["scope"]["shards"] = 5
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    st.apply(tmp_path)
    assert yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))["sample"]["shards"] == 5


def _new_workdir(tmp: Path, *extra: str) -> Path:
    path = _init(tmp, "--cores", "4", "--memory-gb", "16", "--max-open-files", "65536", *extra)
    _approve(path)
    return path


def _set_scope(path: Path, **values) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["scope"].update(values)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _config(tmp: Path) -> dict:
    return yaml.safe_load((tmp / "config.yaml").read_text(encoding="utf-8"))


def test_absent_icon_keys_leave_the_config_as_before(tmp_path):
    _new_workdir(tmp_path)
    st.apply(tmp_path)
    favicon = _config(tmp_path)["favicon"]
    assert "icon_selection" not in favicon and "javascript" not in favicon
    cfg = load_config(tmp_path / "config.yaml")
    assert cfg.favicon.icon_selection == "first_image" and cfg.favicon.javascript.enabled is False


def test_old_settings_without_the_new_keys_apply_to_the_same_config(tmp_path):
    path = _new_workdir(tmp_path)
    st.apply(tmp_path)
    before = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    for key in ("icon_selection", "javascript", "max_connections_per_subnet"):
        data["scope"].pop(key, None)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert st.apply(tmp_path)["written"] == []
    assert (tmp_path / "config.yaml").read_text(encoding="utf-8") == before


def test_icon_selection_round_trips_and_is_checked(tmp_path, capsys):
    path = _new_workdir(tmp_path)
    _set_scope(path, icon_selection="browser_models")
    st.apply(tmp_path)
    assert load_config(tmp_path / "config.yaml").favicon.icon_selection == "browser_models"
    _set_scope(path, icon_selection="everything")
    assert main(["apply", "--workdir", str(tmp_path)]) == 2
    assert "icon_selection" in capsys.readouterr().err
    assert main(["apply", "--workdir", str(tmp_path), "--icon-selection", "first_image"]) == 0
    assert load_config(tmp_path / "config.yaml").favicon.icon_selection == "first_image"


def test_javascript_block_round_trips(tmp_path):
    path = _new_workdir(tmp_path)
    _set_scope(path, javascript={"enabled": True, "max_pages_per_shard": 50, "page_timeout_seconds": 12, "concurrency": 3, "wait_ms": 700})
    st.apply(tmp_path)
    js = load_config(tmp_path / "config.yaml").favicon.javascript
    assert (js.enabled, js.max_pages_per_shard, js.page_timeout_seconds, js.concurrency, js.wait_ms) == (True, 50, 12, 3, 700)


def test_javascript_concurrency_is_automatic_unless_given(tmp_path):
    path = _new_workdir(tmp_path)
    _set_scope(path, javascript={"enabled": True, "concurrency": "auto"})
    st.apply(tmp_path)
    assert "concurrency" not in _config(tmp_path)["favicon"]["javascript"]
    assert load_config(tmp_path / "config.yaml").favicon.javascript.concurrency is None
    assert main(["apply", "--workdir", str(tmp_path), "--javascript-concurrency", "2", "--javascript-wait-ms", "0"]) == 0
    js = load_config(tmp_path / "config.yaml").favicon.javascript
    assert js.enabled is True and js.concurrency == 2 and js.wait_ms == 0


@pytest.mark.parametrize("block", [
    {"enabled": "yes"}, {"enabled": True, "max_pages_per_shard": 0}, {"page_timeout_seconds": 500},
    {"concurrency": 65}, {"concurrency": "many"}, {"wait_ms": -1}, {"wait_ms": 1.5}, {"unknown": 1}, "on",
])
def test_invalid_javascript_settings_are_refused(tmp_path, block):
    path = _new_workdir(tmp_path)
    _set_scope(path, javascript=block)
    with pytest.raises(st.SettingsError, match="javascript"):
        st.apply(tmp_path)


def test_icon_flags_in_init_are_written_to_settings_and_applied(tmp_path):
    path = _new_workdir(tmp_path, "--icon-selection", "browser_models", "--javascript-enabled", "true",
                        "--javascript-concurrency", "2", "--max-connections-per-subnet", "3", "--offhost-icons", "true")
    scope = yaml.safe_load(path.read_text(encoding="utf-8"))["scope"]
    assert scope["icon_selection"] == "browser_models" and scope["max_connections_per_subnet"] == 3 and scope["offhost_icons"] is True
    assert scope["javascript"]["enabled"] is True and scope["javascript"]["concurrency"] == 2
    st.apply(tmp_path)
    cfg = load_config(tmp_path / "config.yaml")
    assert cfg.favicon.icon_selection == "browser_models" and cfg.favicon.javascript.enabled and cfg.favicon.javascript.concurrency == 2
    assert cfg.measurement.max_connections_per_subnet == 3 and cfg.favicon.offhost.enabled is True


def test_offhost_icons_work_with_several_favicon_processes(tmp_path):
    path = _new_workdir(tmp_path)
    _set_scope(path, offhost_icons=True, favicon_processes=4, favicon_workers=64)
    st.apply(tmp_path)
    cfg = load_config(tmp_path / "config.yaml")
    assert cfg.favicon.offhost.enabled and cfg.favicon.processes == 4
    assert "offhost_icon_fetch" in yaml.safe_load((tmp_path / "approval.yaml").read_text(encoding="utf-8"))["operations"]


def test_max_connections_per_subnet_round_trips_and_is_checked(tmp_path):
    path = _new_workdir(tmp_path)
    _set_scope(path, max_connections_per_subnet=2)
    st.apply(tmp_path)
    assert load_config(tmp_path / "config.yaml").measurement.max_connections_per_subnet == 2
    _set_scope(path, max_connections_per_subnet=65)
    with pytest.raises(st.SettingsError, match="max_connections_per_subnet"):
        st.apply(tmp_path)


def test_subnet_timing_settings_round_trip_and_are_checked(tmp_path):
    path = _new_workdir(tmp_path)
    st.apply(tmp_path)
    cfg = load_config(tmp_path / "config.yaml")
    assert cfg.measurement.retry_after_max_hold_seconds == 30 and cfg.measurement.subnet_wait_max_seconds == 120
    base = cfg.checksum
    _set_scope(path, retry_after_max_hold_seconds=10, subnet_wait_max_seconds=60)
    st.apply(tmp_path)
    cfg = load_config(tmp_path / "config.yaml")
    assert cfg.measurement.retry_after_max_hold_seconds == 10 and cfg.measurement.subnet_wait_max_seconds == 60
    assert cfg.checksum != base
    for key, bad in (("retry_after_max_hold_seconds", 901), ("retry_after_max_hold_seconds", -1), ("subnet_wait_max_seconds", 0),
                     ("subnet_wait_max_seconds", 3601), ("subnet_wait_max_seconds", "soon")):
        _set_scope(path, **{key: bad})
        with pytest.raises(st.SettingsError, match=key):
            st.apply(tmp_path)
        _set_scope(path, **{key: 30})


def test_subnet_timing_flags_in_init_are_written_to_settings(tmp_path):
    path = _new_workdir(tmp_path, "--retry-after-max-hold-seconds", "5", "--subnet-wait-max-seconds", "45")
    scope = yaml.safe_load(path.read_text(encoding="utf-8"))["scope"]
    assert scope["retry_after_max_hold_seconds"] == 5 and scope["subnet_wait_max_seconds"] == 45
    st.apply(tmp_path)
    m = load_config(tmp_path / "config.yaml").measurement
    assert m.retry_after_max_hold_seconds == 5 and m.subnet_wait_max_seconds == 45


def test_icon_settings_change_the_checksum_but_hardware_settings_do_not(tmp_path):
    path = _new_workdir(tmp_path)
    st.apply(tmp_path)
    base = load_config(tmp_path / "config.yaml").checksum
    _set_scope(path, icon_selection="browser_models")
    st.apply(tmp_path)
    selected = load_config(tmp_path / "config.yaml").checksum
    _set_scope(path, javascript={"enabled": True})
    st.apply(tmp_path)
    scripted = load_config(tmp_path / "config.yaml").checksum
    assert len({base, selected, scripted}) == 3
    _set_scope(path, javascript={"enabled": True}, favicon_workers=128)
    st.apply(tmp_path)
    assert load_config(tmp_path / "config.yaml").checksum == scripted


def test_plan_prints_the_icon_settings(tmp_path, capsys):
    path = _new_workdir(tmp_path)
    _set_scope(path, icon_selection="browser_models", javascript={"enabled": True})
    st.apply(tmp_path)
    capsys.readouterr()
    assert main(["plan", "--config", str(tmp_path / "config.yaml"), "--cores", "8", "--memory-gb", "32"]) == 0
    out = capsys.readouterr().out
    shown = yaml.safe_load(out[:out.index("\nNothing was sent")])["resource_plan"]["favicon_settings"]
    assert shown["icon_selection"] == "browser_models" and shown["javascript"]["enabled"] is True
    assert shown["javascript"]["concurrency"] == prof_js(8, 32) and shown["javascript"]["concurrency_from"] == "host"


def prof_js(cores, memory):
    from scanner.internet import profile
    return profile.javascript_concurrency(cores, memory)
