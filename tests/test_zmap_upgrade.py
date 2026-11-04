"""Version-specific ZMap contracts: rate, CSV header and the frozen sample."""
from types import SimpleNamespace

import pytest
import yaml

from scanner.internet import pipeline, preflight
from scanner.internet.config import ConfigError, load_config
from scanner.internet.zmap_compat import packet_rate_args, version_number
from tests.helpers import FakeFetcher, write_config
from tests.test_pipeline import tools


def test_packet_rate_is_not_divided_twice_on_4_4():
    assert version_number("zmap v4.4.0") == "4.4.0"
    assert version_number("zmap 2.1.1") == "2.1.1"
    assert packet_rate_args("4.4.0", 1000, 2) == 1000
    assert packet_rate_args("2.1.1", 1000, 2) == 500
    with pytest.raises(ValueError, match="probes"):
        packet_rate_args("2.1.1", 1, 2)
    with pytest.raises(ValueError, match="unsupported"):
        packet_rate_args("4.3.3", 1000, 2)


def test_unknown_version_is_refused_in_config(tmp_path):
    path = write_config(tmp_path)
    raw = yaml.safe_load(path.read_text())
    raw["measurement"]["zmap_version"] = "4.3.3"
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ConfigError, match="zmap_version"):
        load_config(path)


def test_pinned_4_4_command_preserves_packet_ceiling_and_csv_contract(tmp_path):
    path = write_config(tmp_path)
    raw = yaml.safe_load(path.read_text())
    raw["measurement"].update(zmap_version="4.4.0")
    path.write_text(yaml.safe_dump(raw))
    cfg = load_config(path)
    ft = tools()
    pipeline.run(cfg, run_id="upgrade", executor=ft, fetcher=FakeFetcher(),
                 skip_preflight=True, offline_preflight=True)
    commands = [c for c in ft.commands if c[0] == "zmap" and "-p" in c]
    assert len(commands) == 1 + len(cfg.measurement.ports)
    for command in commands:
        assert command[command.index("-T") + 1] == "1"
        assert "--no-header-row" in command
        assert command[command.index("-C") + 1] == "/dev/null"
        if "--dryrun" not in command:
            assert command[command.index("-r") + 1] == str(cfg.measurement.zmap_rate)
            assert command[command.index("--batch") + 1] == "1"


def test_preflight_rejects_binary_that_disagrees_with_version_pin(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    monkeypatch.setattr(preflight.shutil, "which", lambda binary: "/usr/sbin/" + binary)
    monkeypatch.setattr(preflight, "_sha", lambda _path: "a" * 64)
    def executor(cmd, **kw):
        return SimpleNamespace(returncode=0, stdout="zmap 4.4.0" if "--version" in cmd else "", stderr="")
    report = preflight.run_preflight(cfg, pipeline.build_policy(cfg)[1], run_dir=tmp_path,
                                     executor=executor, offline=True)
    check = next(c for c in report["checks"] if c["name"] == "zmap_version_supported")
    assert check["status"] == "fail" and "configured" in check["detail"]


def _sweep_commands(tmp_path, version, ports):
    path = write_config(tmp_path)
    raw = yaml.safe_load(path.read_text())
    raw["measurement"].update(zmap_version=version)
    if ports is not None:
        raw["measurement"]["zmap_source_ports"] = ports
    path.write_text(yaml.safe_dump(raw))
    cfg = load_config(path)
    ft = tools()
    pipeline.run(cfg, run_id="srcport", executor=ft, fetcher=FakeFetcher(),
                 skip_preflight=True, offline_preflight=True)
    return [c for c in ft.commands if c[0] == "zmap" and "-p" in c and "--dryrun" not in c]


@pytest.mark.parametrize("version", ["2.1.1", "4.4.0"])
def test_source_port_range_reaches_the_zmap_command_only_when_set(tmp_path, version):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    with_range = _sweep_commands(tmp_path / "a", version, "1024-9999")
    assert with_range and all("--source-port=1024-9999" in c for c in with_range)
    without = _sweep_commands(tmp_path / "b", version, None)
    assert without and not any(a.startswith(("--source-port", "-s")) for c in without for a in c)


@pytest.mark.parametrize("value", ["9999-1024", "0-100", "1024-70000", "abc", "1-2-3", True, 1.5])
def test_bad_source_port_range_is_refused(tmp_path, value):
    path = write_config(tmp_path)
    raw = yaml.safe_load(path.read_text())
    raw["measurement"]["zmap_source_ports"] = value
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ConfigError, match="zmap_source_ports"):
        load_config(path)
