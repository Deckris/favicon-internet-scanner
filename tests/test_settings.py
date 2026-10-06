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
    path = _init(tmp_path)
    _approve(path)
    assert main(["apply", "--workdir", str(tmp_path)]) == 0
    cfg = load_config(tmp_path / "config.yaml")
    assert cfg.transparency.contact == "optout@uni.example"
    assert cfg.measurement.min_seconds_between_probes_per_ip == 15
    assert cfg.measurement.zmap_probes == 1
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
