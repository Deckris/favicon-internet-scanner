"""Responsible-use gates: anonymous traffic and unpiloted large samples are refused unless accepted on purpose."""
import json
from pathlib import Path
from types import SimpleNamespace

import yaml

from scanner.internet import pipeline
from scanner.internet.__main__ import PILOT_MAX_TARGETS_PER_PORT, _anonymous_refusal, _pilot_refusal, main
from scanner.internet.config import load_config
from tests.helpers import config_dict, write_approval, write_exclusions


def _config(tmp: Path, *, anonymous: bool, fraction: float = 0.0001) -> Path:
    excl = write_exclusions(tmp)
    approval = write_approval(tmp, excl, **({"transparency_url": "none", "opt_out_contact": "none"} if anonymous else {}))
    raw = config_dict(tmp, excl, approval)
    raw["sample"]["fraction"] = fraction
    if anonymous:
        raw["fetch"] = {**raw["fetch"], "user_agent": "research-scan (academic measurement; no contact published)"}
        raw["transparency"] = {"info_url": "none", "contact": "none", "anonymous": True}
    p = tmp / "scanner.yaml"
    p.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return p


def _token(cfg_path: Path) -> str:
    cfg = load_config(cfg_path)
    _, splan, _ = pipeline.build_policy(cfg)
    return pipeline.confirm_token(cfg, splan)


def test_run_without_contact_is_refused(tmp_path, capsys):
    p = _config(tmp_path, anonymous=True)
    assert main(["run", "--config", str(p), "--confirm", _token(p)]) == 2
    err = capsys.readouterr().err
    assert "contact" in err and "info_url" in err
    assert _anonymous_refusal(load_config(p), SimpleNamespace())


def test_identifiable_config_is_not_refused_for_identity(tmp_path):
    cfg = load_config(_config(tmp_path, anonymous=False))
    assert _anonymous_refusal(cfg, SimpleNamespace()) is None


def test_large_sample_without_a_pilot_is_refused(tmp_path, capsys):
    p = _config(tmp_path, anonymous=False, fraction=0.0001)
    assert main(["run", "--config", str(p), "--confirm", _token(p)]) == 2
    assert "pilot" in capsys.readouterr().err


def _splan(per_port):
    return SimpleNamespace(targets_per_port=per_port)


def test_pilot_gate_accepts_a_completed_small_run_and_ignores_incomplete_or_large_ones(tmp_path):
    cfg = load_config(_config(tmp_path, anonymous=False))
    args = SimpleNamespace(skip_pilot_check=False)
    out = Path(cfg.output_dir)

    def manifest(name, **fields):
        (out / name).mkdir(parents=True, exist_ok=True)
        (out / name / "manifest.json").write_text(json.dumps(fields), encoding="utf-8")

    big = PILOT_MAX_TARGETS_PER_PORT * 50
    assert _pilot_refusal(cfg, _splan(big), args)
    manifest("incomplete", complete=False, sample={"targets_per_port": 370})
    manifest("too-large", complete=True, sample={"targets_per_port": big})
    assert _pilot_refusal(cfg, _splan(big), args)
    manifest("pilot", complete=True, sample={"targets_per_port": 370})
    assert _pilot_refusal(cfg, _splan(big), args) is None


def test_small_samples_and_the_explicit_skip_need_no_pilot(tmp_path):
    cfg = load_config(_config(tmp_path, anonymous=False))
    assert _pilot_refusal(cfg, _splan(PILOT_MAX_TARGETS_PER_PORT), SimpleNamespace(skip_pilot_check=False)) is None
    assert _pilot_refusal(cfg, _splan(10**6), SimpleNamespace(skip_pilot_check=True)) is None


def test_shipped_examples_default_to_the_conservative_settings():
    root = Path(__file__).resolve().parents[1] / "run"
    config = yaml.safe_load((root / "config.example.yaml").read_text(encoding="utf-8"))
    approval = yaml.safe_load((root / "approval.example.yaml").read_text(encoding="utf-8"))
    assert config["favicon"]["offhost_icons"]["enabled"] is False
    assert "offhost_icon_fetch" not in approval["operations"]
    assert config["measurement"]["zmap_rate"] <= 100 and approval["max_rate_per_second"] <= 100
    assert config["sample"]["fraction"] <= 1e-6 and approval["max_sample_fraction"] <= 1e-6
    assert approval["status"] == "blocked"
    assert not config.get("transparency", {}).get("anonymous", False)
