"""Shipped templates are inert, and the instrument stays decoupled from the test fixtures."""
import ast
from pathlib import Path

import pytest

from scanner.internet.config import ConfigError, load_config
from scanner.safety import TargetPolicy

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "scanner" / "internet"


def test_example_config_is_refused_as_shipped():
    with pytest.raises(ConfigError):
        load_config(ROOT / "run" / "config.example.yaml")


def test_example_approval_is_blocked_and_unfilled():
    text = (ROOT / "run" / "approval.example.yaml").read_text(encoding="utf-8")
    assert "status: blocked" in text and "REPLACE_ME" in text


def _imports(path: Path) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
    return out


def test_instrument_never_imports_lab_or_other_experiments_or_unfinished_modules():
    banned = ("lab", "scanner.run_pipeline", "scanner.hostname_discovery", "scanner.enrichment", "scanner.matching", "scanner.config")
    files = list(PKG.glob("*.py")) + [ROOT / "scanner" / "zdns_runner.py"]
    for f in files:
        for mod in _imports(f):
            assert not any(mod == b or mod.startswith(b + ".") for b in banned if b != "scanner.config") , (f.name, mod)
            assert mod != "scanner.config", (f.name, mod)


def test_shell_scripts_use_lf_line_endings():
    for f in (ROOT / "run").glob("*.sh"):
        assert b"\r" not in f.read_bytes(), f.name


def test_every_probe_stage_goes_through_the_target_policy():
    # production policy refuses special-use space even if a stage were handed such an address
    from scanner.internet.pipeline import build_policy
    from tests.helpers import write_config
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        cfg = load_config(write_config(Path(d)))
        policy, _plan, _excl = build_policy(cfg)
        for ip in ("127.0.0.1", "10.1.1.1", "192.168.0.1", "169.254.1.1", "224.0.0.1", "203.0.113.9", "8.8.4.4"):
            assert policy.check_ip(ip, stage="zgrab") is not None, ip      # last one is in the exclusions file
        assert policy.check_ip("1.1.1.1", stage="zgrab") is None
        assert policy.check_hostname("localhost", stage="dns") is not None
        assert policy.check_hostname("*.example.com", stage="dns") is not None
        assert isinstance(policy, TargetPolicy)
