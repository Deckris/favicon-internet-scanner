"""Things that differ between the developer's WSL2 host and a fresh university Linux host."""
import signal
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from scanner.internet import pipeline
from scanner.internet import preflight as pre
from scanner.internet.config import ConfigError, load_config
from tests.helpers import config_dict, write_approval, write_config, write_exclusions


def _config(tmp_path, **vantage):
    excl = write_exclusions(tmp_path)
    d = config_dict(tmp_path, excl, write_approval(tmp_path, excl))
    d["vantage"].update(vantage)
    p = tmp_path / "v.yaml"
    p.write_text(yaml.safe_dump(d), encoding="utf-8")
    return p


def test_egress_check_options_are_validated(tmp_path):
    assert load_config(write_config(tmp_path)).vantage.egress_check == "url"
    with pytest.raises(ConfigError, match="url, nic or off"):
        load_config(_config(tmp_path, egress_check="sometimes"))
    with pytest.raises(ConfigError, match="https://"):
        load_config(_config(tmp_path, egress_check_urls=["http://insecure.example/ip"]))
    with pytest.raises(ConfigError, match="source_ipv4 must equal"):
        load_config(_config(tmp_path, egress_check="nic"))                  # private source != public address
    ok = load_config(_config(tmp_path, egress_check="nic", source_ipv4="93.184.216.99"))
    assert ok.vantage.egress_check == "nic"


def test_url_mode_falls_back_to_the_next_service_when_one_is_blocked(tmp_path, monkeypatch):
    cfg = load_config(_config(tmp_path, egress_check_urls=["https://blocked.example/ip", "https://ok.example/ip"]))
    asked = []

    def fake(url, timeout=10.0):
        asked.append(url)
        return None if "blocked" in url else "93.184.216.99"
    monkeypatch.setattr(pre, "_public_ip", fake)
    assert pre.current_egress(cfg) == "93.184.216.99" and asked == ["https://blocked.example/ip", "https://ok.example/ip"]
    monkeypatch.setattr(pre, "_public_ip", lambda *a, **k: None)
    assert pre.current_egress(cfg) is None                                  # all blocked: unknown, never "fine"


def test_nic_mode_trusts_the_interface_not_a_web_service(tmp_path, monkeypatch):
    cfg = load_config(_config(tmp_path, egress_check="nic", source_ipv4="93.184.216.99"))
    monkeypatch.setattr(pre, "_public_ip", lambda *a, **k: pytest.fail("nic mode must not call out"))
    have = lambda *a, **k: SimpleNamespace(returncode=0, stdout="2: eth0    inet 93.184.216.99/24 brd 93.184.216.255 scope global eth0", stderr="")    # noqa: E731
    gone = lambda *a, **k: SimpleNamespace(returncode=0, stdout="2: eth0    inet 10.0.0.5/24 scope global eth0", stderr="")                             # noqa: E731
    assert pre.current_egress(cfg, have) == "93.184.216.99"
    assert pre.current_egress(cfg, gone) is None                            # the address left the interface: the guard must trip


def test_off_mode_is_never_reported_as_a_clean_pass(tmp_path):
    cfg = load_config(_config(tmp_path, egress_check="off"))
    assert pre.current_egress(cfg) == cfg.vantage.public_egress_ip
    _plan, splan, _ = pipeline.build_policy(cfg)
    rep = pre.run_preflight(cfg, splan, run_dir=tmp_path, executor=lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""), offline=False)
    check = next(c for c in rep["checks"] if c["name"] == "egress_matches_approved_source")
    assert check["status"] == "warn" and "NOT CHECKED" in check["detail"]


def test_only_pinned_zmap_versions_are_accepted():
    assert pre.zmap_version_supported("zmap 2.1.1")
    assert pre.zmap_version_supported("  zmap 2.1.0 ")
    assert pre.zmap_version_supported("zmap 4.4.0")
    assert not pre.zmap_version_supported("zmap 4.3.3")
    assert not pre.zmap_version_supported("zmap 2.0.9")
    assert not pre.zmap_version_supported("")


def test_nohup_style_ignored_hangup_is_respected():
    old = signal.signal(signal.SIGHUP, signal.SIG_IGN)                       # what `nohup` sets up before exec
    try:
        restore = pipeline._install_signal_handlers()
        assert signal.getsignal(signal.SIGHUP) == signal.SIG_IGN             # still ignored: a dropped SSH session cannot kill the run
        assert signal.getsignal(signal.SIGTERM) != signal.SIG_DFL            # SIGTERM still stops cleanly
        restore()
    finally:
        signal.signal(signal.SIGHUP, old)


def test_default_hangup_still_stops_the_run_cleanly():
    old = signal.signal(signal.SIGHUP, signal.SIG_DFL)
    try:
        restore = pipeline._install_signal_handlers()
        assert callable(signal.getsignal(signal.SIGHUP))
        restore()
    finally:
        signal.signal(signal.SIGHUP, old)


def test_shell_scripts_parse_and_gate_the_environment():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "run"
    setup = (root / "setup-wsl.sh").read_text(encoding="utf-8")
    assert "sys.version_info >= (3, 11)" in setup and "ZMAP_COMMIT=" in setup and "x86_64" in setup
    assert "RESPECT_INSTALL_PREFIX_CONFIG=ON" in setup
    for name in ("setup-wsl.sh", "scanner"):
        res = subprocess.run(["bash", "-n", str(root / name)], capture_output=True, text=True)
        assert res.returncode == 0, res.stderr
    assert "pytest" in (root.parent / "requirements.txt").read_text(encoding="utf-8")


def test_tracked_text_files_use_unix_line_endings():
    from pathlib import Path
    import subprocess as sp
    root = Path(__file__).resolve().parent.parent
    names = sp.run(["git", "ls-files"], cwd=root, capture_output=True, text=True).stdout.split()
    if not names:
        pytest.skip("not a git checkout")
    suffixes = {".sh", ".py", ".md", ".yaml", ".txt", ".lock"}
    bad = [n for n in names if (Path(n).suffix in suffixes or Path(n).name in {"scanner", "Dockerfile"})
           and b"\r" in (root / n).read_bytes()]
    assert not bad, f"CRLF line endings in: {bad}"
