"""The scanner entry-point script and the container recipe: syntax, dispatch and packaging."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "run" / "scanner"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def run(*args, cwd=None):
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, cwd=cwd)


def test_script_parses():
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0


def test_help_lists_every_command():
    out = run("help")
    assert out.returncode == 0
    for cmd in ("build", "verify", "doctor", "plan", "run", "favicons", "stop", "summary", "pack"):
        assert f"  {cmd} " in out.stdout


def test_unknown_command_and_missing_arguments_are_refused(tmp_path):
    assert run("--workdir", str(tmp_path), "frobnicate").returncode == 2
    assert run("--workdir", str(tmp_path), "favicons").returncode == 2        # needs --source-run
    assert run("--workdir", str(tmp_path)).returncode == 2                    # no command


def test_docker_mode_build_is_the_only_mode_for_build(tmp_path):
    assert run("--native", "--workdir", str(tmp_path), "build").returncode == 2


def test_stop_touches_the_configured_kill_switch(tmp_path):
    (tmp_path / "config.yaml").write_text("operations:\n  kill_switch_file: STOP   # touch it to stop\n", encoding="utf-8")
    out = run("--native", "--workdir", str(tmp_path), "stop")
    assert out.returncode == 0 and (tmp_path / "STOP").exists()


def test_stop_without_a_kill_switch_setting_fails(tmp_path):
    (tmp_path / "config.yaml").write_text("run_label: x\n", encoding="utf-8")
    assert run("--native", "--workdir", str(tmp_path), "stop").returncode == 2


def test_pack_ships_only_the_manifest_and_report_by_default(tmp_path):
    run_dir = tmp_path / "runs" / "r1"
    (run_dir / "raw").mkdir(parents=True)
    (run_dir / "report").mkdir()
    (run_dir / "normalized").mkdir()
    (run_dir / "ip_results.csv").write_text("203.0.113.5,example.test", encoding="utf-8")
    (run_dir / "normalized" / "endpoints.jsonl").write_text("{}", encoding="utf-8")
    (run_dir / "scanned_ips.txt").write_text("203.0.113.5", encoding="utf-8")
    (run_dir / "raw" / "tool.jsonl").write_text("secret host data", encoding="utf-8")
    (run_dir / "report" / "summary.md").write_text("ok", encoding="utf-8")
    (run_dir / "manifest.json").write_text('{"complete": true}', encoding="utf-8")
    assert run("--native", "--workdir", str(tmp_path), "pack", str(run_dir)).returncode == 0
    names = subprocess.run(["tar", "-tzf", str(run_dir) + ".results.tar.gz"], capture_output=True, text=True).stdout
    assert "r1/report/summary.md" in names and "r1/manifest.json" in names
    assert not any(part in names for part in ("r1/raw", "r1/normalized", "ip_results.csv", "scanned_ips.txt"))
    assert (tmp_path / "runs" / "r1.results.tar.gz.SHA256SUMS").exists()
    assert run("--native", "--workdir", str(tmp_path), "pack", str(run_dir), "--with-results").returncode == 0
    names = subprocess.run(["tar", "-tzf", str(run_dir) + ".results.tar.gz"], capture_output=True, text=True).stdout
    assert "r1/ip_results.csv" in names and "r1/normalized" in names and "r1/raw" not in names
    assert run("--native", "--workdir", str(tmp_path), "pack", str(run_dir), "--with-raw").returncode == 0
    assert "r1/raw" in subprocess.run(["tar", "-tzf", str(run_dir) + ".results.tar.gz"], capture_output=True, text=True).stdout
    assert run("--native", "--workdir", str(tmp_path), "pack", str(run_dir), "--bogus").returncode == 2


def test_the_word_help_is_only_a_command_when_it_comes_first(tmp_path):
    out = run("--native", "--workdir", str(tmp_path), "summary", "help")
    assert out.returncode != 0 and "usage:" not in out.stdout      # a value, not a request for help
    assert "usage:" in run("help").stdout and "scanner init" in run("help", "init").stdout


def test_a_missing_work_folder_is_created(tmp_path, monkeypatch):
    import sys
    monkeypatch.setenv("SCANNER_PYTHON", sys.executable)
    work = tmp_path / "new" / "work"
    assert run("--native", "--workdir", str(work), "init").returncode == 0 and (work / "settings.yaml").exists()


def test_container_recipe_pins_everything_and_ships_with_the_package():
    docker = (ROOT / "run" / "Dockerfile").read_text(encoding="utf-8")
    for pinned in ("651ed713759a12e283c449259b2f6fa027ccf9b5", "ea734bcf60ef2921684cb522dfb87a07a322afa6", "v2.1.1", "golang:1.25.8", "ubuntu:24.04"):
        assert pinned in docker
    assert "requirements.lock" in docker and "setcap cap_net_raw+ep" in docker
    assert (ROOT / "scanner" / "requirements.lock").is_file()
