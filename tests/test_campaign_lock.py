"""Campaign lock: a live holder blocks a second campaign, a dead or invalid holder does not."""
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from scanner.internet import campaign


def _cfg(tmp_path):
    return SimpleNamespace(output_dir=str(tmp_path), checksum="ab" * 32)


def _lock_file(cfg):
    return campaign.campaign_dir(cfg) / "campaign.lock"


def test_lock_held_by_a_running_process_is_refused(tmp_path):
    cfg = _cfg(tmp_path)
    path = campaign._acquire_lock(cfg)
    assert path.read_text() == str(os.getpid())
    with pytest.raises(campaign.CampaignLocked):
        campaign._acquire_lock(cfg)
    assert path.exists()


def test_lock_of_a_finished_process_is_taken_over(tmp_path):
    cfg = _cfg(tmp_path)
    done = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"], capture_output=True, text=True)
    _lock_file(cfg).parent.mkdir(parents=True, exist_ok=True)
    _lock_file(cfg).write_text(done.stdout.strip())
    campaign._acquire_lock(cfg)
    assert _lock_file(cfg).read_text() == str(os.getpid())


@pytest.mark.parametrize("content", ["0", "-1", "", "not a pid"])
def test_lock_with_an_invalid_pid_is_stale(tmp_path, content):
    cfg = _cfg(tmp_path)
    _lock_file(cfg).parent.mkdir(parents=True, exist_ok=True)
    _lock_file(cfg).write_text(content)
    campaign._acquire_lock(cfg)
    assert _lock_file(cfg).read_text() == str(os.getpid())
