"""Shared fixtures."""
import shutil

import pytest


@pytest.fixture(autouse=True)
def roomy_disk(monkeypatch):
    """Campaigns check the free disk before each shard; whatever the machine running the tests has left must not decide a test.

    Tests of the check and of the in-shard guard set their own ``shutil.disk_usage``, which replaces this one.
    """
    real = shutil.disk_usage

    def usage(path):
        seen = real(path)
        return type(seen)(seen.total, seen.used, max(seen.free, 1 << 42))
    monkeypatch.setattr(shutil, "disk_usage", usage)
