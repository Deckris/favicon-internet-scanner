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


@pytest.fixture(autouse=True)
def fixed_context_clock(monkeypatch):
    """The request times the favicon stage takes from the clock would differ between two runs of identical input.

    A stored page whose output line has no timestamp is dated by the clock too; it gets a fixed date unless the line has one.
    """
    from scanner.internet import favicon
    real = favicon._fetched_at
    monkeypatch.setattr(favicon, "now_iso", lambda: "2026-10-04T18:00:00+00:00")
    monkeypatch.setattr(favicon, "_fetched_at", lambda stamp: real(stamp) if stamp else 1_800_000_000.0)
