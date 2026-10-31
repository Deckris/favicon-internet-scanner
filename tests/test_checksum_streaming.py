from __future__ import annotations

import hashlib
import os
import tracemalloc

from scanner.internet.config import sha256_file
from scanner.internet import settings


def _big_file(tmp_path, size=50 * 1024 * 1024):
    path = tmp_path / "big.bin"
    block = os.urandom(1 << 20)
    with open(path, "wb") as fh:
        for _ in range(size // len(block)):
            fh.write(block)
        fh.write(b"tail")
    return path


def test_sha256_file_matches_hashlib_with_small_peak(tmp_path):
    path = _big_file(tmp_path)
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    tracemalloc.start()
    try:
        got = sha256_file(path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert got == expected
    assert peak < 5 * 1024 * 1024


def test_settings_sha256_file_streams(tmp_path):
    path = _big_file(tmp_path, 8 * 1024 * 1024)
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    tracemalloc.start()
    try:
        got = settings.sha256_file(path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert got == expected
    assert peak < 5 * 1024 * 1024


def test_sha256_file_empty_and_str_path(tmp_path):
    path = tmp_path / "empty"
    path.write_bytes(b"")
    assert sha256_file(str(path)) == hashlib.sha256(b"").hexdigest()
