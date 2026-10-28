"""write_jsonl streams its rows and keeps the exact bytes and checksum of the earlier all-in-memory version."""
import hashlib

from scanner.models import canonical_json, write_jsonl


def _legacy(path, rows, sort_key=None):
    rows = list(rows)
    if sort_key:
        rows.sort(key=lambda row: canonical_json(row.get(sort_key)))
    data = "".join(canonical_json(row) + "\n" for row in rows).encode("utf-8")
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def test_same_bytes_and_checksum_as_before(tmp_path):
    rows = [{"b": 2, "a": "é"}, {"a": "x", "b": [3, 1]}, {"a": None, "b": {"z": 1}}]
    assert write_jsonl(tmp_path / "new.jsonl", iter(rows)) == _legacy(tmp_path / "old.jsonl", rows)
    assert (tmp_path / "new.jsonl").read_bytes() == (tmp_path / "old.jsonl").read_bytes()


def test_sorted_output_matches_too(tmp_path):
    rows = [{"k": "b"}, {"k": "a"}, {"k": "c"}]
    assert write_jsonl(tmp_path / "new.jsonl", rows, sort_key="k") == _legacy(tmp_path / "old.jsonl", rows, "k")


def test_an_empty_input_writes_an_empty_file(tmp_path):
    assert write_jsonl(tmp_path / "e.jsonl", []) == hashlib.sha256(b"").hexdigest()
    assert (tmp_path / "e.jsonl").read_bytes() == b""
