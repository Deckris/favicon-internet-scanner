import os

import pytest

from scanner.ct.models import Observation, ObservationTable


def obs(name, source="crtsh", cert_id="1", **kw):
    return Observation(name=name, source=source, seen_at="2026-01-01T00:00:00Z", cert_id=cert_id, **kw)


def test_dedup_key_and_add():
    table = ObservationTable()
    assert obs("a.example.com").dedup_key() == ("a.example.com", "crtsh", "1")
    assert table.add(obs("a.example.com"))
    assert not table.add(obs("a.example.com", issuer="other"))
    assert table.add(obs("a.example.com", source="certstream"))
    assert table.add(obs("a.example.com", cert_id=None))
    assert len(table) == 3


def test_extend_counts_and_order():
    table = ObservationTable()
    rows = [obs("b.example.org"), obs("a.example.org"), obs("b.example.org")]
    assert table.extend(rows) == 2
    assert [o.name for o in table] == ["b.example.org", "a.example.org"]
    assert table.names() == ["a.example.org", "b.example.org"]


def test_dict_roundtrip():
    original = obs("a.example.com", issuer="Test CA", log="log.invalid")
    assert Observation.from_dict(original.to_dict()) == original


def test_jsonl_roundtrip(tmp_path):
    table = ObservationTable()
    table.extend([obs("a.example.com", issuer="Test CA"), obs("bü.example.com", source="import", cert_id=None)])
    path = tmp_path / "obs.jsonl"
    table.to_jsonl(path)
    raw = path.read_bytes()
    assert b"\r" not in raw and raw.endswith(b"\n")
    first = raw.decode("utf-8").splitlines()[0]
    assert first.index('"cert_id"') < first.index('"name"') < first.index('"source"')
    again = ObservationTable.from_jsonl(path)
    assert list(again) == list(table)


def test_jsonl_write_is_synced_unique_and_leaves_no_temp_file(tmp_path, monkeypatch):
    table = ObservationTable()
    table.add(obs("a.example.com"))
    target = tmp_path / "obs.jsonl"
    synced, replaced = [], []
    real_replace = os.replace
    monkeypatch.setattr(os, "fsync", lambda fd: synced.append(fd))
    monkeypatch.setattr(os, "replace", lambda a, b: (replaced.append(str(a)), real_replace(a, b)))
    table.to_jsonl(target)
    table.to_jsonl(target)
    assert len(synced) == 2 and len(set(replaced)) == 2
    assert [p.name for p in tmp_path.iterdir()] == ["obs.jsonl"]


def test_jsonl_failure_keeps_the_old_file_and_removes_the_temp_file(tmp_path, monkeypatch):
    target = tmp_path / "obs.jsonl"
    target.write_text("old\n", encoding="utf-8")
    table = ObservationTable()
    table.add(obs("a.example.com"))

    def fail(src, dst):
        raise OSError("disk")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError):
        table.to_jsonl(target)
    assert target.read_text(encoding="utf-8") == "old\n"
    assert [p.name for p in tmp_path.iterdir()] == ["obs.jsonl"]
