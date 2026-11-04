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
