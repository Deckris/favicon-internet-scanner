import json

from scanner.internet.favicon import RecordLog


def _rec(i, host=None):
    return {"ip": f"10.0.{i // 250}.{i % 250}", "port": 443, "hostname": host, "n": i}


def _write(path, recs):
    log = RecordLog(path)
    for r in recs:
        log.append(r)
    log.close()


def _offsets(index):
    return dict(index._offsets)


def _full(path):
    sidecar = RecordLog(path)._sidecar
    if sidecar.exists():
        sidecar.unlink()
    return _offsets(RecordLog(path).load_index())


def test_sidecar_written_and_equivalent(tmp_path):
    path = tmp_path / "rec.jsonl"
    _write(path, [_rec(i, "h" if i % 3 else None) for i in range(50)] + [_rec(3, "h")])
    assert path.with_name("rec.jsonl.idx").exists()
    idx = RecordLog(path).load_index()
    side = _offsets(idx)
    assert side == _full(path)
    assert idx.get(("10.0.0.3", 443, "h"))["n"] == 3


def test_truncated_last_line(tmp_path):
    path = tmp_path / "rec.jsonl"
    _write(path, [_rec(i) for i in range(10)])
    with path.open("ab") as fh:
        fh.write(b'{"ip": "10.9.9.9", "po')
    side = _offsets(RecordLog(path).load_index())
    assert side == _full(path)
    assert len(side) == 10
    _write(path, [_rec(20)])           # reopened after the cut line
    assert _offsets(RecordLog(path).load_index()) == _full(path)


def test_log_appended_after_sidecar(tmp_path):
    path = tmp_path / "rec.jsonl"
    _write(path, [_rec(i) for i in range(10)])
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(_rec(99)) + "\n" + json.dumps(_rec(2)) + "\n")
    idx = RecordLog(path).load_index()
    assert _offsets(idx) == _full(path)
    assert ("10.0.0.99", 443, None) in idx


def test_stale_sidecar_bigger_than_log(tmp_path):
    path = tmp_path / "rec.jsonl"
    _write(path, [_rec(i) for i in range(10)])
    with path.open("r+b") as fh:
        fh.truncate(path.stat().st_size // 2)
    side = _offsets(RecordLog(path).load_index())
    assert side == _full(path)


def test_corrupt_sidecar(tmp_path):
    path = tmp_path / "rec.jsonl"
    _write(path, [_rec(i) for i in range(10)])
    sc = RecordLog(path)._sidecar
    for junk in (b"not json", b'{"version":1,"covered":5,"entries":[]}', b'{"version":2}', b""):
        sc.write_bytes(junk)
        assert _offsets(RecordLog(path).load_index()) == _full(path)
        sc.write_bytes(junk)


def _run_log(tmp_path):
    run = tmp_path / "run"
    (run / "raw").mkdir(parents=True)
    return run, run / "raw" / "favicon_records.jsonl"


def test_run_layout_sidecar_goes_to_work(tmp_path):
    run, path = _run_log(tmp_path)
    _write(path, [_rec(i) for i in range(5)])
    assert not list((run / "raw").glob("*.idx*"))
    assert (run / "work" / "favicon_records.idx").exists()
    assert _offsets(RecordLog(path).load_index()) == _full(path)


def test_run_layout_sidecar_not_in_checksum_pass(tmp_path):
    run, path = _run_log(tmp_path)
    _write(path, [_rec(i) for i in range(5)])
    skipped = {"manifest.json", "stacks.txt"}
    listed = []
    for f in run.rglob("*"):
        rel = f.relative_to(run).as_posix()
        if not f.is_file() or rel in skipped or rel.split("/")[0] in ("report", "work"):
            continue
        listed.append(rel)
    assert listed == ["raw/favicon_records.jsonl"]
    side = RecordLog(path)._sidecar
    assert side.relative_to(run).as_posix().startswith("work/")


def test_run_layout_stale_and_corrupt_fall_back(tmp_path):
    run, path = _run_log(tmp_path)
    _write(path, [_rec(i) for i in range(10)])
    sc = RecordLog(path)._sidecar
    sc.write_bytes(b"not json")
    assert _offsets(RecordLog(path).load_index()) == _full(path)
    _write(path, [_rec(i) for i in range(10)])
    with path.open("r+b") as fh:
        fh.truncate(path.stat().st_size // 2)
    assert _offsets(RecordLog(path).load_index()) == _full(path)
