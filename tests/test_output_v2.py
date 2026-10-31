"""Output schema 2: slim hostname rows, zstd raw files, and the readers that hide both.

``tests/golden_v1/`` holds the files a schema 1 run wrote for each golden scenario. A schema 2 run of the same
scenario must give back exactly those rows, that CSV, the same endpoint and address tables, and raw tool output
whose decompressed bytes carry the checksums the schema 1 manifest recorded.
"""
import hashlib
import json
import os
import subprocess
import sys
import tracemalloc
from pathlib import Path

import pytest

from scanner.internet import outputs, pipeline
from scanner.internet.__main__ import main
from scanner.internet.config import load_config
from scanner.internet.runner import ManagedExecutor, _pump_to_file, capture_stdout, iter_lines
from tests.helpers import write_config
from tests.test_golden_outputs import SCENARIOS
from tests.test_pipeline import go, tools

GOLDEN_V1 = Path(__file__).parent / "golden_v1"
PY = sys.executable
needs_zstd = pytest.mark.skipif(outputs.zstandard is None, reason="zstandard is not installed")


def _lf(raw: bytes) -> bytes:
    return raw.replace(b"\r\n", b"\n")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------ equivalence with the schema 1 goldens

@pytest.mark.skipif(os.name != "posix", reason="golden files are generated on Linux")
@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_schema_2_run_reproduces_the_schema_1_outputs(name, tmp_path):
    cfg, ft, fetcher = SCENARIOS[name](tmp_path)
    run_dir = pipeline.run(cfg, run_id="t1", executor=ft, fetcher=fetcher, skip_preflight=True, offline_preflight=True)
    old = GOLDEN_V1 / name
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["output_schema"] == 2 and not (run_dir / "normalized" / "hostname_resolution.csv").exists()

    # (a) the hostname rows, parsed, in order
    expected = [json.loads(l) for l in (old / "normalized" / "hostname_resolution.jsonl").read_text(encoding="utf-8").splitlines()]
    assert list(outputs.iter_hostname_rows(run_dir)) == expected

    # (b) the CSV
    csv_path = outputs.export_csv(run_dir, tmp_path / "export.csv")
    assert _lf(csv_path.read_bytes()) == (old / "normalized" / "hostname_resolution.csv").read_bytes()

    # (c) the tables that did not change
    for rel in ("normalized/endpoints.jsonl", "ip_results.csv", "favicons/index.jsonl"):
        if (old / rel).exists():
            assert _lf((run_dir / rel).read_bytes()) == (old / rel).read_bytes(), rel
        else:
            assert not (run_dir / rel).exists(), rel

    # (d) raw tool output: the stored files are compressed, the content is what the schema 1 manifest checksummed
    old_sums = json.loads((old / "manifest.json").read_text(encoding="utf-8"))["output_checksums"]
    raw = {k: v for k, v in old_sums.items() if k.startswith(("raw/zgrab/", "raw/zdns/"))}
    assert raw or name != "mixed"
    for rel, digest in raw.items():
        stored = run_dir / (rel[: -len(".jsonl")] + outputs.RAW_SUFFIX)
        assert stored.is_file()
        with outputs.open_binary(stored) as fh:
            assert _sha(fh.read()) == digest, rel
        assert manifest["output_checksums"][str(stored.relative_to(run_dir)).replace("\\", "/")] == _sha(stored.read_bytes())
    for job in map(json.loads, (run_dir / "normalized" / "tool_jobs.jsonl").read_text().splitlines()):
        if job["raw_path"].startswith(("raw/zgrab/", "raw/zdns/")):
            assert job["raw_sha256"] == manifest["output_checksums"][job["raw_path"].replace("\\", "/")]


# ------------------------------------------------------------------ the row split

def test_hostname_rows_hold_only_the_key_and_hostname_fields(tmp_path):
    run_dir = go(load_config(write_config(tmp_path)), tools())
    slim = [json.loads(l) for l in (run_dir / "normalized" / "hostname_resolution.jsonl").read_text().splitlines()]
    endpoint = [json.loads(l) for l in (run_dir / "normalized" / "endpoints.jsonl").read_text().splitlines()]
    assert slim and all(set(r) <= set(outputs.KEY_FIELDS) | outputs.HOSTNAME_FIELDS for r in slim)
    assert all(set(outputs.KEY_FIELDS) <= set(r) for r in slim)
    ep_fields = set(endpoint[0]) - {"hostnames"}
    assert not (ep_fields & outputs.HOSTNAME_FIELDS)
    full = list(outputs.iter_hostname_rows(run_dir))
    assert all(set(r) == ep_fields | outputs.HOSTNAME_FIELDS for r in full)
    assert len(full) == len(slim)


def _fake_run(tmp_path, schema, endpoints, hostnames):
    run = tmp_path / f"run{schema}"
    (run / "normalized").mkdir(parents=True)
    manifest = {"run_id": "x"} if schema == 1 else {"run_id": "x", "output_schema": schema}
    (run / "manifest.json").write_text(json.dumps(manifest))
    (run / "normalized" / "endpoints.jsonl").write_text("".join(json.dumps(r) + "\n" for r in endpoints))
    (run / "normalized" / "hostname_resolution.jsonl").write_text("".join(json.dumps(r) + "\n" for r in hostnames))
    return run


def test_join_streams_endpoints_in_step_with_hostname_rows(tmp_path):
    eps = [{"target_ip": "1.1.1.1", "port": 80, "protocol": "http", "hostnames": ["a"]},
           {"target_ip": "1.1.1.1", "port": 443, "protocol": "https", "hostnames": ["a", "b"]},
           {"target_ip": "1.1.1.2", "port": 80, "protocol": "tcp_only", "hostnames": []}]
    hosts = [{"target_ip": "1.1.1.1", "port": 80, "hostname": "a"},
             {"target_ip": "1.1.1.1", "port": 443, "hostname": "a"}, {"target_ip": "1.1.1.1", "port": 443, "hostname": "b"},
             {"target_ip": "1.1.1.2", "port": 80, "hostname": None}]
    got = list(outputs.iter_hostname_rows(_fake_run(tmp_path, 2, eps, hosts)))
    assert [(r["target_ip"], r["port"], r["hostname"], r["protocol"]) for r in got] == [
        ("1.1.1.1", 80, "a", "http"), ("1.1.1.1", 443, "a", "https"), ("1.1.1.1", 443, "b", "https"), ("1.1.1.2", 80, None, "tcp_only")]
    assert all("hostnames" not in r for r in got)
    assert [r["hostname"] for r in outputs.iter_hostname_rows(_fake_run(tmp_path, 1, eps, hosts))] == ["a", "a", "b", None]
    assert list(outputs.iter_endpoint_rows(tmp_path / "run2")) == eps


def test_a_hostname_row_without_its_endpoint_is_an_error(tmp_path):
    run = _fake_run(tmp_path, 2, [{"target_ip": "1.1.1.1", "port": 80}], [{"target_ip": "1.1.1.9", "port": 80, "hostname": "a"}])
    with pytest.raises(ValueError, match="no endpoint row"):
        list(outputs.iter_hostname_rows(run))


def test_v1_runs_pass_through_and_a_missing_manifest_means_v1(tmp_path):
    run = _fake_run(tmp_path, 1, [], [{"target_ip": "1.1.1.1", "port": 80, "hostname": "a", "protocol": "http"}])
    assert list(outputs.iter_hostname_rows(run))[0]["protocol"] == "http"
    (run / "manifest.json").unlink()
    assert outputs.output_schema(run) == 1


# ------------------------------------------------------------------ export-csv

def test_export_csv_command_writes_the_table(tmp_path, capsys):
    run_dir = go(load_config(write_config(tmp_path)), tools())
    out = tmp_path / "t.csv"
    assert main(["export-csv", str(run_dir), "--out", str(out)]) == 0
    text = out.read_bytes().decode("utf-8")
    assert text.startswith("target_ip,port,zmap_result,") and "\r\n" in text
    assert main(["export-csv", str(run_dir)]) == 0
    assert (run_dir / "normalized" / "hostname_resolution.csv").read_bytes() == out.read_bytes()
    assert text.count("\r\n") == len(list(outputs.iter_hostname_rows(run_dir))) + 1


def test_export_csv_of_an_empty_table_is_an_empty_file(tmp_path):
    run = _fake_run(tmp_path, 2, [], [])
    assert outputs.export_csv(run, tmp_path / "e.csv").read_bytes() == b""


# ------------------------------------------------------------------ compression

@needs_zstd
def test_streamed_zst_file_is_checksummed_over_stored_bytes(tmp_path):
    proc = subprocess.Popen([PY, "-c", "import sys\nfor i in range(20000): print('{\"n\": %d}' % i)"], stdout=subprocess.PIPE, text=True)
    sink: list[str] = []
    path = tmp_path / "o.jsonl.zst"
    _pump_to_file(proc.stdout, path, sink)
    proc.wait()
    assert sink == [_sha(path.read_bytes())]
    lines = list(iter_lines(path))
    assert lines[:2] == ['{"n": 0}', '{"n": 1}'] and len(lines) == 20000
    assert path.stat().st_size < 20000 * 9 // 2


@needs_zstd
def test_executor_streams_compressed_output_within_bounded_memory(tmp_path):
    cfg = load_config(write_config(tmp_path))
    (tmp_path / "raw").mkdir()
    ex = ManagedExecutor(cfg, tmp_path, lambda: False)
    big = ("import sys\nline = '{\"ip\": \"10.0.0.1\", \"pad\": \"' + 'x' * 1000 + '\"}\\n'\n"
           "for _ in range(50_000):\n    sys.stdout.write(line)\n")
    out = tmp_path / "big.jsonl.zst"
    tracemalloc.start()
    try:
        proc, digest = capture_stdout(ex, [PY, "-c", big], out, capture_output=True, text=True, check=False)
        count = sum(1 for line in iter_lines(out) if line.strip())
        _cur, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert proc.returncode == 0 and count == 50_000 and digest == _sha(out.read_bytes()) and peak < 16_000_000


@needs_zstd
def test_text_executors_are_stored_compressed_with_the_same_checksum_rule(tmp_path):
    def fake(command, **kw):
        return subprocess.CompletedProcess(command, 0, "a\nb\n", "")
    out = tmp_path / "f.jsonl.zst"
    _, digest = capture_stdout(fake, ["x"], out)
    assert digest == _sha(out.read_bytes()) and outputs.read_text(out) == "a\nb\n"


@needs_zstd
def test_a_frame_cut_short_and_an_empty_file_still_read(tmp_path):
    data = b"".join(b'{"n": %d}\n' % i for i in range(50000))
    stored = outputs.compress_bytes(data)
    cut = tmp_path / "cut.jsonl.zst"
    cut.write_bytes(stored[: len(stored) // 2])
    got = list(iter_lines(cut))
    assert 0 < len(got) < 50000 and got[0] == '{"n": 0}'
    empty = tmp_path / "empty.jsonl.zst"
    empty.write_bytes(b"")
    assert list(iter_lines(empty)) == []


def test_plain_files_read_the_same_way(tmp_path):
    p = tmp_path / "p.jsonl"
    p.write_bytes(b'a\r\nb\n\nc')
    assert list(iter_lines(p)) == ["a\r", "b", "", "c"] and outputs.read_text(p) == 'a\r\nb\n\nc'


@needs_zstd
def test_run_stores_raw_batches_compressed_and_says_so(tmp_path):
    run_dir = go(load_config(write_config(tmp_path)), tools())
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["compression"] == "zstd" and "compression_note" not in m
    zst = sorted((run_dir / "raw").glob("*/*.jsonl.zst"))
    assert zst and not list((run_dir / "raw").glob("*/*.jsonl"))
    for p in zst:
        assert m["output_checksums"][str(p.relative_to(run_dir)).replace("\\", "/")] == _sha(p.read_bytes())
        assert all(json.loads(l) for l in iter_lines(p) if l.strip())


def test_without_the_package_raw_files_stay_plain_and_the_manifest_notes_it():
    root = Path(__file__).resolve().parents[1]
    code = (f"import sys; sys.path.insert(0, {str(root)!r}); sys.modules['zstandard'] = None\n"
            "from scanner.internet import outputs\n"
            "print(outputs.COMPRESSION, outputs.RAW_SUFFIX, bool(outputs.COMPRESSION_NOTE))")
    res = subprocess.run([PY, "-I", "-c", code], capture_output=True, text=True)
    assert res.stdout.split() == ["none", ".jsonl", "True"], res.stderr
