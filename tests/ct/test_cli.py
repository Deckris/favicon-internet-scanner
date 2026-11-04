"""The ``python -m scanner.ct`` command line, driven through ``main(argv)`` with fakes; no socket is opened."""
import json

import pytest

from scanner.ct import __main__ as cli
from scanner.ct import certstream, crtsh, logcoverage
from scanner.ct.models import Observation, ObservationTable

NOW = "2026-01-01T00:00:00+00:00"


def obs(name, source="crtsh", cert_id=None):
    return Observation(name=name, source=source, seen_at=NOW, cert_id=cert_id)


def names_in(path):
    return sorted(o.name for o in ObservationTable.from_jsonl(path))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(crtsh, "default_connect", refuse)
    monkeypatch.setattr(logcoverage, "fetch_log_list", refuse)
    monkeypatch.setattr(certstream, "stream_websocket", refuse)


@pytest.fixture
def terms(tmp_path):
    path = tmp_path / "terms.txt"
    path.write_text("acme\n", encoding="utf-8")
    return path


def fake_windows(rows, record=None, raises=None):
    class FakeWindows:
        def __init__(self, **kwargs):
            if record is not None:
                record.update(kwargs)

        def iter_window(self, start, end, *, step=None):
            if record is not None:
                record["window"] = (start, end)
            yield from rows
            if raises:
                raise raises

    return FakeWindows


CRTSH_ARGS = ["crtsh", "--start", "2026-01-01T00:00", "--end", "2026-01-01T01:00", "--user-agent", "tester (mailto:ops@example.com)"]


def test_crtsh_writes_table_and_names(monkeypatch, tmp_path, capsys):
    seen = {}
    rows = [obs("login.acme-pay.example.com"), obs("www.other.example.org")]
    monkeypatch.setattr(crtsh, "CrtShWindows", fake_windows(rows, seen))
    out, names = tmp_path / "o.jsonl", tmp_path / "n.txt"
    assert cli.main([*CRTSH_ARGS, "--out", str(out), "--names-out", str(names)]) == 0
    assert names_in(out) == ["login.acme-pay.example.com", "www.other.example.org"]
    assert names.read_text().split() == ["login.acme-pay.example.com", "www.other.example.org"]
    assert seen["min_gap_s"] == 1.0 and seen["statement_cap"] == 5000
    assert seen["user_agent"].startswith("tester")
    assert seen["window"][0].tzinfo is not None
    err = capsys.readouterr().err
    assert "2 observations" in err and "User-Agent" in err


def test_crtsh_terms_filter(monkeypatch, tmp_path, terms):
    rows = [obs("login.acme-pay.example.com"), obs("www.other.example.org")]
    monkeypatch.setattr(crtsh, "CrtShWindows", fake_windows(rows))
    out = tmp_path / "o.jsonl"
    assert cli.main([*CRTSH_ARGS, "--terms", str(terms), "--out", str(out)]) == 0
    assert names_in(out) == ["login.acme-pay.example.com"]


def test_crtsh_passes_options(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(crtsh, "CrtShWindows", fake_windows([], seen))
    out = tmp_path / "o.jsonl"
    assert cli.main([*CRTSH_ARGS, "--min-gap", "2.5", "--statement-cap", "100", "--out", str(out)]) == 0
    assert seen["min_gap_s"] == 2.5 and seen["statement_cap"] == 100
    assert out.exists()


@pytest.mark.parametrize(
    "extra",
    [
        ["--min-gap", "0.5"],
        ["--statement-cap", "0"],
        ["--start", "yesterday"],
        ["--end", "2025-12-31T00:00"],
        ["--user-agent", "  "],
    ],
)
def test_crtsh_rejects_bad_options(monkeypatch, tmp_path, extra):
    monkeypatch.setattr(crtsh, "CrtShWindows", fake_windows([]))
    out = tmp_path / "o.jsonl"
    assert cli.main([*CRTSH_ARGS, *extra, "--out", str(out)]) == 2
    assert not out.exists()


def test_crtsh_requires_user_agent(tmp_path, capsys):
    argv = ["crtsh", "--start", "2026-01-01T00:00", "--end", "2026-01-01T01:00", "--out", str(tmp_path / "o.jsonl")]
    assert cli.main(argv) == 2


def test_crtsh_statement_cap_keeps_partial_and_fails(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(crtsh, "CrtShWindows", fake_windows([obs("a.example.com")], raises=crtsh.StatementCapReached("minute 3")))
    out = tmp_path / "o.jsonl"
    assert cli.main([*CRTSH_ARGS, "--out", str(out)]) == 1
    assert names_in(out) == ["a.example.com"]
    assert "cap" in capsys.readouterr().err


def test_crtsh_runtime_error_is_exit_1(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(crtsh, "CrtShWindows", fake_windows([], raises=OSError("connection refused")))
    assert cli.main([*CRTSH_ARGS, "--out", str(tmp_path / "o.jsonl")]) == 1
    assert "connection refused" in capsys.readouterr().err


@pytest.mark.parametrize("kind", ["certstream", "zonestream"])
def test_stream_collects_and_filters(monkeypatch, tmp_path, terms, capsys, kind):
    calls = {}

    def fake_stream(url, *, parse, max_messages=None, **kwargs):
        calls.update(url=url, parse=parse, max_messages=max_messages)
        yield obs("www.acme.example.com", source=kind)
        yield obs("mail.other.example.net", source=kind)

    monkeypatch.setattr(certstream, "stream_websocket", fake_stream)
    out, names = tmp_path / "o.jsonl", tmp_path / "n.txt"
    argv = [kind, "--url", "wss://feed.example.com/", "--max-messages", "10", "--terms", str(terms), "--out", str(out), "--names-out", str(names)]
    assert cli.main(argv) == 0
    assert calls["url"] == "wss://feed.example.com/" and calls["max_messages"] == 10
    assert calls["parse"] is getattr(certstream, f"parse_{kind}")
    assert names_in(out) == ["www.acme.example.com"]
    assert names.read_text().split() == ["www.acme.example.com"]
    assert "feed URL yourself" in capsys.readouterr().err


@pytest.mark.parametrize("kind", ["certstream", "zonestream"])
def test_stream_needs_explicit_websocket_url(tmp_path, kind):
    out = str(tmp_path / "o.jsonl")
    assert cli.main([kind, "--out", out]) == 2
    assert cli.main([kind, "--url", "http://feed.example.com/", "--out", out]) == 2


def test_stream_accepts_lists_per_message(monkeypatch, tmp_path):
    monkeypatch.setattr(certstream, "stream_websocket", lambda url, **k: iter([[obs("a.example.com"), obs("b.example.com")]]))
    out = tmp_path / "o.jsonl"
    assert cli.main(["certstream", "--url", "ws://127.0.0.1:1/", "--out", str(out)]) == 0
    assert names_in(out) == ["a.example.com", "b.example.com"]


def test_stream_interrupt_still_writes(monkeypatch, tmp_path):
    def fake_stream(url, **kwargs):
        yield obs("a.example.com")
        raise KeyboardInterrupt

    monkeypatch.setattr(certstream, "stream_websocket", fake_stream)
    out = tmp_path / "o.jsonl"
    assert cli.main(["certstream", "--url", "ws://127.0.0.1:1/", "--out", str(out)]) == 0
    assert names_in(out) == ["a.example.com"]


def test_import_export_file(monkeypatch, tmp_path, terms):
    export = tmp_path / "export.csv"
    export.write_text("x", encoding="utf-8")
    table = ObservationTable()
    table.extend([obs("shop.acme.example.com"), obs("blog.other.example.com")])
    from scanner.ct import importers

    monkeypatch.setattr(importers, "load_crtsh_export", lambda path: table)
    out, names = tmp_path / "o.jsonl", tmp_path / "n.txt"
    assert cli.main(["import", "--crtsh-export", str(export), "--terms", str(terms), "--out", str(out), "--names-out", str(names)]) == 0
    assert names_in(out) == ["shop.acme.example.com"]
    assert names.read_text().split() == ["shop.acme.example.com"]
    assert cli.main(["import", "--crtsh-export", str(export), "--out", str(tmp_path / "all.jsonl")]) == 0
    assert len(ObservationTable.from_jsonl(tmp_path / "all.jsonl")) == 2


def test_import_missing_file_is_exit_1(tmp_path):
    assert cli.main(["import", "--crtsh-export", str(tmp_path / "none.csv"), "--out", str(tmp_path / "o.jsonl")]) == 1


def test_filter_roundtrip(tmp_path, terms):
    src = tmp_path / "in.jsonl"
    table = ObservationTable()
    table.extend([obs("a.acme.example.com"), obs("b.other.example.com")])
    table.to_jsonl(src)
    out, names = tmp_path / "o.jsonl", tmp_path / "n.txt"
    assert cli.main(["filter", "--in", str(src), "--terms", str(terms), "--out", str(out), "--names-out", str(names)]) == 0
    assert names_in(out) == ["a.acme.example.com"]
    assert names.read_text().split() == ["a.acme.example.com"]


def test_filter_label_boundary_flag_reaches_filter(monkeypatch, tmp_path, terms):
    from scanner.ct import terms as terms_mod

    flags = []
    real = terms_mod.TermFilter.from_file.__func__

    def spy(cls, path, **kwargs):
        flags.append(kwargs.get("label_boundary"))
        return real(cls, path, **kwargs)

    monkeypatch.setattr(terms_mod.TermFilter, "from_file", classmethod(spy))
    src = tmp_path / "in.jsonl"
    ObservationTable().to_jsonl(src)
    assert cli.main(["filter", "--in", str(src), "--terms", str(terms), "--label-boundary", "--out", str(tmp_path / "o.jsonl")]) == 0
    assert cli.main(["filter", "--in", str(src), "--terms", str(terms), "--out", str(tmp_path / "p.jsonl")]) == 0
    assert flags == [True, False]


def test_filter_requires_terms(tmp_path):
    assert cli.main(["filter", "--in", str(tmp_path / "x"), "--out", str(tmp_path / "y")]) == 2


def test_names_command(tmp_path, capsys):
    src = tmp_path / "in.jsonl"
    table = ObservationTable()
    table.extend([obs("b.example.com", cert_id=1), obs("a.example.com", cert_id=2), obs("a.example.com", source="certstream", cert_id=3)])
    table.to_jsonl(src)
    out = tmp_path / "names.txt"
    assert cli.main(["names", "--in", str(src), "--out", str(out)]) == 0
    assert out.read_text().split() == ["a.example.com", "b.example.com"]
    assert "2 names" in capsys.readouterr().err


def test_names_missing_input_is_exit_1(tmp_path):
    assert cli.main(["names", "--in", str(tmp_path / "none.jsonl"), "--out", str(tmp_path / "n.txt")]) == 1


LOG_LIST = {"urls": ["https://ct.example.com/log1/", "https://ct.example.com/log2/"]}


def test_log_coverage_from_file_json(monkeypatch, tmp_path, capsys):
    watched = tmp_path / "watched.txt"
    watched.write_text("# mine\nhttps://ct.example.com/log1/\n\nhttps://ct.example.com/old/\n", encoding="utf-8")
    listing = tmp_path / "list.json"
    listing.write_text("{}", encoding="utf-8")
    seen = {}

    def fake_compare(urls, log_list):
        seen["watched"] = list(urls)
        return {"covered": ["https://ct.example.com/log1/"], "missing": ["https://ct.example.com/log2/"], "unknown": ["https://ct.example.com/old/"]}

    monkeypatch.setattr(logcoverage, "load_log_list", lambda source: LOG_LIST)
    monkeypatch.setattr(logcoverage, "compare", fake_compare)
    assert cli.main(["log-coverage", "--watched", str(watched), "--log-list", str(listing), "--json"]) == 0
    assert seen["watched"] == ["https://ct.example.com/log1/", "https://ct.example.com/old/"]
    captured = capsys.readouterr()
    assert json.loads(captured.out)["missing"] == ["https://ct.example.com/log2/"]
    assert "1 covered, 1 missing, 1 unknown" in captured.err


def test_log_coverage_fetch_text(monkeypatch, tmp_path, capsys):
    watched = tmp_path / "watched.txt"
    watched.write_text("https://ct.example.com/log1/\n", encoding="utf-8")
    monkeypatch.setattr(logcoverage, "fetch_log_list", lambda *a, **k: LOG_LIST)
    monkeypatch.setattr(logcoverage, "compare", lambda w, l: {"covered": list(w), "missing": [], "unknown": []})
    assert cli.main(["log-coverage", "--watched", str(watched), "--fetch"]) == 0
    assert "covered: 1" in capsys.readouterr().out


def test_log_coverage_needs_exactly_one_source(tmp_path):
    watched = tmp_path / "w.txt"
    watched.write_text("", encoding="utf-8")
    assert cli.main(["log-coverage", "--watched", str(watched)]) == 2
    assert cli.main(["log-coverage", "--watched", str(watched), "--fetch", "--log-list", str(watched)]) == 2


def test_log_coverage_fetch_failure_is_exit_1(monkeypatch, tmp_path):
    watched = tmp_path / "w.txt"
    watched.write_text("", encoding="utf-8")

    def boom(*a, **k):
        raise OSError("unreachable")

    monkeypatch.setattr(logcoverage, "fetch_log_list", boom)
    assert cli.main(["log-coverage", "--watched", str(watched), "--fetch"]) == 1


def test_usage_errors(capsys):
    assert cli.main([]) == 2
    assert cli.main(["nonsense"]) == 2
    assert cli.main(["--help"]) == 0
