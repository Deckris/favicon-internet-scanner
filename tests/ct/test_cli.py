"""The ``python -m scanner.ct`` command line, driven through ``main(argv)`` with fakes; no socket is opened."""
import json
import os
import signal
from pathlib import Path

import pytest

from scanner.ct import __main__ as cli
from scanner.ct import certstream, crtsh, logcoverage
from scanner.ct.models import Observation, ObservationTable

NOW = "2026-01-01T00:00:00+00:00"
FIXTURES = Path(__file__).parent / "fixtures"


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
    path.write_text("alpha\n", encoding="utf-8")
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
    rows = [obs("www.alpha-widget.example.com"), obs("www.other.example.org")]
    monkeypatch.setattr(crtsh, "CrtShWindows", fake_windows(rows, seen))
    out, names = tmp_path / "o.jsonl", tmp_path / "n.txt"
    assert cli.main([*CRTSH_ARGS, "--out", str(out), "--names-out", str(names)]) == 0
    assert names_in(out) == ["www.alpha-widget.example.com", "www.other.example.org"]
    assert names.read_text().split() == ["www.alpha-widget.example.com", "www.other.example.org"]
    assert seen["min_gap_s"] == 1.0 and seen["statement_cap"] == 5000
    assert seen["user_agent"].startswith("tester")
    assert seen["window"][0].tzinfo is not None
    err = capsys.readouterr().err
    assert "2 observations" in err and "application_name" in err


def test_crtsh_terms_filter(monkeypatch, tmp_path, terms):
    rows = [obs("www.alpha-widget.example.com"), obs("www.other.example.org")]
    monkeypatch.setattr(crtsh, "CrtShWindows", fake_windows(rows))
    out = tmp_path / "o.jsonl"
    assert cli.main([*CRTSH_ARGS, "--terms", str(terms), "--out", str(out)]) == 0
    assert names_in(out) == ["www.alpha-widget.example.com"]


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
        ["--user-agent", "httpx"],
        ["--user-agent", "a@"],
        ["--min-gap", "nan"],
        ["--min-gap", "inf"],
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
        yield obs("www.alpha.example.com", source=kind)
        yield obs("mail.other.example.net", source=kind)

    monkeypatch.setattr(certstream, "stream_websocket", fake_stream)
    out, names = tmp_path / "o.jsonl", tmp_path / "n.txt"
    argv = [kind, "--url", "wss://feed.example.com/", "--max-messages", "10", "--terms", str(terms), "--out", str(out), "--names-out", str(names)]
    assert cli.main(argv) == 0
    assert calls["url"] == "wss://feed.example.com/" and calls["max_messages"] == 10
    assert calls["parse"] is getattr(certstream, f"parse_{kind}")
    assert names_in(out) == ["www.alpha.example.com"]
    assert names.read_text().split() == ["www.alpha.example.com"]
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
    table.extend([obs("www.alpha.example.net"), obs("blog.other.example.com")])
    from scanner.ct import importers

    monkeypatch.setattr(importers, "load_crtsh_export", lambda path: table)
    out, names = tmp_path / "o.jsonl", tmp_path / "n.txt"
    assert cli.main(["import", "--crtsh-export", str(export), "--terms", str(terms), "--out", str(out), "--names-out", str(names)]) == 0
    assert names_in(out) == ["www.alpha.example.net"]
    assert names.read_text().split() == ["www.alpha.example.net"]
    assert cli.main(["import", "--crtsh-export", str(export), "--out", str(tmp_path / "all.jsonl")]) == 0
    assert len(ObservationTable.from_jsonl(tmp_path / "all.jsonl")) == 2


def test_import_missing_file_is_exit_1(tmp_path):
    assert cli.main(["import", "--crtsh-export", str(tmp_path / "none.csv"), "--out", str(tmp_path / "o.jsonl")]) == 1


def test_filter_roundtrip(tmp_path, terms):
    src = tmp_path / "in.jsonl"
    table = ObservationTable()
    table.extend([obs("a.alpha.example.com"), obs("b.other.example.com")])
    table.to_jsonl(src)
    out, names = tmp_path / "o.jsonl", tmp_path / "n.txt"
    assert cli.main(["filter", "--in", str(src), "--terms", str(terms), "--out", str(out), "--names-out", str(names)]) == 0
    assert names_in(out) == ["a.alpha.example.com"]
    assert names.read_text().split() == ["a.alpha.example.com"]


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
        return {"covered": ["https://ct.example.com/log1/"], "missing": [{"url": "https://ct.example.com/log2/", "type": "standard"}], "unknown": ["https://ct.example.com/old/"]}

    monkeypatch.setattr(logcoverage, "load_log_list", lambda source: LOG_LIST)
    monkeypatch.setattr(logcoverage, "compare", fake_compare)
    assert cli.main(["log-coverage", "--watched", str(watched), "--log-list", str(listing), "--json"]) == 0
    assert seen["watched"] == ["https://ct.example.com/log1/", "https://ct.example.com/old/"]
    captured = capsys.readouterr()
    assert json.loads(captured.out)["missing"] == [{"url": "https://ct.example.com/log2/", "type": "standard"}]
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


def test_crtsh_connect_hands_the_user_agent_to_the_connector(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(crtsh, "default_connect", lambda user_agent, *a, **k: calls.append(user_agent) or object())
    seen = {}
    monkeypatch.setattr(crtsh, "CrtShWindows", fake_windows([], seen))
    assert cli.main([*CRTSH_ARGS, "--out", str(tmp_path / "o.jsonl")]) == 0
    seen["connect"]()
    assert calls == ["tester (mailto:ops@example.com)"]


def test_crtsh_statement_failure_keeps_partial_and_fails(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(crtsh, "CrtShWindows", fake_windows([obs("a.example.com")], raises=crtsh.StatementFailed("x")))
    out = tmp_path / "o.jsonl"
    assert cli.main([*CRTSH_ARGS, "--out", str(out)]) == 1
    assert names_in(out) == ["a.example.com"]
    assert "statement failed" in capsys.readouterr().err


def test_crtsh_with_real_reader_stops_at_the_statement_cap(monkeypatch, tmp_path, capsys):
    class Conn:
        def execute(self, sql, params):
            class Cursor:
                def fetchall(self):
                    return []
            return Cursor()

        def close(self):
            pass

    opened = []
    monkeypatch.setattr(crtsh, "default_connect", lambda user_agent, *a, **k: opened.append(user_agent) or Conn())
    real = crtsh.CrtShWindows
    monkeypatch.setattr(crtsh, "CrtShWindows", lambda **kw: real(**kw, sleep=lambda s: None))
    out = tmp_path / "o.jsonl"
    assert cli.main([*CRTSH_ARGS, "--statement-cap", "3", "--out", str(out)]) == 1
    assert opened == ["tester (mailto:ops@example.com)"]
    assert "statement cap" in capsys.readouterr().err
    assert out.exists()


def test_log_coverage_with_real_comparison(tmp_path, capsys):
    watched = tmp_path / "watched.txt"
    watched.write_text("https://ct.alpha.example/2026/" + chr(10) + "https://ct.nowhere.example/" + chr(10), encoding="utf-8")
    assert cli.main(["log-coverage", "--watched", str(watched), "--log-list", str(FIXTURES / "log_list.json")]) == 0
    out = capsys.readouterr().out
    assert "covered: 1" in out and "  https://ct.alpha.example/2026/" in out
    assert "  https://ct.beta.example/log/" in out and "{" not in out
    assert "unknown: 1" in out


def test_offline_end_to_end_import_then_names(tmp_path):
    table_path, names_path, final = tmp_path / "obs.jsonl", tmp_path / "names.txt", tmp_path / "final.txt"
    export = FIXTURES / "crtsh_export.json"
    assert cli.main(["import", "--crtsh-export", str(export), "--out", str(table_path), "--names-out", str(names_path)]) == 0
    expected = ["alpha.example", "beta.test", "www.alpha.example", "xn--bcher-kva.example"]
    assert sorted(names_path.read_text(encoding="utf-8").split()) == expected
    assert cli.main(["names", "--in", str(table_path), "--out", str(final)]) == 0
    assert sorted(final.read_text(encoding="utf-8").split()) == expected
    assert names_in(table_path) == expected


def test_crtsh_constructor_rejection_is_a_usage_error(monkeypatch, tmp_path):
    def reject(**kwargs):
        raise ValueError("bad")

    monkeypatch.setattr(crtsh, "CrtShWindows", reject)
    assert cli.main([*CRTSH_ARGS, "--out", str(tmp_path / "o.jsonl")]) == 2


def test_crtsh_skipped_windows_make_the_run_fail(monkeypatch, tmp_path, capsys):
    windows = fake_windows([obs("a.example.com")])
    windows.errors = ["window 1 timed out and was skipped"]
    monkeypatch.setattr(crtsh, "CrtShWindows", windows)
    out = tmp_path / "o.jsonl"
    assert cli.main([*CRTSH_ARGS, "--out", str(out)]) == 1
    assert names_in(out) == ["a.example.com"]
    err = capsys.readouterr().err
    assert "timed out and was skipped" in err and "incomplete" in err


@pytest.mark.parametrize("raises", [RuntimeError("boom"), KeyboardInterrupt()])
def test_crtsh_writes_the_table_on_any_exception(monkeypatch, tmp_path, raises):
    monkeypatch.setattr(crtsh, "CrtShWindows", fake_windows([obs("a.example.com")], raises=raises))
    out, names = tmp_path / "o.jsonl", tmp_path / "n.txt"
    assert cli.main([*CRTSH_ARGS, "--out", str(out), "--names-out", str(names)]) == 1
    assert names_in(out) == ["a.example.com"] and names.read_text().split() == ["a.example.com"]


def test_stream_writes_the_table_on_unexpected_error(monkeypatch, tmp_path):
    def fake_stream(url, **kwargs):
        yield obs("a.example.com")
        raise ValueError("bad frame")

    monkeypatch.setattr(certstream, "stream_websocket", fake_stream)
    out = tmp_path / "o.jsonl"
    assert cli.main(["certstream", "--url", "ws://127.0.0.1:1/", "--out", str(out)]) == 1
    assert names_in(out) == ["a.example.com"]


@pytest.mark.skipif(not hasattr(signal, "SIGTERM"), reason="no SIGTERM")
def test_sigterm_ends_a_stream_gracefully(monkeypatch, tmp_path):
    def fake_stream(url, **kwargs):
        yield obs("a.example.com")
        signal.raise_signal(signal.SIGTERM)
        yield obs("b.example.com")

    monkeypatch.setattr(certstream, "stream_websocket", fake_stream)
    out = tmp_path / "o.jsonl"
    previous = signal.getsignal(signal.SIGTERM)
    assert cli.main(["certstream", "--url", "ws://127.0.0.1:1/", "--out", str(out)]) == 0
    assert names_in(out) == ["a.example.com"]
    assert signal.getsignal(signal.SIGTERM) is previous


def test_table_is_flushed_periodically(monkeypatch, tmp_path):
    out = tmp_path / "o.jsonl"
    sizes = []
    monkeypatch.setattr(cli, "FLUSH_EVERY", 2)

    def fake_stream(url, **kwargs):
        for i in range(5):
            yield obs(f"h{i}.example.com")
            sizes.append(len(ObservationTable.from_jsonl(out)) if out.exists() else 0)

    monkeypatch.setattr(certstream, "stream_websocket", fake_stream)
    assert cli.main(["zonestream", "--url", "ws://127.0.0.1:1/", "--out", str(out)]) == 0
    assert sizes == [0, 2, 2, 4, 4]
    assert len(ObservationTable.from_jsonl(out)) == 5
    assert [p.name for p in tmp_path.iterdir()] == ["o.jsonl"]


def test_stream_options_reach_the_feed(monkeypatch, tmp_path, terms):
    calls = {}

    def fake_stream(url, *, parse, max_messages=None, max_seconds=None, **kwargs):
        calls.update(max_messages=max_messages, max_seconds=max_seconds)
        yield obs("alpha-widget.example.com")
        yield obs("alphabet.example.com")

    monkeypatch.setattr(certstream, "stream_websocket", fake_stream)
    out = tmp_path / "o.jsonl"
    argv = ["certstream", "--url", "wss://feed.example.com/", "--max-seconds", "30", "--terms", str(terms), "--out", str(out)]
    assert cli.main(argv) == 0
    assert calls == {"max_messages": None, "max_seconds": 30.0}
    assert names_in(out) == ["alpha-widget.example.com", "alphabet.example.com"]
    assert cli.main([*argv, "--label-boundary"]) == 0
    assert names_in(out) == ["alpha-widget.example.com"]


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_stream_rejects_bad_max_seconds(tmp_path, value):
    argv = ["certstream", "--url", "ws://127.0.0.1:1/", "--max-seconds", value, "--out", str(tmp_path / "o.jsonl")]
    assert cli.main(argv) == 2
