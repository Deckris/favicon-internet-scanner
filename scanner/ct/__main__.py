"""Collect hostnames from Certificate Transparency sources into a local table of observations.

    python -m scanner.ct crtsh --start 2026-01-01T00:00 --end 2026-01-01T01:00 --user-agent "name (mailto:you@example.com)" --out obs.jsonl
    python -m scanner.ct certstream --url wss://certstream.example.com/ --max-messages 1000 --out obs.jsonl
    python -m scanner.ct import --crtsh-export export.csv --out obs.jsonl
    python -m scanner.ct filter --in obs.jsonl --terms terms.txt --out filtered.jsonl
    python -m scanner.ct names --in obs.jsonl --out ct_names.txt
    python -m scanner.ct log-coverage --watched logs.txt --fetch

Exit codes: 0 ok, 1 runtime error, 2 usage error. Nothing here is read by the scanner unless the ``ct_names``
config section points at the names file.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import math
import signal
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

FLUSH_EVERY = 5000
FLUSH_SECONDS = 60.0

POLITENESS_CRTSH = (
    "crt.sh is a shared public service: at most one statement per {gap:g} s, at most {cap} statements per run, "
    "back-off on connection errors. The identifying string, with its contact, is sent as the PostgreSQL "
    "application_name."
)
POLITENESS_STREAM = (
    "live feed: you must pass the feed URL yourself; reconnects back off, "
    "and only names that match --terms are kept when it is given."
)


class UsageError(Exception):
    pass


def _say(text: str) -> None:
    print(text, file=sys.stderr)


def _utc(text: str) -> datetime:
    try:
        value = datetime.fromisoformat(text)
    except ValueError as exc:
        raise UsageError(f"not an ISO 8601 time: {text!r}") from exc
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _flatten(items):
    """Yield observations whether a source yields one per item or a list per item."""
    for item in items:
        if isinstance(item, (list, tuple)):
            yield from item
        else:
            yield item


def _add_outputs(p: argparse.ArgumentParser) -> None:
    p.add_argument("--out", type=Path, required=True, help="observation table (JSON Lines)")
    p.add_argument("--names-out", type=Path, help="also write the distinct names, one per line")


def _write_outputs(table, args) -> int | None:
    """Write the table and, when asked, the names file; returns the number of names written."""
    from scanner.ct.names import write_names

    table.to_jsonl(args.out)
    if args.names_out:
        return write_names(args.names_out, table.names())
    return None


def _summary(table, args, extra: str = "") -> str:
    parts = [f"{len(table)} observations -> {args.out}"]
    if args.names_out:
        parts.append(f"{len(table.names())} names -> {args.names_out}")
    if extra:
        parts.append(extra)
    return "; ".join(parts)


def _finish(table, args, *, extra: str = "") -> int:
    _write_outputs(table, args)
    _say(_summary(table, args, extra))
    return 0


def _term_filter(path, label_boundary: bool):
    from scanner.ct.terms import TermFilter

    try:
        return TermFilter.from_file(path, label_boundary=label_boundary)
    except ValueError as exc:
        raise UsageError(f"--terms: {exc}") from exc


def _apply_terms(table, args, label_boundary: bool = False):
    from scanner.ct.models import ObservationTable

    if not getattr(args, "terms", None):
        return table
    flt = _term_filter(args.terms, label_boundary)
    kept = ObservationTable()
    kept.extend(flt.filter(table))
    return kept


@contextlib.contextmanager
def _graceful_stop():
    """Turn SIGTERM into ``KeyboardInterrupt`` for the duration, so a terminated run still writes its table."""
    def handler(signum, frame):
        raise KeyboardInterrupt

    try:
        previous = signal.signal(signal.SIGTERM, handler)
    except (ValueError, OSError):   # not the main thread
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def _collect(args, items, flt, *, handled: dict | None = None, interrupt_is_error: bool):
    """Read ``items`` into a table. The table and names file are written however the read ends.

    Periodic writes (every ``FLUSH_EVERY`` new rows or ``FLUSH_SECONDS``) keep a long run from losing everything.
    Returns ``(table, seen, error)``; ``handled`` maps exception classes to a message, any other exception is
    re-raised after the write.
    """
    from scanner.ct.models import ObservationTable

    table = ObservationTable()
    seen = 0
    error = None
    last_rows, last_time = 0, time.monotonic()
    try:
        with _graceful_stop():
            for obs in _flatten(items):
                seen += 1
                if flt is None or flt.matches(obs.name):
                    table.add(obs)
                if len(table) - last_rows >= FLUSH_EVERY or time.monotonic() - last_time >= FLUSH_SECONDS:
                    if len(table) != last_rows:
                        table.to_jsonl(args.out)
                    last_rows, last_time = len(table), time.monotonic()
    except KeyboardInterrupt:
        if interrupt_is_error:
            error = "interrupted"
        else:
            _say("interrupted, writing what was collected")
    except BaseException as exc:
        label = next((text for cls, text in (handled or {}).items() if isinstance(exc, cls)), None)
        if label is None:
            raise
        error = f"{label}: {exc}"
    finally:
        _write_outputs(table, args)
    return table, seen, error


def _cmd_crtsh(args) -> int:
    from scanner.ct import crtsh

    try:
        crtsh.validate_identifier(args.user_agent)
    except ValueError as exc:
        raise UsageError(f"--user-agent: {exc}") from exc
    if not math.isfinite(args.min_gap) or args.min_gap < 1.0:
        raise UsageError("--min-gap must be a finite number of at least 1 second")
    if args.statement_cap < 1:
        raise UsageError("--statement-cap must be at least 1")
    start, end = _utc(args.start), _utc(args.end)
    if end <= start:
        raise UsageError("--end must be after --start")
    flt = _term_filter(args.terms, args.label_boundary) if args.terms else None
    _say(POLITENESS_CRTSH.format(gap=args.min_gap, cap=args.statement_cap))
    try:
        source = crtsh.CrtShWindows(
            connect=lambda: crtsh.default_connect(args.user_agent), user_agent=args.user_agent,
            min_gap_s=args.min_gap, statement_cap=args.statement_cap,
        )
    except ValueError as exc:
        raise UsageError(str(exc)) from exc
    try:
        table, seen, error = _collect(args, source.iter_window(start, end), flt,
                                      handled={crtsh.StatementCapReached: "statement cap reached",
                                                       crtsh.StatementFailed: "statement failed"},
                                      interrupt_is_error=True)
    finally:
        close = getattr(source, "close", None)
        if close:
            close()
    problems = list(getattr(source, "errors", []))
    _say(_summary(table, args, f"{seen} read"))
    for problem in problems:
        _say(problem)
    if error:
        _say(f"{error}; the result is incomplete")
        return 1
    if problems:
        _say("some windows were skipped; the result is incomplete")
        return 1
    return 0


def _cmd_stream(args, kind: str) -> int:
    from scanner.ct import certstream

    if not args.url.lower().startswith(("ws://", "wss://")):
        raise UsageError("--url must be a ws:// or wss:// address")
    if args.max_messages is not None and args.max_messages < 1:
        raise UsageError("--max-messages must be at least 1")
    if args.max_seconds is not None and (not math.isfinite(args.max_seconds) or args.max_seconds <= 0):
        raise UsageError("--max-seconds must be a positive, finite number")
    parse = certstream.parse_certstream if kind == "certstream" else certstream.parse_zonestream
    flt = _term_filter(args.terms, args.label_boundary) if args.terms else None
    _say(POLITENESS_STREAM)
    feed = certstream.stream_websocket(args.url, parse=parse, max_messages=args.max_messages, max_seconds=args.max_seconds)
    table, seen, _ = _collect(args, feed, flt, interrupt_is_error=False)
    _say(_summary(table, args, f"{seen} read"))
    return 0


def _cmd_import(args) -> int:
    from scanner.ct import importers

    table = importers.load_crtsh_export(args.crtsh_export)
    total = len(table)
    table = _apply_terms(table, args)
    return _finish(table, args, extra=f"{total} read")


def _cmd_filter(args) -> int:
    from scanner.ct.models import ObservationTable

    table = ObservationTable.from_jsonl(args.input)
    total = len(table)
    table = _apply_terms(table, args, label_boundary=args.label_boundary)
    return _finish(table, args, extra=f"{total} read")


def _cmd_names(args) -> int:
    from scanner.ct.models import ObservationTable
    from scanner.ct.names import write_names

    table = ObservationTable.from_jsonl(args.input)
    written = write_names(args.out, table.names())
    _say(f"{len(table)} observations, {written} names -> {args.out}")
    return 0


def _read_watched(path: Path) -> list[str]:
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    return [line for line in lines if line and not line.startswith("#")]


def _cmd_log_coverage(args) -> int:
    from scanner.ct import logcoverage

    watched = _read_watched(args.watched)
    log_list = logcoverage.fetch_log_list() if args.fetch else logcoverage.load_log_list(args.log_list)
    result = logcoverage.compare(watched, log_list)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for key in ("covered", "missing", "unknown"):
            print(f"{key}: {len(result[key])}")
            for item in result[key]:
                print(f"  {item['url'] if isinstance(item, dict) else item}")
    _say(
        f"{len(watched)} watched: {len(result['covered'])} covered, "
        f"{len(result['missing'])} missing, {len(result['unknown'])} unknown"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m scanner.ct", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    c = sub.add_parser("crtsh", help="query crt.sh over a time window, one minute at a time")
    c.add_argument("--start", required=True, help="window start, ISO 8601 (UTC if no zone)")
    c.add_argument("--end", required=True, help="window end, ISO 8601 (UTC if no zone)")
    c.add_argument("--user-agent", required=True, help="identifying string with a contact e-mail or URL, sent as the PostgreSQL application_name")
    c.add_argument("--min-gap", type=float, default=1.0, help="seconds between statements (minimum and default 1)")
    c.add_argument("--statement-cap", type=int, default=5000, help="statements one run may send before it stops")
    c.add_argument("--terms", type=Path, help="keep only names that match a term in this file")
    c.add_argument("--label-boundary", action="store_true", help="match terms only at label or hyphen boundaries")
    _add_outputs(c)
    c.set_defaults(handler=_cmd_crtsh)

    for kind in ("certstream", "zonestream"):
        s = sub.add_parser(kind, help=f"read names from a {kind} websocket feed")
        s.add_argument("--url", required=True, help="ws:// or wss:// address of the feed (no default)")
        s.add_argument("--max-messages", type=int, help="stop after this many messages")
        s.add_argument("--max-seconds", type=float, help="stop after this many seconds")
        s.add_argument("--terms", type=Path, help="keep only names that match a term in this file")
        s.add_argument("--label-boundary", action="store_true", help="match terms only at label or hyphen boundaries")
        _add_outputs(s)
        s.set_defaults(handler=lambda a, k=kind: _cmd_stream(a, k))

    i = sub.add_parser("import", help="load a crt.sh export file")
    i.add_argument("--crtsh-export", type=Path, required=True)
    i.add_argument("--terms", type=Path, help="keep only names that match a term in this file")
    _add_outputs(i)
    i.set_defaults(handler=_cmd_import)

    f = sub.add_parser("filter", help="keep the observations whose name matches a term")
    f.add_argument("--in", dest="input", type=Path, required=True)
    f.add_argument("--terms", type=Path, required=True)
    f.add_argument("--label-boundary", action="store_true", help="match terms only at label or hyphen boundaries")
    _add_outputs(f)
    f.set_defaults(handler=_cmd_filter)

    n = sub.add_parser("names", help="write the names file for the scanner's ct_names section")
    n.add_argument("--in", dest="input", type=Path, required=True)
    n.add_argument("--out", type=Path, required=True)
    n.set_defaults(handler=_cmd_names)

    g = sub.add_parser("log-coverage", help="compare the logs you watch with the published log list")
    g.add_argument("--watched", type=Path, required=True, help="one log URL per line")
    src = g.add_mutually_exclusive_group(required=True)
    src.add_argument("--log-list", type=Path, help="a saved copy of the log list")
    src.add_argument("--fetch", action="store_true", help="download the current log list")
    g.add_argument("--json", action="store_true", help="print the result as JSON on stdout")
    g.set_defaults(handler=_cmd_log_coverage)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        return args.handler(args)
    except UsageError as exc:
        _say(f"error: {exc}")
        return 2
    except KeyboardInterrupt:
        _say("interrupted")
        return 1
    except Exception as exc:  # noqa: BLE001 - any runtime failure is reported as exit code 1
        _say(f"error: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
