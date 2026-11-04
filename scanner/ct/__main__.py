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
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

POLITENESS_CRTSH = (
    "crt.sh is a shared public service: at most one statement per {gap:g} s, a contact in the User-Agent "
    "is required, at most {cap} rows per statement, with back-off on errors."
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


def _finish(table, args, *, extra: str = "") -> int:
    from scanner.ct.names import write_names

    table.to_jsonl(args.out)
    written = None
    if args.names_out:
        written = write_names(args.names_out, table.names())
    parts = [f"{len(table)} observations -> {args.out}"]
    if written is not None:
        parts.append(f"{written} names -> {args.names_out}")
    if extra:
        parts.append(extra)
    _say("; ".join(parts))
    return 0


def _apply_terms(table, args, label_boundary: bool = False):
    from scanner.ct.models import ObservationTable
    from scanner.ct.terms import TermFilter

    if not getattr(args, "terms", None):
        return table
    flt = TermFilter.from_file(args.terms, label_boundary=label_boundary)
    kept = ObservationTable()
    kept.extend(flt.filter(table))
    return kept


def _cmd_crtsh(args) -> int:
    from scanner.ct import crtsh
    from scanner.ct.models import ObservationTable
    from scanner.ct.terms import TermFilter

    if not args.user_agent.strip():
        raise UsageError("--user-agent must carry a contact")
    if args.min_gap < 1.0:
        raise UsageError("--min-gap must be at least 1 second")
    if args.statement_cap < 1:
        raise UsageError("--statement-cap must be at least 1")
    start, end = _utc(args.start), _utc(args.end)
    if end <= start:
        raise UsageError("--end must be after --start")
    flt = TermFilter.from_file(args.terms, label_boundary=args.label_boundary) if args.terms else None
    _say(POLITENESS_CRTSH.format(gap=args.min_gap, cap=args.statement_cap))
    source = crtsh.CrtShWindows(
        connect=crtsh.default_connect, user_agent=args.user_agent, min_gap_s=args.min_gap, statement_cap=args.statement_cap
    )
    table = ObservationTable()
    seen = 0
    error = None
    try:
        for obs in _flatten(source.iter_window(start, end)):
            seen += 1
            if flt is None or flt.matches(obs.name):
                table.add(obs)
    except crtsh.StatementCapReached as exc:
        error = f"statement cap reached, window incomplete: {exc}"
    except KeyboardInterrupt:
        error = "interrupted"
    status = _finish(table, args, extra=f"{seen} read")
    if error:
        _say(error)
        return 1
    return status


def _cmd_stream(args, kind: str) -> int:
    from scanner.ct import certstream
    from scanner.ct.models import ObservationTable
    from scanner.ct.terms import TermFilter

    if not args.url.lower().startswith(("ws://", "wss://")):
        raise UsageError("--url must be a ws:// or wss:// address")
    if args.max_messages is not None and args.max_messages < 1:
        raise UsageError("--max-messages must be at least 1")
    parse = certstream.parse_certstream if kind == "certstream" else certstream.parse_zonestream
    flt = TermFilter.from_file(args.terms) if args.terms else None
    _say(POLITENESS_STREAM)
    table = ObservationTable()
    seen = 0
    try:
        for obs in _flatten(certstream.stream_websocket(args.url, parse=parse, max_messages=args.max_messages)):
            seen += 1
            if flt is None or flt.matches(obs.name):
                table.add(obs)
    except KeyboardInterrupt:
        _say("interrupted, writing what was collected")
    return _finish(table, args, extra=f"{seen} read")


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
                print(f"  {item}")
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
    c.add_argument("--user-agent", required=True, help="identifies you to crt.sh; include a contact address")
    c.add_argument("--min-gap", type=float, default=1.0, help="seconds between statements (minimum and default 1)")
    c.add_argument("--statement-cap", type=int, default=5000, help="rows one statement may return before the window is split")
    c.add_argument("--terms", type=Path, help="keep only names that match a term in this file")
    c.add_argument("--label-boundary", action="store_true", help="match terms only at label or hyphen boundaries")
    _add_outputs(c)
    c.set_defaults(handler=_cmd_crtsh)

    for kind in ("certstream", "zonestream"):
        s = sub.add_parser(kind, help=f"read names from a {kind} websocket feed")
        s.add_argument("--url", required=True, help="ws:// or wss:// address of the feed (no default)")
        s.add_argument("--max-messages", type=int, help="stop after this many messages")
        s.add_argument("--terms", type=Path, help="keep only names that match a term in this file")
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
