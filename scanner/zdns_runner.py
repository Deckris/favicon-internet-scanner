"""Batched ZDNS stage.

One zdns invocation per (module, chunk of names); never one process per name.
Names are validated by the caller; this module only runs the tool and turns its
JSON lines into plain records. zdns writes JSON results to stdout and progress
text to stderr, so only stdout is parsed.

Output format pinned against zdns v2.1.1 (github.com/zmap/zdns): one JSON object
per input name, ``{"name": <input>, "results": {<MODULE>: {"status", "data":
{"answers": [{"type", "name", "answer"}...]}, "error"?}}}``. CNAME records that
were followed appear in ``answers`` ahead of the terminal A/AAAA/PTR records.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from scanner.models import ToolJob, stable_id

Executor = Callable[..., Any]

MODULES = ("A", "AAAA", "PTR")
# zdns statuses that mean "the resolver gave a definite DNS answer".
DEFINITE_STATUSES = frozenset({"NOERROR", "NXDOMAIN", "NODATA"})
_TIMEOUT_STATUSES = frozenset({"TIMEOUT", "ITERATIVE_TIMEOUT"})


def _norm(name: str | None) -> str:
    return (name or "").strip().rstrip(".").lower()


@dataclass(frozen=True)
class ZdnsAnswer:
    name: str                     # the queried name exactly as given (hostname or IP for PTR)
    module: str
    status: str                   # NOERROR | NXDOMAIN | SERVFAIL | TIMEOUT | ... | NO_OUTPUT | TOOL_ERROR | PARSE_ERROR
    records: tuple[tuple[str, str, str], ...] = ()   # (type, owner, answer) all normalized, no trailing dots
    error: str | None = None
    resolver: str | None = None
    raw_sha256: str = ""


def parse_zdns_line(line: str, module: str) -> ZdnsAnswer | None:
    """Parse one stdout line; ``None`` if it carries no usable name."""
    sha = hashlib.sha256(line.encode("utf-8")).hexdigest()
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict) or not isinstance(obj.get("name"), str):
        return None
    name = obj["name"]
    try:
        result = ((obj.get("results") or {}).get(module)) or {}
        status = str(result.get("status") or "PARSE_ERROR")
        data = result.get("data") or {}
        records: list[tuple[str, str, str]] = []
        for ans in data.get("answers") or []:
            if not isinstance(ans, dict):
                continue
            rtype = str(ans.get("type") or "").upper()
            records.append((rtype, _norm(ans.get("name")), _norm(str(ans.get("answer") or ""))))
        error = result.get("error")
        return ZdnsAnswer(
            name=name, module=module, status=status, records=tuple(records),
            error=str(error) if error else None, resolver=data.get("resolver"), raw_sha256=sha,
        )
    except Exception as exc:  # malformed shape: keep the name, flag the line
        return ZdnsAnswer(name=name, module=module, status="PARSE_ERROR", error=str(exc), raw_sha256=sha)


def _chunks(items: list[str], size: int) -> list[list[str]]:
    size = max(1, size)
    return [items[i:i + size] for i in range(0, len(items), size)]


def run_zdns(
    module: str,
    names: list[str],
    *,
    nameservers: list[str],
    run_dir: Path,
    threads: int = 100,
    timeout: float = 10.0,
    retries: int = 2,
    network_timeout: float = 5.0,
    chunk_size: int = 50_000,
    binary: str = "zdns",
    executor: Executor = subprocess.run,
) -> tuple[list[ToolJob], dict[str, ZdnsAnswer]]:
    """Run ``zdns <module>`` over ``names``; every input gets an answer record."""
    if module not in MODULES:
        raise ValueError(f"unsupported zdns module {module!r}")
    if not nameservers:
        raise ValueError("zdns requires explicit nameservers (the system resolver is never used)")
    unique = sorted(set(names))
    raw_dir = Path(run_dir) / "raw" / "zdns"
    raw_dir.mkdir(parents=True, exist_ok=True)

    jobs: list[ToolJob] = []
    answers: dict[str, ZdnsAnswer] = {}
    for chunk in _chunks(unique, chunk_size):
        job_id = stable_id("ZDNS", module, chunk[:1], len(chunk), len(jobs))
        output_path = raw_dir / f"{job_id}.jsonl"
        command = [
            binary, module,
            "--name-servers", ",".join(nameservers),
            "--threads", str(threads),
            # --timeout bounds one whole name (including retries); keep it above the per-try budget.
            "--timeout", str(int(timeout)),
            "--retries", str(retries),
            "--network-timeout", str(int(network_timeout)),    # per-try; the default (2s) is too tight for cold PTR lookups
        ]
        started_at = datetime.now(UTC).isoformat()
        try:
            result = executor(command, input="".join(f"{n}\n" for n in chunk), capture_output=True, text=True, check=False)
            stdout = getattr(result, "stdout", "") or ""
            exit_code = getattr(result, "returncode", None)
            stderr = (getattr(result, "stderr", "") or "").strip()
        except Exception as exc:  # binary missing / OS error: every name becomes TOOL_ERROR
            stdout, exit_code, stderr = "", -1, f"{type(exc).__name__}: {exc}"
        finished_at = datetime.now(UTC).isoformat()
        output_path.write_text(stdout, encoding="utf-8")

        parsed = 0
        for line in stdout.split("\n"):
            if not line.strip():
                continue
            ans = parse_zdns_line(line, module)
            if ans is None:
                continue
            parsed += 1
            answers[ans.name] = ans
        tool_error = None
        if exit_code not in (0, None):
            tool_error = stderr[-500:] or f"zdns exited {exit_code}"
        for name in chunk:
            if name not in answers:
                answers[name] = ZdnsAnswer(
                    name=name, module=module,
                    status="TOOL_ERROR" if tool_error else "NO_OUTPUT", error=tool_error,
                )
        jobs.append(ToolJob(
            job_id=job_id, tool="zdns", purpose=f"{module}", command=tuple(command),
            input_count=len(chunk), output_count=parsed, exit_code=exit_code,
            raw_path=str(output_path.relative_to(run_dir)),
            raw_sha256=hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            started_at=started_at, finished_at=finished_at, error=tool_error,
        ))
    return jobs, answers


@dataclass(frozen=True)
class Resolution:
    """Forward resolution of one hostname, derived from the A and AAAA answers."""
    hostname: str
    status: str                       # resolved | nxdomain | servfail | timeout | no_answer | cname_loop | too_many_cnames | tool_error | refused
    cname_chain: tuple[str, ...] = ()
    a: tuple[str, ...] = ()
    aaaa: tuple[str, ...] = ()
    error: str | None = None


def _walk(records: tuple[tuple[str, str, str], ...], start: str, rtype: str, max_cnames: int) -> tuple[str, list[str], list[str]]:
    """Follow CNAMEs from ``start``; return (state, chain, terminal answers)."""
    cnames = {owner: target for t, owner, target in records if t == "CNAME"}
    chain: list[str] = []
    seen = {start}
    cur = start
    while cur in cnames:
        nxt = cnames[cur]
        if nxt in seen:
            return "cname_loop", chain + [nxt], []
        seen.add(nxt)
        chain.append(nxt)
        if len(chain) > max_cnames:
            return "too_many_cnames", chain, []
        cur = nxt
    return "ok", chain, sorted({ans for t, owner, ans in records if t == rtype and owner == cur})


def resolve(hostname: str, a_ans: ZdnsAnswer | None, aaaa_ans: ZdnsAnswer | None, *, max_cnames: int = 8) -> Resolution:
    """Combine the A and AAAA answers for one hostname into a single verdict."""
    if a_ans is None:
        return Resolution(hostname, "tool_error", error="no A answer")
    status = a_ans.status
    if status in ("TOOL_ERROR", "NO_OUTPUT", "PARSE_ERROR"):
        return Resolution(hostname, "tool_error", error=a_ans.error or status)
    if status == "NXDOMAIN":
        return Resolution(hostname, "nxdomain")
    if status in _TIMEOUT_STATUSES:
        return Resolution(hostname, "timeout", error=a_ans.error)
    if status != "NOERROR" and status != "NODATA":
        # SERVFAIL, REFUSED, ... -- not a definite name answer.
        return Resolution(hostname, "servfail" if status == "SERVFAIL" else "tool_error", error=a_ans.error or status)
    key = _norm(hostname)
    state, chain, a = _walk(a_ans.records, key, "A", max_cnames)
    if state != "ok":
        return Resolution(hostname, state, cname_chain=tuple(chain))
    aaaa: list[str] = []
    if aaaa_ans is not None and aaaa_ans.status in ("NOERROR", "NODATA"):
        a_state, a_chain, aaaa = _walk(aaaa_ans.records, key, "AAAA", max_cnames)
        if a_state != "ok":
            aaaa = []
        if not chain:
            chain = a_chain
    if not a and not aaaa:
        return Resolution(hostname, "no_answer", cname_chain=tuple(chain))
    return Resolution(hostname, "resolved", cname_chain=tuple(chain), a=tuple(a), aaaa=tuple(aaaa))


def ptr_names(answer: ZdnsAnswer | None) -> list[str]:
    if answer is None or answer.status != "NOERROR":
        return []
    return sorted({ans for t, _owner, ans in answer.records if t == "PTR" and ans})


__all__ = ["ZdnsAnswer", "Resolution", "run_zdns", "parse_zdns_line", "resolve", "ptr_names", "MODULES"]
