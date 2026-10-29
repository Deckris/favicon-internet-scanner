"""Scale and memory benchmark for a whole run (not collected by pytest).

    BENCH_SIZES=5000,10000 BENCH_OUT=bench.json python tests/bench_scale_memory.py

Synthesises N responsive addresses (443 and 80 on all of them, 8080 on every tenth, a PTR name,
forward record and SNI handshake on every fifth, a page and one of 16 icons per endpoint) behind the
scripted tools, with no fetch latency and per-address pacing off. Each size is run twice: once
untraced for wall times, once under tracemalloc for allocation peaks, because tracing slows the run
several-fold. Peaks are Python allocations; the process peak is reported separately.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
if "tests" not in sys.modules or not hasattr(sys.modules["tests"], "__path__"):
    _spec = importlib.util.spec_from_loader("tests", loader=None, is_package=True)
    _pkg = importlib.util.module_from_spec(_spec)
    _pkg.__path__ = [str(ROOT / "tests")]
    sys.modules["tests"] = _pkg

from scanner.internet import pipeline                      # noqa: E402
from scanner.internet.config import load_config            # noqa: E402
from scanner.models import FetchResult                     # noqa: E402
from tests.helpers import FakeFetcher, FakeTools, write_config   # noqa: E402

CERT_HOST = "good.test"


def address(i: int) -> str:
    return f"23.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"


class BenchFetcher(FakeFetcher):
    """A page and one of 16 icons per request, instantly."""

    def __init__(self) -> None:
        super().__init__()
        from PIL import Image
        self.icons = []
        for shade in range(16):
            buf = io.BytesIO()
            Image.new("RGB", (16, 16), (shade * 15, 30, 30)).save(buf, format="PNG")
            self.icons.append(buf.getvalue())

    def fetch(self, url, *, connect_ip, kind, context=""):
        is_icon = kind == "favicon"
        n = sum(int(p) for p in (connect_ip or "0.0.0.0").split("."))
        body = self.icons[n % 16] if is_icon else b'<html><head><title>Bench</title><link rel="icon" href="/fav.png"></head></html>'
        return FetchResult(
            kind=kind, requested_url=url, connect_ip=connect_ip, host_header=None, sni=None, outcome="ok",
            failure_category=None, http_status=200, content_type="image/png" if is_icon else "text/html",
            content_encoding=None, retry_after=None, body_sha256=hashlib.sha256(body).hexdigest(), body_bytes=len(body),
            redirect_chain=(), final_url=url, certificate=None,
        ), body


def build_tools(n: int) -> FakeTools:
    l4: dict[int, list[str]] = {80: [], 443: [], 8080: []}
    tls: dict[tuple[str, int], str] = {}
    sni: dict[tuple[str, str], str] = {}
    http: dict[tuple[str, int], int | None] = {}
    ptr: dict[str, list[str]] = {}
    a: dict[str, list[str]] = {}
    for i in range(n):
        ip = address(i)
        l4[443].append(ip)
        l4[80].append(ip)
        tls[(ip, 443)] = "ok"
        tls[(ip, 80)] = "plain"
        http[(ip, 80)] = 200
        if i % 10 == 0:
            l4[8080].append(ip)
            tls[(ip, 8080)] = "reset"
        if i % 5 == 0:
            name = f"h{i}.bench.test"
            ptr[ip] = [name + "."]
            a[name] = [ip]
            sni[(ip, name)] = "ok"
    return FakeTools(l4=l4, tls=tls, tls_sni=sni, http=http, ptr=ptr, a=a)


def process_peak_mib() -> float | None:
    try:
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(peak / (1024 if sys.platform != "darwin" else 1024 * 1024), 1)
    except ImportError:
        pass
    try:
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t)]
        c = Counters()
        c.cb = ctypes.sizeof(c)
        k32 = ctypes.WinDLL("kernel32")
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi = ctypes.WinDLL("psapi")
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(c), c.cb)
        return round(c.PeakWorkingSetSize / 1048576, 1)
    except Exception:
        return None


# The record-building and write-out calls inside pipeline.run, measured one by one under tracemalloc.
PHASES = ("_write_records", "_write_ip_results", "write_jsonl", "_summarize", "_summary_md")


def instrument(phases: dict[str, dict[str, float]]):
    """Wrap the record and write-out functions; return a function that restores them."""
    saved = {}
    for name in PHASES:
        fn = getattr(pipeline, name)
        saved[name] = fn

        def wrapper(*args, __fn=fn, __name=name, **kw):
            tracemalloc.reset_peak()
            before = tracemalloc.get_traced_memory()[0]
            t0 = time.perf_counter()
            try:
                return __fn(*args, **kw)
            finally:
                peak = tracemalloc.get_traced_memory()[1]
                rec = phases.setdefault(__name, {"calls": 0, "seconds": 0.0, "peak_mib": 0.0, "held_before_mib": 0.0, "growth_peak_mib": 0.0})
                rec["calls"] += 1
                rec["seconds"] = round(rec["seconds"] + time.perf_counter() - t0, 3)
                rec["peak_mib"] = round(max(rec["peak_mib"], peak / 1048576), 1)
                rec["held_before_mib"] = round(max(rec["held_before_mib"], before / 1048576), 1)
                rec["growth_peak_mib"] = round(max(rec["growth_peak_mib"], (peak - before) / 1048576), 1)
        setattr(pipeline, name, wrapper)

    def restore():
        for name, fn in saved.items():
            setattr(pipeline, name, fn)
    return restore


def sizes_of(run_dir: Path) -> dict[str, int]:
    out: dict[str, int] = {}
    for p in run_dir.rglob("*"):
        if p.is_file():
            top = p.relative_to(run_dir).parts[0] if len(p.relative_to(run_dir).parts) > 1 else p.name
            out[top] = out.get(top, 0) + p.stat().st_size
    out["total"] = sum(v for k, v in out.items())
    return out


def one_run(n: int, traced: bool, keep: Path | None) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="bench-"))
    try:
        cfg = load_config(write_config(tmp))
        tools = build_tools(n)
        fetcher = BenchFetcher()
        phases: dict[str, dict[str, float]] = {}
        restore = instrument(phases) if traced else (lambda: None)
        if traced:
            tracemalloc.start()
        t0 = time.perf_counter()
        try:
            run_dir = pipeline.run(cfg, run_id="bench", executor=tools, fetcher=fetcher, skip_preflight=True, offline_preflight=True)
            wall = time.perf_counter() - t0
            peak = tracemalloc.get_traced_memory()[1] / 1048576 if traced else None
        finally:
            restore()
            if traced:
                tracemalloc.stop()
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        res = {
            "wall_seconds": round(wall, 2), "stage_seconds": manifest["stage_seconds"], "complete": manifest["complete"],
            "stage_errors": manifest["stage_errors"], "endpoints": manifest["stage_counts"].get("l4_endpoints"),
            "output_bytes": sizes_of(run_dir),
        }
        if traced:
            res["tracemalloc_peak_mib"] = round(peak, 1)
            res["phases"] = phases
        if keep:
            shutil.copytree(run_dir, keep, dirs_exist_ok=True)
        return res
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def table(results: list[dict]) -> str:
    stages = list(results[0]["timed"]["stage_seconds"]) if results else []
    lines = []
    head = ["N", "endpoints", "wall s", "traced wall s", "py peak MiB", "records+write peak MiB", "proc peak MiB", "output MiB", "normalized MiB"]
    lines.append(" | ".join(head))
    for r in results:
        t, m = r["timed"], r["traced"]
        rec_peak = max((p["peak_mib"] for p in m["phases"].values()), default=0.0)
        lines.append(" | ".join(str(x) for x in (
            r["n"], t["endpoints"], t["wall_seconds"], m["wall_seconds"], m["tracemalloc_peak_mib"], rec_peak,
            r.get("process_peak_mib"), round(t["output_bytes"]["total"] / 1048576, 1), round(t["output_bytes"].get("normalized", 0) / 1048576, 1))))
    lines.append("")
    lines.append("stage seconds (untraced): " + " | ".join(["N"] + stages))
    for r in results:
        lines.append(" | ".join([str(r["n"])] + [str(r["timed"]["stage_seconds"].get(s, "")) for s in stages]))
    lines.append("")
    lines.append("record / write-out calls under tracemalloc (peak MiB, held before MiB, seconds):")
    for r in results:
        for name, p in r["traced"]["phases"].items():
            lines.append(f"  N={r['n']} {name}: peak {p['peak_mib']} held-before {p['held_before_mib']} growth {p['growth_peak_mib']} {p['seconds']}s x{p['calls']}")
    return "\n".join(lines)


def main() -> None:
    sizes = [int(s) for s in os.environ.get("BENCH_SIZES", "5000,10000,20000").split(",") if s.strip()]
    keep_dir = os.environ.get("BENCH_KEEP")
    results = []
    for n in sizes:
        print(f"[bench] N={n} untraced", flush=True)
        timed = one_run(n, False, Path(keep_dir) / str(n) if keep_dir else None)
        process_peak = process_peak_mib()          # before the traced run; sizes ascend, so it is this size's peak
        print(f"[bench] N={n} traced", flush=True)
        traced = one_run(n, True, None)
        results.append({"n": n, "timed": timed, "traced": traced, "process_peak_mib": process_peak})
    print()
    print(table(results))
    out = os.environ.get("BENCH_OUT")
    if out:
        Path(out).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nwritten {out}")


if __name__ == "__main__":
    main()
