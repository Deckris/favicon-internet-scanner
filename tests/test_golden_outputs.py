"""Frozen run outputs: end-to-end scenarios compared with the files under tests/golden/.

The record files are compared byte for byte. Run directories also hold wall-clock times, absolute
temporary paths and thread-ordered logs; `_scrub` and `_collect` name every field they touch and
leave everything else alone. Regenerate the goldens deliberately with REGEN_GOLDEN=1.
"""
import hashlib
import io
import json
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.internet import outputs, pipeline
from scanner.internet.config import load_config
from tests.helpers import FakeFetcher, write_config
from tests.test_enrich import MIXED, ONE, TARPIT, _tarpit_config
from tests.test_pipeline import IP_DEAD, IP_ELSE, IP_HTTP, IP_OK, IP_STRICT, tools

GOLDEN = Path(__file__).parent / "golden"

# Written as-is by the pipeline, in a fixed order: compared as raw bytes.
EXACT = (
    "normalized/endpoints.jsonl", "normalized/hostname_resolution.jsonl",
    "normalized/policy_refusals.jsonl", "ip_results.csv", "scanned_ips.txt", "favicons/index.jsonl",
)
# JSON documents that carry times or paths: compared after `_scrub`.
SCRUBBED_JSON = ("manifest.json", "report/summary.json", "config.snapshot.json")
SCRUBBED_JSONL = ("normalized/tool_jobs.jsonl",)
# Favicon workers append in completion order; the set of lines is what is deterministic.
SORTED_LINES = ("raw/favicon_records.jsonl",)
TIME_KEYS = {"started_at", "finished_at", "elapsed_seconds"}
# Hold times, paths or free-disk figures, so their checksums in the manifest are not stable. Every
# other file, raw tool output and stored icons included, is pinned by its checksum there.
VOLATILE = {"config.snapshot.json", "preflight.json", "normalized/tool_jobs.jsonl", "raw/favicon_records.jsonl",
            "report/summary.json"}


def _png(shade: int) -> bytes:
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), (shade, 30, 30)).save(buf, format="PNG")
    return buf.getvalue()


class ShadeFetcher(FakeFetcher):
    """Serves a titled page and one of two icons by address, so the same icon shows up on several IPs."""

    def fetch(self, url, *, connect_ip, kind, context=""):
        from scanner.models import FetchResult
        self.calls.append((url, connect_ip, kind))
        is_icon = kind == "favicon"
        shade = 40 if (connect_ip or "").rsplit(".", 1)[-1] in {"1", "2", "4", "6"} else 200
        title = "Café 日本" if "xn--" in url or "ü" in url else "Shop"
        body = _png(shade) if is_icon else f'<html><head><title>{title}</title><link rel="icon" href="/fav.png"></head></html>'.encode()
        return FetchResult(
            kind=kind, requested_url=url, connect_ip=connect_ip, host_header=None, sni=None, outcome="ok",
            failure_category=None, http_status=200, content_type="image/png" if is_icon else "text/html",
            content_encoding=None, retry_after=None, body_sha256=hashlib.sha256(body).hexdigest(), body_bytes=len(body),
            redirect_chain=(), final_url=url, certificate=None,
        ), body


def _setup_mixed(tmp):
    ft = tools(
        l4={443: [IP_OK, IP_STRICT, IP_ELSE, "1.1.1.9"], 80: [IP_HTTP, "1.1.1.9"], 8080: [IP_DEAD, "1.1.1.9", IP_OK]},
        tls={(IP_OK, 443): "ok", (IP_STRICT, 443): "strict", (IP_ELSE, 443): "ok", (IP_HTTP, 80): "plain", (IP_DEAD, 8080): "reset",
             ("1.1.1.9", 443): "ok", ("1.1.1.9", 80): "plain", ("1.1.1.9", 8080): "nonhttp", (IP_OK, 8080): "ok"},
        tls_sni={(IP_OK, "good.test"): "ok", (IP_STRICT, "edge.shop.example"): "ok", ("1.1.1.9", "other.test"): "ok"},
        http={(IP_HTTP, 80): 200, ("1.1.1.9", 80): 301},
        ptr={IP_OK: ["good.test."], IP_STRICT: ["edge.shop.example."], "1.1.1.9": ["other.test.", "mail.other.test."]},
        a={"good.test": [IP_OK], "edge.shop.example": [IP_STRICT], "other.test": ["1.1.1.9"], "mail.other.test": ["1.1.1.9", "9.9.9.77"]},
        nxdomain={"www.good.test"},
    )
    return load_config(write_config(tmp)), ft, ShadeFetcher()


def _setup_tarpit(tmp):
    ft = tools(
        l4={80: [TARPIT, MIXED, ONE], 443: [TARPIT, MIXED], 8080: [TARPIT, MIXED]},
        tls={(TARPIT, 80): "reset", (TARPIT, 443): "reset", (TARPIT, 8080): "reset",
             (MIXED, 80): "reset", (MIXED, 443): "ok", (MIXED, 8080): "reset", (ONE, 80): "reset"},
        tls_sni={}, http={}, ptr={}, a={}, nxdomain=set())
    ft.windows[(MIXED, 80)] = 0
    return _tarpit_config(tmp), ft, ShadeFetcher()


def _setup_zmap_fails(tmp):
    ft = tools()
    orig = ft._zmap

    def flaky(c):
        if "--dryrun" not in c and c[c.index("-p") + 1] == "80":
            raise OSError("zmap exploded")
        return orig(c)
    ft._zmap = flaky
    return load_config(write_config(tmp)), ft, ShadeFetcher()


def _setup_tls_tool_crash(tmp):
    ft = tools()
    orig = ft._zgrab

    def crash_tls(c, stdin):
        if c[1] == "tls":
            return SimpleNamespace(returncode=2, stdout="", stderr="zgrab2 segfault")
        return orig(c, stdin)
    ft._zgrab = crash_tls
    return load_config(write_config(tmp)), ft, ShadeFetcher()


def _setup_zero_responsive(tmp):
    return load_config(write_config(tmp)), tools(l4={}), ShadeFetcher()


def _setup_non_ascii(tmp):
    ft = tools(
        ptr={IP_OK: ["bücher.test.", "xn--bcher-kva.test."], IP_STRICT: ["日本語.example.", "edge.shop.example."],
             IP_ELSE: ["bad\ud800name.test."]},
        a={"bücher.test": [IP_OK], "xn--bcher-kva.test": [IP_OK], "xn--wgv71a119e.example": [IP_STRICT],
           "edge.shop.example": [IP_STRICT], "good.test": [IP_OK]},
        tls_sni={(IP_OK, "good.test"): "ok", (IP_OK, "xn--bcher-kva.test"): "ok", (IP_STRICT, "edge.shop.example"): "ok"},
    )
    return load_config(write_config(tmp)), ft, ShadeFetcher()


SCENARIOS = {
    "mixed": _setup_mixed,
    "tarpit": _setup_tarpit,
    "zmap_port_fails": _setup_zmap_fails,
    "tls_tool_crash": _setup_tls_tool_crash,
    "zero_responsive": _setup_zero_responsive,
    "non_ascii_names": _setup_non_ascii,
}


def _scrub(value, tmp: Path):
    """Replace the fields that differ between runs of identical input.

    Times become "<time>", per-stage durations become 0, the config checksum (it covers the temporary
    paths) becomes "<config>", and the absolute temporary directory becomes "<tmp>" with path
    separators unified. Nothing else is altered.
    """
    roots = sorted({str(tmp), tmp.as_posix()}, key=len, reverse=True)

    def walk(v, key=None):
        if isinstance(v, dict):
            if key == "stage_seconds":
                return {k: 0.0 for k in v}
            return {k: walk(x, k) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if key in TIME_KEYS:
            return "<time>"
        if key == "config_checksum":
            return "<config>"
        if isinstance(v, str):
            for r in roots:
                v = v.replace(r, "<tmp>")
            return v.replace("\\", "/") if "<tmp>" in v or key == "raw_path" else v
        return v
    return walk(value)


def _dump(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _lf(raw: bytes) -> bytes:
    return raw.replace(b"\r\n", b"\n")


def _collect(run_dir: Path, tmp: Path) -> dict[str, bytes]:
    """The comparable form of one run directory, keyed by relative path."""
    out: dict[str, bytes] = {}
    files = sorted(str(p.relative_to(run_dir)).replace("\\", "/") for p in run_dir.rglob("*") if p.is_file())
    out["files.txt"] = ("".join(f + "\n" for f in files)).encode()
    for rel in EXACT:
        if (run_dir / rel).exists():
            out[rel] = _lf((run_dir / rel).read_bytes())
    for rel in SCRUBBED_JSON:
        doc = json.loads((run_dir / rel).read_text(encoding="utf-8"))
        if rel == "manifest.json":
            doc["output_checksums"] = {k: v for k, v in doc["output_checksums"].items() if k not in VOLATILE}
        out[rel] = _dump(_scrub(doc, tmp))
    for rel in SCRUBBED_JSONL:
        lines = [_scrub(json.loads(l), tmp) for l in (run_dir / rel).read_text(encoding="utf-8").splitlines()]
        out[rel] = b"".join(json.dumps(l, sort_keys=True, ensure_ascii=False).encode() + b"\n" for l in lines)
    for rel in SORTED_LINES:
        if (run_dir / rel).exists():
            out[rel] = b"".join(l + b"\n" for l in sorted(_lf((run_dir / rel).read_bytes()).splitlines()))
    # The Markdown report repeats the stage times and error text of summary.json
    md = (run_dir / "report" / "summary.md").read_text(encoding="utf-8")
    summary = json.loads((run_dir / "report" / "summary.json").read_text(encoding="utf-8"))
    for stage in summary.get("stage_seconds", {}):
        md = re.sub(rf'("{re.escape(stage)}": )[0-9.eE+-]+', r"\g<1>0.0", md)
    for r in sorted({str(tmp), tmp.as_posix()}, key=len, reverse=True):
        md = md.replace(r, "<tmp>")
    out["report/summary.md"] = _lf(md.encode("utf-8"))
    return out


def run_scenario_dir(name: str, tmp: Path) -> Path:
    tmp.mkdir(parents=True, exist_ok=True)
    cfg, ft, fetcher = SCENARIOS[name](tmp)
    return pipeline.run(cfg, run_id="t1", executor=ft, fetcher=fetcher, skip_preflight=True, offline_preflight=True)


def run_scenario(name: str, tmp: Path) -> dict[str, bytes]:
    return _collect(run_scenario_dir(name, tmp), tmp)


# Raw tool output and stored icons are pinned by checksum, and those bytes depend on the platform's
# newline handling in the fakes and on the image library build, so the goldens are kept for Linux.
@pytest.mark.skipif(os.name != "posix", reason="golden files are generated on Linux")
@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_run_outputs_match_golden(name, tmp_path):
    got = run_scenario(name, tmp_path)
    base = GOLDEN / name
    if os.environ.get("REGEN_GOLDEN") == "1":
        for rel, data in got.items():
            p = base / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        pytest.skip(f"golden files for {name} regenerated")
    assert base.is_dir(), f"no golden files for {name}; generate them with REGEN_GOLDEN=1"
    expected = {str(p.relative_to(base)).replace("\\", "/") for p in base.rglob("*") if p.is_file()}
    assert set(got) == expected
    for rel in sorted(got):
        assert got[rel] == (base / rel).read_bytes(), f"{name}: {rel} differs from the golden copy"


def test_scenarios_cover_the_expected_shapes(tmp_path):
    """Guards the goldens themselves: they must keep exercising the cases they were chosen for."""
    got = run_scenario("mixed", tmp_path)
    rows = list(outputs.iter_hostname_rows(run_scenario_dir("mixed", tmp_path / "again")))
    assert {r["port"] for r in rows} >= {80, 443, 8080}
    assert {"verified", "resolved_elsewhere", "nxdomain"} <= {r["final_hostname_status"] for r in rows}
    assert any(r["sni_confirmation_attempted"] for r in rows)
    icons = [json.loads(l) for l in got["favicons/index.jsonl"].splitlines()]
    assert len(icons) == 2 and any(len(i["observations"]) > 1 for i in icons)
