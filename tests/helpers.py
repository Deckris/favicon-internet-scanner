"""Shared helpers for the scanner tests: config builder and fake external tools."""
from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

from scanner.internet.config import sha256_file

FIX = Path(__file__).parent / "fixtures" / "scan"


def fixture_line(rel: str) -> dict[str, Any]:
    return json.loads((FIX / rel).read_text(encoding="utf-8").splitlines()[0])


def write_exclusions(tmp: Path, text: str = "# opt-out\n8.8.4.0/24\n") -> Path:
    p = tmp / "exclusions.txt"
    p.write_text(text, encoding="utf-8")
    return p


def write_approval(tmp: Path, excl: Path, **over: Any) -> Path:
    data = {
        "schema_version": 1, "status": "approved", "approval_reference": "TEST-REF-1",
        "operations": ["hostname_resolution", "favicon_fetch"],
        "approved_domains": ["example.com"], "target_population": "sample of IPv4",
        "exclusions_checksum": sha256_file(excl), "ports": [80, 443, 8080, 8090],
        "protocols": ["http", "https"], "max_rate_per_second": 1000,
        "source_addresses": ["93.184.216.99"], "transparency_url": "https://example.org/scan",
        "opt_out_contact": "optout@example.org", "data_handling_reference": "dh-1",
        "incident_contact": "inc@example.org", "valid_until": "2099-01-01T00:00:00+00:00",
        "max_sample_fraction": 0.0001,
    }
    data.update(over)
    p = tmp / "approval.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return p


def config_dict(tmp: Path, excl: Path, approval: Path, **over: Any) -> dict[str, Any]:
    cfg = {
        "run_label": "test",
        "vantage": {"id": "test-vantage", "interface": "eth0", "source_ipv4": "192.168.1.10", "public_egress_ip": "93.184.216.99"},
        "sample": {"fraction": 0.0001, "seed": 4},
        "measurement": {"ports": [80, 443, 8080], "zmap_rate": 100, "zmap_max_runtime": 100000, "zmap_cooldown": 8,
                        "zmap_probes": 2, "zgrab_connect_timeout": 4.0, "zgrab_target_timeout": 8.0,
                        "zgrab_senders": 10, "zgrab_batch_size": 500, "min_seconds_between_probes_per_ip": 0},
        "target_policy": {"exclusions_file": str(excl), "exclusions_sha256": sha256_file(excl), "approval_file": str(approval),
                          "hostname_policy": {"mode": "any_public", "suffixes": []}},
        "dns": {"resolvers": ["9.9.9.9:53", "1.1.1.1"], "timeout": 5, "retries": 2, "threads": 10, "max_cnames": 8},
        "hostnames": {"max_candidates_per_ip": 20},
        "sni_confirm": {"enabled": True, "max_per_endpoint": 3},
        "favicon": {"enabled": True, "max_hostnames_per_endpoint": 3, "workers": 2, "max_icons_per_page": 4},
        "fetch": {"connect_timeout": 4.0, "read_timeout": 8.0, "total_timeout": 15.0, "max_document_bytes": 1048576,
                  "max_favicon_bytes": 524288, "max_decoded_bytes": 4194304, "max_redirects": 3,
                  "user_agent": "scanner-research-scanner (+https://example.org/scan; contact optout@example.org)"},
        "transparency": {"info_url": "https://example.org/scan", "contact": "optout@example.org"},
        "output": {"dir": str(tmp / "out")},
        "operations": {"kill_switch_file": str(tmp / "KILL")},
    }
    for k, v in over.items():
        cfg[k] = v
    return cfg


def write_config(tmp: Path, **over: Any) -> Path:
    excl = write_exclusions(tmp)
    approval = write_approval(tmp, excl)
    p = tmp / "scanner.yaml"
    p.write_text(yaml.safe_dump(config_dict(tmp, excl, approval, **over)), encoding="utf-8")
    return p


# ---------------------------------------------------------------- fake external tools

def _tls_line(ip: str, port: int, domain: str | None, kind: str) -> str:
    """Build a zgrab2-tls-shaped line from the real captured fixtures."""
    template = {"ok": "zgrab_tls/ok.jsonl", "nonhttp": "zgrab_tls/nonhttp_ok.jsonl",
                "strict": "zgrab_tls/strict_no_sni.jsonl", "close": "zgrab_tls/silent_close.jsonl",
                "reset": "zgrab_tls/reset.jsonl", "hang": "zgrab_tls/hang.jsonl",
                "plain": "zgrab_tls/plain_http.jsonl", "refused": "zgrab_tls/closed_port.jsonl"}[kind]
    obj = fixture_line(template)
    obj["ip"], obj["port"] = ip, port
    if domain:
        obj["domain"] = domain
    return json.dumps(obj)


class FakeTools:
    """Routes zmap / zgrab2 / zdns invocations to scripted answers. Records every command."""

    def __init__(self, *, l4: dict[int, list[str]], tls: dict[tuple[str, int], str], tls_sni: dict[tuple[str, str], str],
                 http: dict[tuple[str, int], int | None], ptr: dict[str, list[str]], a: dict[str, list[str]],
                 aaaa: dict[str, list[str]] | None = None, cnames: dict[str, list[str]] | None = None,
                 nxdomain: set[str] = frozenset(), zmap_rc: int = 0) -> None:
        self.l4, self.tls, self.tls_sni, self.http = l4, tls, tls_sni, http
        self.ptr, self.a, self.aaaa, self.cnames, self.nx = ptr, a, aaaa or {}, cnames or {}, set(nxdomain)
        self.zmap_rc = zmap_rc
        self.windows: dict[tuple[str, int], int] = {}      # SYN-ACK window per endpoint (default: a normal 64240)
        self.commands: list[list[str]] = []
        self.zdns_inputs: dict[str, list[str]] = {}

    def __call__(self, command: list[str], **kw: Any) -> Any:
        self.commands.append(list(command))
        tool = Path(command[0]).name
        if tool == "zmap":
            return self._zmap(command)
        if tool == "zgrab2":
            return self._zgrab(command, kw.get("input", ""))
        if tool == "zdns":
            return self._zdns(command, kw.get("input", ""))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def _zmap(self, c: list[str]) -> Any:
        if "--dryrun" in c:            # sample listing: print the targets, send nothing
            ips = sorted({ip for v in self.l4.values() for ip in v} | set(getattr(self, "extra_sample", [])))
            text = "".join(f"ip {{ saddr: 192.168.1.10 | daddr: {ip} | checksum: 0X0 }}\n" for ip in ips)
            return SimpleNamespace(returncode=0, stdout="", stderr=text)
        port = int(c[c.index("-p") + 1])
        out = Path(c[c.index("-o") + 1])
        assert c[c.index("-f") + 1].split(",")[0] == "saddr"          # the address must stay the first column
        out.write_text("".join(f"{ip},{self.windows.get((ip, port), 64240)},64\n" for ip in self.l4.get(port, [])), encoding="utf-8")
        return SimpleNamespace(returncode=self.zmap_rc, stdout="", stderr="" if not self.zmap_rc else "zmap boom")

    def _zgrab(self, c: list[str], stdin: str) -> Any:
        module = c[1]
        lines = []
        for row in stdin.splitlines():
            ip, domain, _tag, port = (row.split(",") + ["", "", "", ""])[:4]
            port = int(port)
            if module == "tls":
                kind = self.tls_sni.get((ip, domain)) if domain else self.tls.get((ip, port), "refused")
                lines.append(_tls_line(ip, port, domain or None, kind or "close"))
            else:
                status = self.http.get((ip, port))
                if status is None:
                    lines.append(json.dumps({"ip": ip, "data": {"http": {"status": "connection-timeout", "error": "no http"}}}))
                else:
                    lines.append(json.dumps({"ip": ip, "data": {"http": {"status": "success", "result": {"response": {
                        "status_code": status, "headers": {"content_type": ["text/html"]}, "body": "<html></html>"}}}}}))
        return SimpleNamespace(returncode=0, stdout="\n".join(lines) + ("\n" if lines else ""), stderr="")

    def _zdns(self, c: list[str], stdin: str) -> Any:
        module = c[1]
        names = [n for n in stdin.splitlines() if n]
        self.zdns_inputs.setdefault(module, []).extend(names)
        lines = []
        for n in names:
            lines.append(json.dumps(self._answer(module, n)))
        return SimpleNamespace(returncode=0, stdout="\n".join(lines) + "\n", stderr="")

    def _answer(self, module: str, name: str) -> dict[str, Any]:
        def wrap(status: str, answers: list[dict[str, str]]) -> dict[str, Any]:
            data: dict[str, Any] = {"resolver": "9.9.9.9:53", "protocol": "udp"}
            if answers:
                data["answers"] = answers
            return {"name": name, "results": {module: {"status": status, "data": data}}}
        if module == "PTR":
            hosts = self.ptr.get(name, [])
            if not hosts:
                return wrap("NXDOMAIN", [])
            return wrap("NOERROR", [{"type": "PTR", "name": "x.in-addr.arpa", "answer": h + "."} for h in hosts])
        if name in self.nx:
            return wrap("NXDOMAIN", [])
        table = self.a if module == "A" else self.aaaa
        rtype = module
        answers: list[dict[str, str]] = []
        owner = name
        for hop in self.cnames.get(name, []):
            answers.append({"type": "CNAME", "name": owner, "answer": hop + "."})
            owner = hop
        for ip in table.get(name, []):
            answers.append({"type": rtype, "name": owner, "answer": ip})
        return wrap("NOERROR", answers)


def make_png() -> bytes:
    import io
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), (200, 30, 30)).save(buf, format="PNG")
    return buf.getvalue()


class FakeFetcher:
    """Stands in for WebFetcher: serves an HTML page and a PNG favicon for any URL."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None, str]] = []

    def fetch(self, url: str, *, connect_ip: str | None, kind: str, context: str = ""):
        from scanner.models import FetchResult
        self.calls.append((url, connect_ip, kind))
        is_icon = kind == "favicon"
        body = make_png() if is_icon else b'<html><head><link rel="icon" href="/fav.png"></head></html>'
        return FetchResult(
            kind=kind, requested_url=url, connect_ip=connect_ip, host_header=None, sni=None, outcome="ok",
            failure_category=None, http_status=200, content_type="image/png" if is_icon else "text/html",
            content_encoding=None, retry_after=None, body_sha256="x" * 64, body_bytes=len(body),
            redirect_chain=(), final_url=url, certificate=None,
        ), body
