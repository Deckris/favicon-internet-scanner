"""TLS-first characterization via ``zgrab2 tls`` (handshake only, no HTTP).

Direct-IP mode sends no SNI; SNI-confirmation mode sends the verified hostname.
The tls module keeps the server certificate whenever the handshake completes,
including when the service is not HTTP -- the ``http --use-https`` module drops
it in that case, which is why it is not used here.

Error strings were captured from zgrab2 (commit ea734bcf, v1.0.0) against local
fixtures; see ``classify`` for the mapping.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from scanner.certificates import parse_der
from scanner.models import CertificateInfo, ToolJob, stable_id

Executor = Callable[..., Any]

_EPHEMERAL = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):\d+->")

# Outcome labels (stable, documented in the runbook).
OK = "tls_success"
ALERT_UNRECOGNIZED_NAME = "tls_alert_unrecognized_name"
ALERT_OTHER = "tls_alert_other"
CLOSED = "tls_close"
RESET = "tls_reset"
TIMEOUT = "tls_timeout"
CONNECT_TIMEOUT = "tcp_connect_failed"
VERSION = "tls_version_incompatible"
NO_CIPHER = "tls_no_cipher"
NOT_TLS = "not_tls"
PARSE_ERROR = "tls_parse_error"
OTHER = "tls_other_error"


@dataclass(frozen=True)
class TlsResult:
    ip: str
    port: int
    sni: str | None
    zgrab_status: str
    outcome: str
    error: str | None
    tls_version: str | None
    cipher_suite: str | None
    certificate: CertificateInfo | None
    cert_parse_error: str | None
    raw_line_sha256: str

    @property
    def ok(self) -> bool:
        return self.outcome == OK


def classify(status: str, error: str | None, has_handshake: bool) -> str:
    if has_handshake and status == "success":
        return OK
    text = (error or "").lower()
    if "unrecognized name" in text:
        return ALERT_UNRECOGNIZED_NAME
    if ("first record does not look like a tls handshake" in text or "oversized record" in text
            or "received record with version" in text):
        return NOT_TLS
    if "protocol version" in text or "unsupported versions" in text or "no supported versions" in text:
        return VERSION
    if "no cipher" in text or "insufficient security" in text or "no mutually supported" in text:
        return NO_CIPHER
    if "remote error: tls:" in text:
        return ALERT_OTHER
    if "connection reset" in text:
        return RESET
    if status == "connection-timeout":
        return CONNECT_TIMEOUT
    if "i/o timeout" in text or "deadline exceeded" in text or status == "io-timeout" and "eof" not in text:
        return TIMEOUT
    if text.endswith("eof") or "eof" in text.split(":")[-1]:
        return CLOSED
    return OTHER


def parse_line(line: str, *, port: int, sni: str | None, mode: str) -> TlsResult:
    sha = hashlib.sha256(line.encode("utf-8")).hexdigest()
    try:
        obj = json.loads(line)
        ip = obj.get("ip") or ""
        node = (obj.get("data") or {}).get("tls") or {}
        status = str(node.get("status") or "parse_error")
        error = node.get("error")
        error = _EPHEMERAL.sub(r"\1->", error) if isinstance(error, str) else None
        result = node.get("result") or {}
        hl = result.get("handshake_log") or {}
        hello = hl.get("server_hello") or {}
        certs = hl.get("server_certificates") or {}
        raw_b64 = (certs.get("certificate") or {}).get("raw")
        version = ((hello.get("supported_versions") or {}).get("selected_version") or hello.get("version") or {}).get("name")
        cipher = (hello.get("cipher_suite") or {}).get("name")
        cert: CertificateInfo | None = None
        cert_err: str | None = None
        if raw_b64:
            try:
                chain = tuple(base64.b64decode(c["raw"]) for c in (certs.get("chain") or []) if isinstance(c, dict) and c.get("raw"))
                cert = parse_der(
                    base64.b64decode(raw_b64), handshake_mode=mode, sni_sent=sni,
                    observed_at=datetime.now(UTC), chain=chain, target_ip=ip, port=port,
                )
            except Exception as exc:   # malformed certificate: keep the failure, keep going
                cert_err = f"{type(exc).__name__}: {exc}"[:300]
        outcome = classify(status, error, bool(hl))
        if outcome == OK and cert is None and cert_err:
            outcome = OK   # handshake worked; the parser error is retained separately
        return TlsResult(ip, port, sni, status, outcome, error, version, cipher, cert, cert_err, sha)
    except Exception as exc:
        return TlsResult("", port, sni, "parse_error", PARSE_ERROR, str(exc)[:300], None, None, None, None, sha)


def _chunks(items: list[Any], size: int) -> list[list[Any]]:
    size = max(1, size)
    return [items[i:i + size] for i in range(0, len(items), size)]


def run_tls_batches(
    targets: list[tuple[str, int, str | None]],
    *,
    mode: str,                    # "direct_ip" (no SNI) | "hostname_aware" (SNI = hostname)
    cfg: Any,
    policy: Any,
    run_dir: Path,
    binary: str = "zgrab2",
    executor: Executor = subprocess.run,
) -> tuple[list[ToolJob], list[TlsResult]]:
    """Batched ``zgrab2 tls``: one process per (port, chunk). Targets are (ip, port, hostname|None)."""
    if mode == "hostname_aware" and any(not t[2] for t in targets):
        raise ValueError("hostname_aware targets must carry a hostname")
    if mode == "direct_ip" and any(t[2] for t in targets):
        raise ValueError("direct_ip targets must not carry a hostname")
    allowed: list[tuple[str, int, str | None]] = []
    for ip, port, host in targets:
        if policy.check_ip(ip, stage="zgrab", context=f"tls:{mode}:port={port}") is not None:
            continue
        if host and policy.check_hostname(host, stage="zgrab", context=f"tls:{mode}") is not None:
            continue
        allowed.append((ip, port, host))
    allowed = sorted(set(allowed), key=lambda t: (t[1], t[0], t[2] or ""))

    raw_dir = Path(run_dir) / "raw" / "zgrab"
    raw_dir.mkdir(parents=True, exist_ok=True)
    by_port: dict[int, list[tuple[str, int, str | None]]] = {}
    for t in allowed:
        by_port.setdefault(t[1], []).append(t)

    jobs: list[ToolJob] = []
    results: list[TlsResult] = []
    for port in sorted(by_port):
        for chunk in _chunks(by_port[port], cfg.measurement.zgrab_batch_size):
            job_id = stable_id("ZGRABTLS", mode, port, [(t[0], t[2]) for t in chunk])
            out_path = raw_dir / f"{job_id}.jsonl"
            command = [
                binary, "tls", "--port", str(port),
                "--connect-timeout", f"{cfg.measurement.zgrab_connect_timeout}s",
                "--target-timeout", f"{cfg.measurement.zgrab_target_timeout}s",
                "--senders", str(cfg.measurement.zgrab_senders),
                "--blocklist-file=",    # target safety is enforced by TargetPolicy upstream
            ]
            started = datetime.now(UTC).isoformat()
            input_text = "".join(f"{ip},{host or ''},,{port}\n" for ip, port, host in chunk)
            try:
                proc = executor(command, input=input_text, capture_output=True, text=True, check=False)
                stdout = getattr(proc, "stdout", "") or ""
                code = getattr(proc, "returncode", None)
                stderr = (getattr(proc, "stderr", "") or "").strip()
            except Exception as exc:
                stdout, code, stderr = "", -1, f"{type(exc).__name__}: {exc}"
            finished = datetime.now(UTC).isoformat()
            out_path.write_text(stdout, encoding="utf-8")
            chunk_results: list[TlsResult] = []
            wanted = {(ip, host or None) for ip, _p, host in chunk}
            for line in stdout.split("\n"):
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    key = (obj.get("ip") or "", obj.get("domain") or None)
                except (ValueError, AttributeError):
                    key = ("", None)
                res = parse_line(line, port=port, sni=key[1], mode=mode)
                if key in wanted and not res.ip:
                    # Valid JSON for a wanted target but an unexpected shape: keep the target attached to its record.
                    res = TlsResult(key[0], port, key[1], res.zgrab_status, PARSE_ERROR, res.error, None, None, None, None, res.raw_line_sha256)
                if key in wanted:
                    wanted.discard(key)
                    chunk_results.append(res)
                elif key[0]:
                    # Unexpected extra line for a known target: keep the first, ignore duplicates.
                    continue
                else:
                    chunk_results.append(res)   # unparseable line: retained as a parse-error record
            # Every target must end with a record, even if the tool died or dropped it.
            error = (stderr[-500:] or f"zgrab2 exited {code}") if code not in (0, None) else None
            for ip, host in sorted(wanted, key=lambda k: (k[0], k[1] or "")):
                chunk_results.append(TlsResult(ip, port, host, "no_output", OTHER, error or "no output from zgrab2", None, None, None, None, ""))
            jobs.append(ToolJob(
                job_id=job_id, tool="zgrab2", purpose=f"tls:{mode}:port={port}", command=tuple(command),
                input_count=len(chunk), output_count=len(chunk_results), exit_code=code,
                raw_path=str(out_path.relative_to(run_dir)), raw_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
                started_at=started, finished_at=finished, error=error,
            ))
            results.extend(chunk_results)
    return jobs, results


__all__ = ["TlsResult", "run_tls_batches", "parse_line", "classify", "OK", "NOT_TLS"]
