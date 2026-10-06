"""ZGrab2 batched L7 characterization stage.

ZGrab2 is invoked once per chunk of ``cfg.measurement.zgrab_batch_size``
targets sharing the same (scheme, mode, port) key -- never once per target.
Pinned ZGrab2 version: v1.0.0 (commit ea734bcf60ef2921684cb522dfb87a07a322afa6,
https://github.com/zmap/zgrab2/releases/tag/v1.0.0). Input lines use the
ZGrab2 CSV form ``IP, DOMAIN, TAG, PORT`` documented in that tag's README and
``target.go`` (field order fixed; TAG/PORT may be blank).
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

from scanner.models import CertificateInfo, ToolJob, ZGrabResult, stable_id

# Go network errors name the local ephemeral port ("tcp 192.0.2.10:59130->");
# it changes on every run and carries no measurement meaning.
_EPHEMERAL_SOURCE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):\d+->")


def _stable_error(message: Any) -> Any:
    return _EPHEMERAL_SOURCE.sub(r"\1->", message) if isinstance(message, str) else message

Executor = Callable[..., Any]

# zgrab2 http module status strings (zgrab2_schemas/zgrab2/zgrab2.py, pinned tag).
_TIMEOUT_STATUSES = frozenset({"connection-timeout", "io-timeout"})


@dataclass(frozen=True)
class ZGrabTarget:
    ip: str
    hostname: str | None
    port: int


def _chunks(items: list[Any], size: int) -> list[list[Any]]:
    if size <= 0:
        size = 1
    return [items[i:i + size] for i in range(0, len(items), size)]


def _input_line(target: ZGrabTarget) -> str:
    return f"{target.ip},{target.hostname or ''},,{target.port}"


def _first_header(headers: dict[str, Any] | None, name: str) -> str | None:
    if not headers:
        return None
    value = headers.get(name)
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _parse_der_lazy():
    try:
        from scanner.certificates import parse_der
    except Exception:
        return None
    return parse_der


def _parse_line(
    line: str,
    *,
    job_id: str,
    scheme: str,
    mode: str,
    port: int,
    observed_at: str,
) -> ZGrabResult:
    raw_sha = hashlib.sha256(line.encode("utf-8")).hexdigest()
    try:
        obj = json.loads(line)
        top = (obj.get("data") or {}).get("http") or {}
        status = top.get("status") or "parse_error"
        zgrab_error = _stable_error(top.get("error"))
        result = top.get("result") or {}
        response = result.get("response") or {}
        request = response.get("request") or {}
        tls_log = request.get("tls_log") or {}
        handshake_log = tls_log.get("handshake_log") or {}
        server_certs = handshake_log.get("server_certificates") or {}
        cert_obj = server_certs.get("certificate") or {}
        raw_der_b64 = cert_obj.get("raw")
        chain_entries = server_certs.get("chain") or []

        target_ip = obj.get("ip") or ""
        request_hostname = obj.get("domain") or None
        sni_hostname = request_hostname if scheme == "https" else None

        http_status = response.get("status_code")
        content_type = _first_header(response.get("headers"), "content_type")
        content_encoding = _first_header(response.get("headers"), "content_encoding")
        location = _first_header(response.get("headers"), "location")
        body = response.get("body")
        body_sha256 = response.get("body_sha256")
        body_bytes = len(body.encode("utf-8")) if isinstance(body, str) else response.get("body_size")

        tls_handshake_ok: bool | None = None
        tls_error: str | None = None
        if scheme == "https":
            tls_handshake_ok = bool(raw_der_b64) or status == "success"
            if status != "success":
                tls_error = zgrab_error

        certificate: CertificateInfo | None = None
        if raw_der_b64:
            parse_der = _parse_der_lazy()
            if parse_der is not None:
                der = base64.b64decode(raw_der_b64)
                chain = tuple(
                    base64.b64decode(entry["raw"])
                    for entry in chain_entries
                    if isinstance(entry, dict) and entry.get("raw")
                )
                try:
                    certificate = parse_der(
                        der,
                        handshake_mode=mode,
                        sni_sent=sni_hostname,
                        observed_at=datetime.now(UTC),
                        chain=chain,
                        target_ip=target_ip,
                        port=port,
                    )
                except Exception:
                    certificate = None

        return ZGrabResult(
            zgrab_job_id=job_id,
            target_ip=target_ip,
            port=port,
            scheme_attempted=scheme,
            acquisition_mode=mode,
            request_hostname=request_hostname,
            sni_hostname=sni_hostname,
            status=status,
            http_status=http_status,
            content_type=content_type,
            content_encoding=content_encoding,
            location=location,
            body_sha256=body_sha256,
            body_bytes=body_bytes,
            tls_handshake_ok=tls_handshake_ok,
            tls_error=tls_error,
            certificate=certificate,
            error=zgrab_error,
            raw_line_sha256=raw_sha,
        )
    except Exception as exc:
        return ZGrabResult(
            zgrab_job_id=job_id,
            target_ip="",
            port=port,
            scheme_attempted=scheme,
            acquisition_mode=mode,
            request_hostname=None,
            sni_hostname=None,
            status="parse_error",
            http_status=None,
            content_type=None,
            content_encoding=None,
            location=None,
            body_sha256=None,
            body_bytes=None,
            tls_handshake_ok=None,
            tls_error=None,
            certificate=None,
            error=str(exc),
            raw_line_sha256=raw_sha,
        )


def run_zgrab_batches(
    targets: list[ZGrabTarget],
    *,
    scheme: str,
    mode: str,
    cfg: Any,
    policy: Any,
    run_dir: Path,
    executor: Executor = subprocess.run,
) -> tuple[list[ToolJob], list[ZGrabResult]]:
    if mode == "hostname_aware":
        for target in targets:
            if not target.hostname:
                raise ValueError("hostname_aware targets must have a hostname")

    allowed: list[ZGrabTarget] = []
    for target in targets:
        if policy.check_ip(target.ip, stage="zgrab", context=f"zgrab:{mode}:{scheme}:port={target.port}") is not None:
            continue
        if target.hostname and policy.check_hostname(target.hostname, stage="zgrab", context=f"zgrab:{mode}:{scheme}") is not None:
            continue
        allowed.append(target)

    allowed.sort(key=lambda t: (t.ip, t.port, t.hostname or ""))

    by_port: dict[int, list[ZGrabTarget]] = {}
    for target in allowed:
        by_port.setdefault(target.port, []).append(target)

    raw_dir = Path(run_dir) / "raw" / "zgrab"
    raw_dir.mkdir(parents=True, exist_ok=True)
    batch_size = cfg.measurement.zgrab_batch_size

    jobs: list[ToolJob] = []
    results: list[ZGrabResult] = []

    for port in sorted(by_port):
        for chunk in _chunks(by_port[port], batch_size):
            job_id = stable_id("ZGRAB", scheme, mode, port, [(t.ip, t.hostname, t.port) for t in chunk])
            input_text = "".join(_input_line(t) + "\n" for t in chunk)
            output_path = raw_dir / f"{job_id}.jsonl"

            command = [
                "zgrab2", "http",
                "--port", str(port),
                "--user-agent", cfg.fetch.user_agent,
                "--max-redirects", "0",
                "--connect-timeout", f"{cfg.measurement.zgrab_connect_timeout}s",
                "--target-timeout", f"{cfg.measurement.zgrab_target_timeout}s",
                "--senders", str(cfg.measurement.zgrab_senders),
                # Without this, zgrab2's default ("-") resolves to
                # $HOME/.config/zgrab2/blocklist.conf; on a container/host where
                # that file does not exist it fatally aborts before scanning
                # anything (verified against the pinned v1.0.0 binary). An
                # explicit empty value disables the blocklist entirely -- target
                # safety is enforced upstream by scanner.safety.TargetPolicy.
                "--blocklist-file=",
            ]
            if scheme == "https":
                command.append("--use-https")

            started_at = datetime.now(UTC).isoformat()
            result = executor(command, input=input_text, capture_output=True, text=True, check=False)
            finished_at = datetime.now(UTC).isoformat()

            stdout = getattr(result, "stdout", "") or ""
            output_path.write_text(stdout, encoding="utf-8")
            raw_sha256 = hashlib.sha256(stdout.encode("utf-8")).hexdigest()

            chunk_results = [
                _parse_line(line, job_id=job_id, scheme=scheme, mode=mode, port=port, observed_at=finished_at)
                for line in stdout.split("\n")
                if line.strip()
            ]

            exit_code = getattr(result, "returncode", None)
            error = None
            if exit_code not in (0, None):
                error = (getattr(result, "stderr", "") or "").strip() or f"zgrab2 exited {exit_code}"

            jobs.append(ToolJob(
                job_id=job_id,
                tool="zgrab2",
                purpose=f"{mode}:{scheme}:port={port}",
                command=tuple(command),
                input_count=len(chunk),
                output_count=len(chunk_results),
                exit_code=exit_code,
                raw_path=str(output_path.relative_to(run_dir)),
                raw_sha256=raw_sha256,
                started_at=started_at,
                finished_at=finished_at,
                error=error,
            ))
            results.extend(chunk_results)

    return jobs, results


__all__ = ["ZGrabTarget", "run_zgrab_batches"]
