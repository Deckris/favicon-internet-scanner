"""Hostname-aware, IP-pinned HTTP(S) acquisition layer.

The client always opens its TCP connection to a caller-supplied IP while the
HTTP ``Host`` header and TLS SNI carry the measured hostname, so document and
favicon acquisition never depends on local DNS resolution. Every destination
and redirect hop clears the central :class:`~scanner.safety.TargetPolicy`
before a socket is opened. This replaces a hand-written parser
with a standards-capable client while keeping full control over bytes read,
decoding and timing so slow-drip and decompression-bomb fixtures stay bounded.
"""
from __future__ import annotations

import gzip
import hashlib
import ipaddress
import threading
import time
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable
from urllib.parse import urljoin, urlsplit

import httpx

from scanner.models import CertificateInfo, FetchResult, RedirectHop
from scanner.safety import TargetPolicy

try:
    import brotli
except ImportError:  # pragma: no cover - optional at import time, required at runtime
    brotli = None

DEFAULT_PORTS = {"http": 80, "https": 443}
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True)
class FetchLimits:
    connect_timeout: float
    read_timeout: float
    total_timeout: float
    max_bytes: int
    max_decoded_bytes: int
    max_redirects: int


@runtime_checkable
class Resolver(Protocol):
    def resolve_a(self, hostname: str) -> list[str]:
        """Current A-record answers for ``hostname``, or ``[]``/raise on failure."""


class _TooLarge(Exception):
    def __init__(self, outcome: str) -> None:
        super().__init__(outcome)
        self.outcome = outcome


class _StreamDecoder:
    """Incremental content-encoding decoder bounded by ``max_decoded``."""

    def __init__(self, encoding: str | None, max_decoded: int) -> None:
        self._max_decoded = max_decoded
        self._total = 0
        self._encoding = (encoding or "identity").strip().lower()
        self._zlib: zlib.decompressobj | None = None
        self._brotli = None
        if self._encoding in ("gzip", "x-gzip"):
            self._zlib = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif self._encoding == "deflate":
            self._zlib = zlib.decompressobj()
        elif self._encoding == "br":
            if brotli is None:
                raise _TooLarge("unsupported_encoding")
            self._brotli = brotli.Decompressor()
        elif self._encoding not in ("identity", ""):
            raise _TooLarge("unsupported_encoding")

    def feed(self, chunk: bytes) -> bytes:
        if self._zlib is not None:
            out = self._zlib.decompress(chunk, self._max_decoded - self._total + 1)
            while self._zlib.unconsumed_tail and self._total + len(out) <= self._max_decoded:
                out += self._zlib.decompress(self._zlib.unconsumed_tail, self._max_decoded - self._total - len(out) + 1)
        elif self._brotli is not None:
            room = self._max_decoded - self._total + 1
            out = self._brotli.process(chunk, output_buffer_limit=room)
            while not self._brotli.can_accept_more_data() and self._total + len(out) <= self._max_decoded:
                out += self._brotli.process(b"", output_buffer_limit=self._max_decoded - self._total - len(out) + 1)
        else:
            out = chunk
        self._total += len(out)
        if self._total > self._max_decoded:
            raise _TooLarge("decoded_too_large")
        return out


def _default_port(scheme: str) -> int:
    return DEFAULT_PORTS[scheme]


def _host_header(hostname: str, port: int, scheme: str) -> str:
    return hostname if port == _default_port(scheme) else f"{hostname}:{port}"


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class WebFetcher:
    def __init__(
        self,
        policy: TargetPolicy,
        resolver: Resolver,
        *,
        user_agent: str,
        document_limits: FetchLimits,
        favicon_limits: FetchLimits,
        retry_statuses: tuple[int, ...] = (429, 503),
        max_retries: int = 1,
        retry_after_cap: float = 2.0,
    ) -> None:
        self.policy = policy
        self.resolver = resolver
        self.user_agent = user_agent
        self.document_limits = document_limits
        self.favicon_limits = favicon_limits
        self.retry_statuses = retry_statuses
        self.max_retries = max_retries
        self.retry_after_cap = retry_after_cap

    def fetch(self, url: str, *, connect_ip: str | None, kind: str, context: str = "") -> tuple[FetchResult, bytes | None]:
        limits = self.favicon_limits if kind == "favicon" else self.document_limits
        deadline = time.monotonic() + limits.total_timeout
        chain: list[RedirectHop] = []
        visited: set[tuple[str, str | None]] = set()
        current_url = url
        current_ip = connect_ip
        retries = 0
        started = time.monotonic()
        is_retry = False

        while True:
            try:
                parts = urlsplit(current_url)
            except ValueError:
                return self._failure(url, current_ip, None, None, "protocol_error", "unparsable_url", chain, started, kind=kind), None

            if parts.scheme not in ("http", "https"):
                return self._failure(current_url, current_ip, None, None, "policy_refused", "unsafe_scheme", chain, started, kind=kind), None
            hostname = parts.hostname
            if not hostname:
                return self._failure(current_url, current_ip, None, None, "policy_refused", "invalid_hostname", chain, started, kind=kind), None
            try:
                port = parts.port or _default_port(parts.scheme)
            except ValueError:
                return self._failure(current_url, current_ip, None, None, "protocol_error", "unparsable_url", chain, started, kind=kind), None

            if current_ip is None:
                refusal = self.policy.check_url(current_url, stage="document" if kind == "document" else "favicon", context=context)
                if refusal is not None:
                    return self._failure(current_url, None, None, None, "policy_refused", refusal.reason, chain, started, kind=kind), None
                if _is_ip_literal(hostname):
                    current_ip = hostname
                else:
                    current_ip = self._resolve_one(hostname, stage="favicon", context=context)
                    if current_ip is None:
                        return self._failure(current_url, None, hostname, None, "dns_failure", "no_current_answer", chain, started, kind=kind), None

            dedupe_key = (current_url, current_ip)
            if is_retry:
                is_retry = False
            else:
                if dedupe_key in visited:
                    return self._failure(current_url, current_ip, hostname, None, "redirect_loop", "repeat_url", chain, started, kind=kind), None
                visited.add(dedupe_key)

            refusal = self.policy.check_ip(current_ip, stage="document" if kind == "document" else "favicon", context=context)
            if refusal is not None:
                return self._failure(current_url, current_ip, hostname, None, "policy_refused", refusal.reason, chain, started, kind=kind), None

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return self._failure(current_url, current_ip, hostname, None, "timeout", "total_deadline", chain, started, kind=kind), None

            outcome = self._one_request(
                parts, hostname, port, current_ip, limits, min(remaining, limits.total_timeout), deadline,
            )

            if outcome.kind == "transport":
                return self._finish(outcome, chain, started, kind=kind), outcome.body

            if outcome.http_status in REDIRECT_STATUSES and len(chain) < limits.max_redirects:
                location = outcome.location
                if not location:
                    return self._finish(outcome, chain, started, override_outcome="http_status", kind=kind), outcome.body
                next_url = urljoin(current_url, location)
                next_parts = urlsplit(next_url)
                if next_parts.scheme not in ("http", "https") or not next_parts.hostname:
                    chain.append(RedirectHop(from_url=current_url, status=outcome.http_status, location=location, to_url=None, connect_ip=None, decision="unsupported_scheme"))
                    return self._failure(current_url, current_ip, hostname, outcome.http_status, "policy_refused", "unsafe_scheme", chain, started, kind=kind), outcome.body

                try:
                    next_port = next_parts.port or _default_port(next_parts.scheme)
                except ValueError:
                    return self._failure(current_url, current_ip, hostname, outcome.http_status, "protocol_error", "unparsable_url", chain, started, kind=kind), outcome.body
                next_hostname = next_parts.hostname
                same_host_port = next_hostname == hostname and next_port == port

                if same_host_port:
                    next_ip = current_ip
                    decision_refusal = None
                elif _is_ip_literal(next_hostname):
                    next_ip = next_hostname
                    decision_refusal = self.policy.check_ip(next_ip, stage="document_redirect" if kind == "document" else "favicon_redirect", context=current_url)
                else:
                    next_ip, decision_refusal = self._resolve_redirect(next_hostname, kind, current_url)

                if decision_refusal is not None:
                    chain.append(RedirectHop(from_url=current_url, status=outcome.http_status, location=location, to_url=next_url, connect_ip=None, decision="policy_refused"))
                    return self._failure(current_url, current_ip, hostname, outcome.http_status, "policy_refused", decision_refusal, chain, started, kind=kind), outcome.body
                if next_ip is None:
                    chain.append(RedirectHop(from_url=current_url, status=outcome.http_status, location=location, to_url=next_url, connect_ip=None, decision="dns_failure"))
                    return self._failure(current_url, current_ip, hostname, outcome.http_status, "dns_failure", "no_current_answer", chain, started, kind=kind), outcome.body

                chain.append(RedirectHop(from_url=current_url, status=outcome.http_status, location=location, to_url=next_url, connect_ip=next_ip, decision="followed"))
                current_url, current_ip = next_url, next_ip
                continue

            if outcome.http_status in REDIRECT_STATUSES and len(chain) >= limits.max_redirects:
                return self._finish(outcome, chain, started, override_outcome="too_many_redirects", kind=kind), outcome.body

            if outcome.http_status in self.retry_statuses and retries < self.max_retries:
                retries += 1
                delay = min(outcome.retry_after_seconds or 1.0, self.retry_after_cap)
                remaining_after_sleep = deadline - time.monotonic() - delay
                if remaining_after_sleep <= 0:
                    outcome.retries = retries
                    return self._finish(outcome, chain, started, kind=kind), outcome.body
                time.sleep(max(delay, 0.0))
                outcome.retries = retries
                is_retry = True
                continue

            outcome.retries = retries
            return self._finish(outcome, chain, started, kind=kind), outcome.body

    # ------------------------------------------------------------------ helpers

    def _resolve_one(self, hostname: str, *, stage: str, context: str) -> str | None:
        try:
            answers = list(self.resolver.resolve_a(hostname))
        except Exception:
            return None
        allowed = sorted(ip for ip in answers if self.policy.check_ip(ip, stage=stage, context=context) is None)
        return allowed[0] if allowed else None

    def _resolve_redirect(self, hostname: str, kind: str, context: str) -> tuple[str | None, str | None]:
        stage = "document_redirect" if kind == "document" else "favicon_redirect"
        name_refusal = self.policy.check_hostname(hostname, stage=stage, context=context)
        if name_refusal is not None:
            return None, name_refusal.reason
        try:
            answers = list(self.resolver.resolve_a(hostname))
        except Exception:
            return None, None
        if not answers:
            return None, None
        refusal_reason: str | None = None
        allowed: list[str] = []
        for ip in answers:
            refusal = self.policy.check_ip(ip, stage=stage, context=context)
            if refusal is None:
                allowed.append(ip)
            else:
                refusal_reason = refusal.reason
        if allowed:
            return sorted(allowed)[0], None
        return None, refusal_reason or "outside_population"

    def _one_request(self, parts, hostname: str, port: int, connect_ip: str, limits: FetchLimits, timeout: float, deadline: float) -> "_RequestOutcome":
        """One request under a hard wall-clock cap: httpx's read timeout restarts on every byte, so a server that drips
        its response headers would otherwise hold a worker for as long as it likes."""
        fired = threading.Event()
        holder: list = []

        def expire() -> None:
            fired.set()
            for client in holder:
                try:
                    client.close()
                except Exception:
                    pass
        watchdog = threading.Timer(min(max(0.05, deadline - time.monotonic()), 3600.0), expire)
        watchdog.daemon = True
        watchdog.start()
        try:
            result = self._one_request_inner(parts, hostname, port, connect_ip, limits, timeout, deadline, holder)
        except Exception:
            if not fired.is_set():
                raise
            result = None
        finally:
            watchdog.cancel()
        if result is None or (fired.is_set() and result.kind == "transport"):
            return _RequestOutcome(kind="transport", outcome="timeout", http_status=None, content_type=None, content_encoding=None, location=None,
                                   body=None, body_bytes=0, certificate=None, retry_after_seconds=None, connect_ip=connect_ip,
                                   host_header=_host_header(hostname, port, parts.scheme), sni=None, final_url=f"{parts.scheme}://{connect_ip}:{port}")
        return result

    def _one_request_inner(self, parts, hostname: str, port: int, connect_ip: str, limits: FetchLimits, timeout: float, deadline: float, holder: list) -> "_RequestOutcome":
        scheme = parts.scheme
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        request_url = f"{scheme}://{connect_ip}:{port}{path}"
        sni = None if _is_ip_literal(hostname) else hostname
        headers = {"Host": _host_header(hostname, port, scheme), "User-Agent": self.user_agent, "Accept-Encoding": "gzip, deflate, br"}
        extensions: dict = {}
        if sni is not None:
            extensions["sni_hostname"] = sni

        raw_chunks: list[bytes] = []
        raw_total = 0
        cert_info: CertificateInfo | None = None
        final_url = request_url

        try:
            with httpx.Client(verify=False, http2=False, trust_env=False, follow_redirects=False) as client:
                holder.append(client)
                request = client.build_request("GET", request_url, headers=headers, extensions=extensions)
                with client.stream("GET", request_url, headers=headers, extensions=extensions, timeout=httpx.Timeout(connect=limits.connect_timeout, read=limits.read_timeout, write=limits.read_timeout, pool=limits.connect_timeout)) as response:
                    cert_info = self._extract_certificate(response, connect_ip, port, sni)
                    content_encoding = response.headers.get("content-encoding")
                    try:
                        decoder = _StreamDecoder(content_encoding, limits.max_decoded_bytes)
                    except _TooLarge as exc:
                        for _ in response.iter_raw():
                            pass
                        return _RequestOutcome(
                            kind="transport", outcome=exc.outcome, http_status=response.status_code,
                            content_type=response.headers.get("content-type"), content_encoding=content_encoding,
                            location=response.headers.get("location"), body=None, body_bytes=0,
                            certificate=cert_info, retry_after_seconds=None, connect_ip=connect_ip,
                            host_header=headers["Host"], sni=sni, final_url=final_url,
                        )
                    decoded_chunks: list[bytes] = []
                    for chunk in response.iter_raw():
                        if time.monotonic() > deadline:
                            return _RequestOutcome(
                                kind="transport", outcome="timeout", http_status=None, content_type=None,
                                content_encoding=content_encoding, location=None, body=None, body_bytes=raw_total,
                                certificate=cert_info, retry_after_seconds=None, connect_ip=connect_ip,
                                host_header=headers["Host"], sni=sni, final_url=final_url,
                            )
                        raw_total += len(chunk)
                        if raw_total > limits.max_bytes:
                            # How far past the cap the read got depends on chunk
                            # boundaries; record the cap so repeats stay identical.
                            return _RequestOutcome(
                                kind="transport", outcome="body_too_large", http_status=response.status_code, content_type=response.headers.get("content-type"),
                                content_encoding=content_encoding, location=response.headers.get("location"), body=None, body_bytes=limits.max_bytes,
                                certificate=cert_info, retry_after_seconds=None, connect_ip=connect_ip,
                                host_header=headers["Host"], sni=sni, final_url=final_url,
                            )
                        raw_chunks.append(chunk)
                        try:
                            decoded_chunks.append(decoder.feed(chunk))
                        except _TooLarge as exc:
                            return _RequestOutcome(
                                kind="transport", outcome=exc.outcome, http_status=response.status_code, content_type=response.headers.get("content-type"),
                                content_encoding=content_encoding, location=response.headers.get("location"), body=None, body_bytes=raw_total,
                                certificate=cert_info, retry_after_seconds=None, connect_ip=connect_ip,
                                host_header=headers["Host"], sni=sni, final_url=final_url,
                            )
                    body = b"".join(decoded_chunks)
                    status = response.status_code
                    return _RequestOutcome(
                        kind="status", outcome="ok" if 200 <= status < 300 else "http_status", http_status=status,
                        content_type=response.headers.get("content-type"), content_encoding=content_encoding,
                        location=response.headers.get("location"), body=body, body_bytes=len(body),
                        certificate=cert_info, retry_after_seconds=_parse_retry_after(response.headers.get("retry-after")),
                        connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url,
                        raw_retry_after=response.headers.get("retry-after"),
                    )
        except httpx.ConnectTimeout:
            return _RequestOutcome(kind="transport", outcome="timeout", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=0, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except httpx.ReadTimeout:
            return _RequestOutcome(kind="transport", outcome="timeout", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=raw_total, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except httpx.PoolTimeout:
            return _RequestOutcome(kind="transport", outcome="timeout", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=0, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except httpx.RemoteProtocolError:
            return _RequestOutcome(kind="transport", outcome="protocol_error", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=raw_total, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except httpx.ReadError as exc:
            cause = exc.__cause__
            outcome_name = "reset" if isinstance(cause, ConnectionResetError) or "reset" in str(exc).lower() else "connect_error"
            return _RequestOutcome(kind="transport", outcome=outcome_name, http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=raw_total, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except ConnectionResetError:
            return _RequestOutcome(kind="transport", outcome="reset", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=raw_total, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except (httpx.ConnectError,) as exc:
            cause = exc.__cause__
            import ssl as _ssl
            if isinstance(cause, _ssl.SSLError):
                return _RequestOutcome(kind="transport", outcome="tls_error", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=0, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
            return _RequestOutcome(kind="transport", outcome="connect_error", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=0, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except httpx.TimeoutException:
            return _RequestOutcome(kind="transport", outcome="timeout", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=raw_total, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)
        except httpx.HTTPError:
            return _RequestOutcome(kind="transport", outcome="protocol_error", http_status=None, content_type=None, content_encoding=None, location=None, body=None, body_bytes=raw_total, certificate=None, retry_after_seconds=None, connect_ip=connect_ip, host_header=headers["Host"], sni=sni, final_url=final_url)

    def _extract_certificate(self, response: httpx.Response, connect_ip: str, port: int, sni: str | None) -> CertificateInfo | None:
        network_stream = response.extensions.get("network_stream")
        if network_stream is None:
            return None
        try:
            ssl_object = network_stream.get_extra_info("ssl_object")
        except Exception:
            return None
        if ssl_object is None:
            return None
        try:
            # httpcore exposes the raw low-level `_ssl._SSLSocket` C object
            # here, not the `ssl.SSLSocket` wrapper -- its `getpeercert`
            # only accepts the binary-form flag positionally and raises
            # TypeError on `binary_form=True`, so the flag is passed positionally.
            der = ssl_object.getpeercert(True)
        except Exception:
            return None
        if not der:
            return None
        try:
            from scanner.certificates import parse_der
        except ImportError:
            return None
        try:
            return parse_der(
                der,
                handshake_mode="hostname_aware" if sni is not None else "direct_ip",
                sni_sent=sni,
                observed_at=datetime.now(UTC),
                target_ip=connect_ip,
                port=port,
            )
        except Exception:
            return None

    def _failure(self, url, connect_ip, hostname, http_status, outcome, reason, chain, started, kind="document") -> FetchResult:
        return FetchResult(
            kind=kind, requested_url=url, connect_ip=connect_ip, host_header=hostname, sni=None,
            outcome=outcome, failure_category=reason, http_status=http_status, content_type=None,
            content_encoding=None, retry_after=None, body_sha256=None, body_bytes=0,
            redirect_chain=tuple(chain), final_url=None, certificate=None, retries=0,
            timing_ms=round((time.monotonic() - started) * 1000, 3),
        )

    def _finish(self, outcome: "_RequestOutcome", chain: list[RedirectHop], started: float, *, override_outcome: str | None = None, kind: str = "document") -> FetchResult:
        body = outcome.body
        return FetchResult(
            kind=kind, requested_url=outcome.final_url, connect_ip=outcome.connect_ip, host_header=outcome.host_header,
            sni=outcome.sni, outcome=override_outcome or outcome.outcome, failure_category=None if (override_outcome or outcome.outcome) in ("ok", "http_status") else (override_outcome or outcome.outcome),
            http_status=outcome.http_status, content_type=outcome.content_type, content_encoding=outcome.content_encoding,
            retry_after=getattr(outcome, "raw_retry_after", None), body_sha256=_sha256(body) if body is not None else None,
            body_bytes=outcome.body_bytes, redirect_chain=tuple(chain), final_url=outcome.final_url if body is not None or outcome.outcome in ("ok", "http_status") else None,
            certificate=outcome.certificate, retries=getattr(outcome, "retries", 0),
            timing_ms=round((time.monotonic() - started) * 1000, 3),
        )


@dataclass
class _RequestOutcome:
    kind: str
    outcome: str
    http_status: int | None
    content_type: str | None
    content_encoding: str | None
    location: str | None
    body: bytes | None
    body_bytes: int
    certificate: CertificateInfo | None
    retry_after_seconds: float | None
    connect_ip: str | None
    host_header: str | None
    sni: str | None
    final_url: str | None
    raw_retry_after: str | None = None
    retries: int = 0


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(int(value.strip()))
    except ValueError:
        return None
