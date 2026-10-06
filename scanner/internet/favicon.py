"""Document + favicon acquisition for responsive web endpoints.

Every connection goes to the scanned IP (``connect_ip``). The fetch policy that
guards redirects is built from the sampled IPs only (see ``fetch_policy``), so a
redirect can never lead the run to a host outside the sample.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit
from typing import Any

import dns.resolver

from scanner.internet.enrich import document_facts, icon_declaration_facts
from scanner.favicon_acquire import acquire_favicons
from scanner.safety import HostnamePolicyInput, ProductionPolicyInput, TargetPolicy
from scanner.web_fetch import FetchLimits, WebFetcher, _is_ip_literal, _RequestOutcome


def fetch_policy(cfg: Any, sampled_ips: list[str]) -> TargetPolicy:
    """Policy whose whole population is the responsive sample (/32s). Callers skip the stage when empty."""
    if not sampled_ips:
        raise ValueError("fetch policy needs at least one sampled IP")
    return TargetPolicy.production(ProductionPolicyInput(
        approval_reference=cfg.approval.approval_reference if cfg.approval else "unapproved",
        population=tuple(f"{ip}/32" for ip in sorted(set(sampled_ips))),
        hostname_policy=HostnamePolicyInput(cfg.hostname_mode, cfg.hostname_suffixes),
        exclusions=tuple(),
    ))


class RedirectResolver:
    """Minimal A resolver (explicit nameservers) used only to vet redirect targets."""

    def __init__(self, nameservers: tuple[str, ...], timeout: float) -> None:
        self._servers = []
        for ns in nameservers:
            host, _, port = ns.partition(":")
            self._servers.append((host, int(port) if port else 53))
        self._timeout = timeout
        self._local = threading.local()

    def _resolver(self, host: str, port: int) -> dns.resolver.Resolver:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [host]
        r.port = port
        r.timeout = self._timeout
        r.lifetime = self._timeout * 2
        return r

    def resolve_a(self, hostname: str) -> list[str]:
        for host, port in self._servers:
            try:
                answer = self._resolver(host, port).resolve(hostname, "A")
                return sorted({r.address for r in answer})
            except Exception:
                continue
        return []


def _limits(cfg: Any, max_bytes: int) -> FetchLimits:
    f = cfg.fetch
    return FetchLimits(
        connect_timeout=f.connect_timeout, read_timeout=f.read_timeout, total_timeout=f.total_timeout,
        max_bytes=max_bytes, max_decoded_bytes=f.max_decoded_bytes, max_redirects=f.max_redirects,
    )


class GuardedFetcher(WebFetcher):
    """WebFetcher confined to (ip, port) pairs that actually answered the ZMap scan.

    ``TargetPolicy`` checks IPs only. Without this, a ``Location:`` header or ``<link rel=icon>`` on a
    sampled host could point at ``same-ip:22`` / ``:6379`` and the fetcher would connect there, i.e. to a
    port the approval does not cover. Decode errors from hostile bodies become a recorded outcome.
    """

    def __init__(self, *args: Any, allowed_endpoints: set[tuple[str, int]], pacer: Any = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.allowed_endpoints = frozenset(allowed_endpoints)
        self.pacer = pacer

    @staticmethod
    def _outcome(outcome: str, connect_ip: str, hostname: str, port: int, scheme: str) -> _RequestOutcome:
        return _RequestOutcome(
            kind="transport", outcome=outcome, http_status=None, content_type=None, content_encoding=None,
            location=None, body=None, body_bytes=0, certificate=None, retry_after_seconds=None,
            connect_ip=connect_ip, host_header=hostname, sni=None, final_url=f"{scheme}://{connect_ip}:{port}/",
        )

    def _one_request(self, parts, hostname, port, connect_ip, limits, timeout, deadline):   # type: ignore[override]
        if (connect_ip, port) not in self.allowed_endpoints:
            return self._outcome("policy_refused", connect_ip, hostname, port, parts.scheme)
        if self.pacer is not None and not self.pacer.wait(connect_ip):
            return self._outcome("skipped_kill_switch", connect_ip, hostname, port, parts.scheme)
        try:
            return super()._one_request(parts, hostname, port, connect_ip, limits, timeout, deadline)
        except Exception as exc:       # zlib.error / brotli.error / anything a hostile body provokes
            return self._outcome("decode_error" if "error" in type(exc).__name__.lower() else "fetch_error",
                                 connect_ip, hostname, port, parts.scheme)


OFFHOST_PORTS = (80, 443)


class OffhostIconFetcher(WebFetcher):
    """Fetches icons a page declares on OTHER hosts (CDNs, asset domains). Favicon requests only.

    Hosts outside the sample are third parties, so this is deliberately tight: default web ports only
    (on every redirect hop too), public addresses only (reserved space and the exclusions file are
    refused after DNS resolution), one request per unique URL, a per-host cap with a minimum interval,
    a run-wide cap, and a smaller body limit. Every attempt is logged with the page that referred to it.
    """

    def __init__(self, *args: Any, max_total: int, max_per_host: int, min_interval: float,
                 killed: Any = lambda: False, state_path: Any = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.max_total, self.max_per_host, self.min_interval, self.killed = max_total, max_per_host, min_interval, killed
        self.log: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[Any, bytes | None]] = {}
        self._per_host: dict[str, int] = {}
        self._per_ip: dict[str, int] = {}
        self._next_slot: dict[str, float] = {}
        self._sent = 0
        # Caps are campaign-wide: the counts survive from one shard (one run) to the next.
        self._state_path = Path(state_path) if state_path else None
        if self._state_path is not None and self._state_path.exists():
            try:
                saved = json.loads(self._state_path.read_text(encoding="utf-8"))
                self._per_host = {str(k): int(v) for k, v in saved.get("per_host", {}).items()}
                self._sent = int(saved.get("sent", 0))
            except (OSError, ValueError, TypeError):
                pass

    def save_state(self) -> None:
        if self._state_path is None:
            return
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._state_path.with_suffix(".tmp")
        with self._lock:
            tmp.write_text(json.dumps({"sent": self._sent, "per_host": self._per_host}, sort_keys=True), encoding="utf-8")
        tmp.replace(self._state_path)

    def _refuse(self, url: str, connect_ip: str | None, reason: str):
        from scanner.models import FetchResult
        return FetchResult(
            kind="favicon", requested_url=url, connect_ip=connect_ip, host_header=None, sni=None, outcome="policy_refused",
            failure_category=reason, http_status=None, content_type=None, content_encoding=None, retry_after=None,
            body_sha256=None, body_bytes=0, redirect_chain=(), final_url=url, certificate=None), None

    def _record(self, url: str, context: str, result: Any, cached: bool) -> None:
        with self._lock:
            self.log.append({
                "url": url, "referred_by": context, "outcome": result.outcome, "failure_category": result.failure_category,
                "http_status": result.http_status, "content_type": result.content_type, "bytes": result.body_bytes,
                "sha256": result.body_sha256, "connect_ip": result.connect_ip, "cached": cached,
                "redirects": [h.to_url for h in result.redirect_chain],
            })

    def fetch(self, url: str, *, connect_ip: str | None, kind: str, context: str = ""):   # type: ignore[override]
        parts = urlsplit(url)
        try:
            host, port = (parts.hostname or "").lower(), parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError:
            return self._refuse(url, None, "bad_port")
        if kind != "favicon" or connect_ip is not None:
            return self._refuse(url, connect_ip, "offhost_favicons_only")
        if port not in OFFHOST_PORTS:
            return self._refuse(url, None, "offhost_port")
        with self._lock:
            hit = self._cache.get(url)
        if hit is not None:
            self._record(url, context, hit[0], True)
            return hit
        with self._lock:
            reason = ("run_cap" if self._sent >= self.max_total else
                      "host_cap" if self._per_host.get(host, 0) >= self.max_per_host else None)
            if reason is None:
                self._sent += 1
                self._per_host[host] = self._per_host.get(host, 0) + 1
                now = time.monotonic()
                slot = max(now, self._next_slot.get(host, 0.0))
                self._next_slot[host] = slot + self.min_interval
        if reason is not None or self.killed():
            res = self._refuse(url, None, reason or "kill_switch")
            self._record(url, context, res[0], False)
            return res
        delay = slot - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        res = super().fetch(url, connect_ip=None, kind="favicon", context=context)
        with self._lock:
            self._cache[url] = res
        self._record(url, context, res[0], False)
        return res

    def _one_request(self, parts, hostname, port, connect_ip, limits, timeout, deadline):   # type: ignore[override]
        if port not in OFFHOST_PORTS or _is_ip_literal(hostname):    # also stops a redirect hop reaching another port or a bare IP
            return GuardedFetcher._outcome("policy_refused", connect_ip, hostname, port, parts.scheme)
        with self._lock:                                             # many hostnames can point at one machine: cap per address too
            seen = self._per_ip.get(connect_ip, 0)
            if seen >= self.max_per_host * 2:
                return GuardedFetcher._outcome("policy_refused", connect_ip, hostname, port, parts.scheme)
            self._per_ip[connect_ip] = seen + 1
        try:
            return super()._one_request(parts, hostname, port, connect_ip, limits, timeout, deadline)
        except Exception as exc:
            return GuardedFetcher._outcome("decode_error" if "error" in type(exc).__name__.lower() else "fetch_error",
                                           connect_ip, hostname, port, parts.scheme)


class RoutingFetcher:
    """Same-host and sampled-IP requests go to the confined fetcher; off-host icons to the tight third-party one."""

    def __init__(self, local: WebFetcher, offhost: OffhostIconFetcher) -> None:
        self.local, self.offhost = local, offhost

    def fetch(self, url: str, *, connect_ip: str | None, kind: str, context: str = ""):
        if kind == "favicon" and connect_ip is None:
            return self.offhost.fetch(url, connect_ip=None, kind=kind, context=context)
        return self.local.fetch(url, connect_ip=connect_ip, kind=kind, context=context)


def offhost_policy(cfg: Any, exclusions: list[str]) -> TargetPolicy:
    """Public IPv4 only: the whole space minus reserved ranges minus the exclusions file."""
    from scanner.internet.population import population_cidrs
    return TargetPolicy.production(ProductionPolicyInput(
        approval_reference=cfg.approval.approval_reference if cfg.approval else "unapproved",
        population=tuple(population_cidrs()),
        hostname_policy=HostnamePolicyInput(cfg.hostname_mode, cfg.hostname_suffixes),
        exclusions=tuple(exclusions),
    ))


def make_fetcher(cfg: Any, policy: TargetPolicy, resolver: Any, allowed_endpoints: set[tuple[str, int]],
                 *, exclusions: list[str] | None = None, killed: Any = lambda: False, state_path: Any = None,
                 pacer: Any = None) -> Any:
    local = _make_local_fetcher(cfg, policy, resolver, allowed_endpoints, pacer, killed)
    oh = cfg.favicon.offhost
    if not oh.enabled:
        return local
    lim = _limits(cfg, oh.max_bytes)
    third_party = OffhostIconFetcher(
        offhost_policy(cfg, exclusions or []), resolver, user_agent=cfg.fetch.user_agent,
        document_limits=lim, favicon_limits=lim, retry_statuses=(), max_retries=0, retry_after_cap=0.0,
        max_total=oh.max_total_fetches, max_per_host=oh.max_per_host, min_interval=oh.min_interval_seconds, killed=killed,
        state_path=state_path)
    return RoutingFetcher(local, third_party)


def _make_local_fetcher(cfg: Any, policy: TargetPolicy, resolver: Any, allowed_endpoints: set[tuple[str, int]],
                        pacer: Any = None, killed: Any = lambda: False) -> WebFetcher:
    return GuardedFetcher(
        policy, resolver, user_agent=cfg.fetch.user_agent, allowed_endpoints=allowed_endpoints, pacer=pacer, killed=killed,
        document_limits=_limits(cfg, cfg.fetch.max_document_bytes),
        favicon_limits=_limits(cfg, cfg.fetch.max_favicon_bytes),
        retry_statuses=cfg.fetch.retry_statuses, max_retries=cfg.fetch.max_retries,
        retry_after_cap=cfg.fetch.retry_after_cap,
    )


def _is_html(content_type: str | None) -> bool:
    return bool(content_type) and "html" in content_type.lower()


def _favicon_outcome(first: Any, image: Any) -> str:
    """image = a decodable image; otherwise say what came back instead (an HTTP error, an HTML page, ...)."""
    if image is not None:
        return "image"
    fetch = first.fetch
    if fetch is None:
        return "no_image"
    if fetch.http_status is not None and not 200 <= fetch.http_status < 300:
        return f"http_{fetch.http_status}"
    if fetch.outcome not in ("ok", "http_status"):
        return fetch.outcome
    return "not_an_image"      # HTTP 200 but the body does not decode as an image (HTML catch-all page, JSON, ...)


def _display_url(url: str) -> str:
    """An embedded ``data:`` icon can be hundreds of kilobytes of base64; keep the record small."""
    return url if not url.lower().startswith("data:") else f"{url[:40]}... (embedded, {len(url)} chars)"


def probe_identity(fetcher: WebFetcher, *, scheme: str, ip: str, port: int, hostname: str | None, max_icons: int,
                   icon_store: Any = None) -> dict[str, Any]:
    """Fetch ``scheme://host:port/`` through ``ip`` and acquire its favicon. Never raises."""
    host = hostname or ip
    url = f"{scheme}://{host}:{port}/"
    record: dict[str, Any] = {
        "kind": "hostname" if hostname else "direct_ip", "url": url, "scheme": scheme, "hostname": hostname,
        "document_outcome": None, "http_status": None, "final_url": None, "content_type": None,
        "favicon_url": None, "favicon_file": None, "favicon_sha256": None, "favicon_bytes": None, "favicon_content_type": None,
        "favicon_decode_status": None, "favicon_mmh3": None, "favicon_md5": None, "favicon_outcome": "not_attempted",
        "favicon_is_image": False,
        "document_title": None, "document_body_sha256": None, "icon_declared_count": 0, "icon_declared_kinds": {},
        "icon_offhost_hosts": [], "icon_embedded_images": 0,
        "favicon_candidates": 0, "error": None,
    }
    try:
        result, body = fetcher.fetch(url, connect_ip=ip, kind="document", context=f"scanner:{ip}:{port}")
        record.update(document_outcome=result.outcome, http_status=result.http_status,
                      final_url=result.final_url, content_type=result.content_type)
        html = None
        if body and _is_html(result.content_type):
            html = body.decode("utf-8", errors="replace")
        record.update(document_facts(html, body))
        if result.outcome not in ("ok", "http_status") and result.http_status is None:
            record["favicon_outcome"] = "document_failed"
            return record
        decls, resources = acquire_favicons(url, html, connect_ip=ip, fetcher=fetcher, max_icons=max_icons,
                                            on_icon=icon_store.save if icon_store is not None else None)
        record.update(icon_declaration_facts(url, decls, resources))
        record["favicon_candidates"] = len(resources)
        image = next((r for r in resources if r.fingerprint and r.fingerprint.get("image_ok")), None)
        first = image or (resources[0] if resources else None)
        if first is None:
            record["favicon_outcome"] = "none_declared"
        else:
            fp = first.fingerprint or {}
            record.update(
                favicon_url=_display_url(first.resolved_url), favicon_sha256=first.favicon_sha256, favicon_bytes=first.favicon_bytes,
                favicon_content_type=first.content_type_claimed, favicon_decode_status=first.decode_status,
                favicon_mmh3=fp.get("mmh3_hash"), favicon_md5=fp.get("md5_hex"),
                favicon_is_image=image is not None,
                favicon_file=icon_store.path_for(first.favicon_sha256) if icon_store is not None and image is not None else None,
                favicon_outcome=_favicon_outcome(first, image),
            )
    except Exception as exc:   # one bad endpoint must never abort the stage
        record["error"] = f"{type(exc).__name__}: {exc}"[:300]
        record["favicon_outcome"] = "error"
    return record


def run_favicon_stage(fetcher: WebFetcher, jobs: list[dict[str, Any]], *, workers: int, max_icons: int, killed: Any = lambda: False,
                      icon_store: Any = None) -> list[dict[str, Any]]:
    """``jobs``: dicts with scheme/ip/port/hostname. Returns one record per job, order preserved."""
    def one(job: dict[str, Any]) -> dict[str, Any]:
        if killed():
            return {"kind": "hostname" if job.get("hostname") else "direct_ip", "scheme": job["scheme"], "hostname": job.get("hostname"),
                    "favicon_outcome": "skipped_kill_switch", "ip": job["ip"], "port": job["port"]}
        rec = probe_identity(fetcher, scheme=job["scheme"], ip=job["ip"], port=job["port"], hostname=job.get("hostname"), max_icons=max_icons,
                              icon_store=icon_store)
        rec["ip"], rec["port"] = job["ip"], job["port"]
        return rec
    if not jobs:
        return []
    # One host at a time: every job for the same ip:port runs in sequence on one worker, so a scanned server never
    # sees the bare-IP request and several name-based requests at once.
    groups: dict[tuple[str, int], list[int]] = {}
    for idx, job in enumerate(jobs):
        groups.setdefault((job["ip"], job["port"]), []).append(idx)
    out: list[dict[str, Any] | None] = [None] * len(jobs)

    def run_group(indexes: list[int]) -> None:
        for i in indexes:
            out[i] = one(jobs[i])
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        list(pool.map(run_group, groups.values()))
    return [r for r in out if r is not None]
