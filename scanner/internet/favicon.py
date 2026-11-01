"""Document + favicon acquisition for responsive web endpoints.

Every connection goes to the scanned IP (``connect_ip``). The fetch policy that
guards redirects is built from the sampled IPs only (see ``fetch_policy``), so a
redirect can never lead the run to a host outside the sample.
"""
from __future__ import annotations

import ctypes
import dataclasses
import hashlib
import json
import multiprocessing
import multiprocessing.connection
import queue
import threading
import time
from collections import OrderedDict
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from concurrent.futures import Future
from urllib.parse import urlsplit, urlunsplit
from typing import Any

import dns.resolver

from pipeline.favicon_hash import fingerprint as compute_fingerprint
from scanner.internet import outputs
from scanner.internet.enrich import document_facts, icon_declaration_facts
from scanner.internet.icon_store import IconStore
from scanner.internet.offhost_service import OffhostClient, OffhostService
from scanner.internet.pacing import IpPacer, SubnetLimiter
from pipeline.favicon_hash import fingerprint as compute_fingerprint
from scanner.favicon_acquire import acquire_favicons
from scanner.favicon_discovery import parse_icon_declarations
from scanner.models import FaviconDeclaration
from scanner.safety import HostnamePolicyInput, ProductionPolicyInput, TargetPolicy
from scanner.web_fetch import FetchLimits, WebFetcher, _is_ip_literal, _RequestOutcome


class FingerprintCache:
    """Remembers the fingerprint of icon bodies already decoded, keyed by content digest.

    The same few icons (hosting defaults, device logos, CMS marks) turn up on a large share of the addresses of a
    scan, and decoding plus hashing one costs several milliseconds of CPU that all workers share. The fingerprint
    is a pure function of the bytes, so reusing it changes nothing in the records.
    """

    def __init__(self, capacity: int = 2048) -> None:
        self._capacity = max(1, capacity)
        self._items: OrderedDict[tuple[int, bytes], Any] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = self.misses = 0

    def __call__(self, data: bytes) -> Any:
        key = (len(data), hashlib.sha256(data).digest())
        with self._lock:
            found = self._items.get(key)
            if found is not None:
                self._items.move_to_end(key)
                self.hits += 1
                return found
            self.misses += 1
        result = compute_fingerprint(data)
        with self._lock:
            self._items[key] = result
            self._items.move_to_end(key)
            while len(self._items) > self._capacity:
                self._items.popitem(last=False)
        return result


_FINGERPRINTS = FingerprintCache()


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

    def __init__(self, *args: Any, allowed_endpoints: set[tuple[str, int]], pacer: Any = None,
                 max_active_requests: int | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.allowed_endpoints = frozenset(allowed_endpoints)
        self.pacer = pacer
        # Workers that wait out the pause hold no socket; this bounds the requests actually on the wire.
        self._active = threading.BoundedSemaphore(max_active_requests) if max_active_requests else None

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
        result = None
        try:
            if self._active is None:
                result = super()._one_request(parts, hostname, port, connect_ip, limits, timeout, deadline)
                return result
            with self._active:
                result = super()._one_request(parts, hostname, port, connect_ip, limits, timeout, deadline)
                return result
        except Exception as exc:       # zlib.error / brotli.error / anything a hostile body provokes
            return self._outcome("decode_error" if "error" in type(exc).__name__.lower() else "fetch_error",
                                 connect_ip, hostname, port, parts.scheme)
        finally:
            if self.pacer is not None and hasattr(self.pacer, "done"):
                self.pacer.done(connect_ip, result)      # frees the network slot taken by wait()


OFFHOST_PORTS = (80, 443)


class OffhostIconFetcher(WebFetcher):
    """Fetches icons a page declares on OTHER hosts (CDNs, asset domains). Favicon requests only.

    Hosts outside the sample are third parties, so this is deliberately tight: default web ports only
    (on every redirect hop too), public addresses only (reserved space and the exclusions file are
    refused after DNS resolution), one request per unique URL, a per-host cap with a minimum interval,
    a run-wide cap, and a smaller body limit. Every attempt is logged with the page that referred to it.
    """

    def __init__(self, *args: Any, max_total: int, max_per_host: int, min_interval: float,
                 killed: Any = lambda: False, state_path: Any = None, pacer: Any = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.max_total, self.max_per_host, self.min_interval, self.killed = max_total, max_per_host, min_interval, killed
        # Per destination address: the same pause and per-network cap as for the scanned addresses (see IpPacer).
        self.pacer = pacer
        self.log: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[Any, bytes | None]] = {}      # by normalised URL, also by the URL an icon ended at
        self._inflight: dict[str, threading.Event] = {}            # a URL being fetched: other askers wait for it
        self._by_hash: dict[str, str] = {}                         # body digest -> first URL that returned it
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

    @staticmethod
    def _key(url: str) -> str:
        p = urlsplit(url)
        return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))

    def _record(self, url: str, context: str, result: Any, cached: bool, duplicate_content: bool = False) -> None:
        with self._lock:
            self.log.append({
                "url": url, "referred_by": context, "outcome": result.outcome, "failure_category": result.failure_category,
                "http_status": result.http_status, "content_type": result.content_type, "bytes": result.body_bytes,
                "sha256": result.body_sha256, "connect_ip": result.connect_ip, "cached": cached,
                "redirects": [h.to_url for h in result.redirect_chain], "duplicate_content": duplicate_content,
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
        key = self._key(url)
        while True:
            with self._lock:
                hit = self._cache.get(key)
                pending = None if hit is not None else self._inflight.get(key)
                if hit is None and pending is None:
                    self._inflight[key] = threading.Event()
            if hit is not None:
                self._record(url, context, hit[0], True)
                return hit
            if pending is None:
                break
            pending.wait()          # another thread is fetching this URL: take its result instead of asking again
        try:
            return self._fetch_new(url, key, host, context)
        finally:
            with self._lock:
                done = self._inflight.pop(key, None)
            if done is not None:
                done.set()

    def _fetch_new(self, url: str, key: str, host: str, context: str):
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
        sha = res[0].body_sha256
        with self._lock:
            self._cache[key] = res
            final = res[0].final_url
            if res[0].outcome == "ok" and final:
                self._cache.setdefault(self._key(final), res)       # the same icon asked for under its final address
            duplicate = bool(sha) and self._by_hash.setdefault(sha, key) != key
        self._record(url, context, res[0], False, duplicate)
        return res

    def _one_request(self, parts, hostname, port, connect_ip, limits, timeout, deadline):   # type: ignore[override]
        if port not in OFFHOST_PORTS or _is_ip_literal(hostname):    # also stops a redirect hop reaching another port or a bare IP
            return GuardedFetcher._outcome("policy_refused", connect_ip, hostname, port, parts.scheme)
        with self._lock:                                             # many hostnames can point at one machine: cap per address too
            seen = self._per_ip.get(connect_ip, 0)
            if seen >= self.max_per_host * 2:
                return GuardedFetcher._outcome("policy_refused", connect_ip, hostname, port, parts.scheme)
            self._per_ip[connect_ip] = seen + 1
        if self.pacer is not None and not self.pacer.wait(connect_ip):
            return GuardedFetcher._outcome("skipped_kill_switch", connect_ip, hostname, port, parts.scheme)
        result = None
        try:
            result = super()._one_request(parts, hostname, port, connect_ip, limits, timeout, deadline)
            return result
        except Exception as exc:
            return GuardedFetcher._outcome("decode_error" if "error" in type(exc).__name__.lower() else "fetch_error",
                                           connect_ip, hostname, port, parts.scheme)
        finally:
            if self.pacer is not None and hasattr(self.pacer, "done"):
                self.pacer.done(connect_ip, result)


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
    if not cfg.favicon.offhost.enabled:
        return local
    return RoutingFetcher(local, make_offhost_fetcher(cfg, resolver, exclusions or [], killed=killed, state_path=state_path, pacer=pacer))


def make_offhost_fetcher(cfg: Any, resolver: Any, exclusions: list[str], *, killed: Any = lambda: False,
                         state_path: Any = None, pacer: Any = None) -> OffhostIconFetcher:
    """The third-party icon fetcher. ``pacer`` spaces requests per destination address (shared by all callers)."""
    oh = cfg.favicon.offhost
    lim = _limits(cfg, oh.max_bytes)
    return OffhostIconFetcher(
        offhost_policy(cfg, exclusions), resolver, user_agent=cfg.fetch.user_agent,
        document_limits=lim, favicon_limits=lim, retry_statuses=(), max_retries=0, retry_after_cap=0.0,
        max_total=oh.max_total_fetches, max_per_host=oh.max_per_host, min_interval=oh.min_interval_seconds, killed=killed,
        state_path=state_path, pacer=pacer)


def _make_local_fetcher(cfg: Any, policy: TargetPolicy, resolver: Any, allowed_endpoints: set[tuple[str, int]],
                        pacer: Any = None, killed: Any = lambda: False) -> WebFetcher:
    return GuardedFetcher(
        policy, resolver, user_agent=cfg.fetch.user_agent, allowed_endpoints=allowed_endpoints, pacer=pacer, killed=killed,
        document_limits=_limits(cfg, cfg.fetch.max_document_bytes),
        favicon_limits=_limits(cfg, cfg.fetch.max_favicon_bytes),
        retry_statuses=cfg.fetch.retry_statuses, max_retries=cfg.fetch.max_retries,
        retry_after_cap=cfg.fetch.retry_after_cap, max_active_requests=getattr(cfg.favicon, "max_active_requests", None),
    )


def _is_html(content_type: str | None) -> bool:
    return bool(content_type) and "html" in content_type.lower()


# The HTTP stage reads at most 256 KB of a body, so a page near that size may have been cut off and is fetched again.
MAX_REUSED_BODY_BYTES = 200_000


def _header(headers: Any, name: str) -> str | None:
    value = (headers or {}).get(name)
    if isinstance(value, list):
        value = value[0] if value else None
    return value if isinstance(value, str) and value else None


def _fetched_at(stamp: Any) -> float:
    """zgrab2's own time of the request as epoch seconds; the time the line is read if it has none (a later, so younger, value)."""
    try:
        when = datetime.fromisoformat(stamp)
        return round((when if when.tzinfo else when.replace(tzinfo=UTC)).timestamp(), 3)
    except (TypeError, ValueError):
        return round(time.time(), 3)


def capture_http_document(line: str, *, port: int, max_icons: int) -> tuple[tuple[str, int], dict[str, Any]] | None:
    """Compact record of a plain-HTTP bare-IP page from one output line of the HTTP stage, or None.

    Keeps what the favicon stage needs (status, headers it checks, title, body hash, parsed icon declarations) and
    none of the body, so a shard does not hold its pages in memory.
    """
    try:
        obj = json.loads(line)
        http = (obj.get("data") or {}).get("http") or {}
        response = (http.get("result") or {}).get("response") or {}
        body, ip = response.get("body"), obj.get("ip")
        if http.get("status") != "success" or obj.get("domain") or not ip or not isinstance(body, str):
            return None
        if "�" in body:      # zgrab2 prints invalid UTF-8 as U+FFFD, so the raw bytes (and their hash) are no longer known
            return None
        raw = body.encode("utf-8")
        headers = response.get("headers")
        url = f"http://{ip}:{port}/"
        return (ip, port), {
            "http_status": response.get("status_code"), "content_type": _header(headers, "content_type"),
            "content_encoding": _header(headers, "content_encoding"), "location": _header(headers, "location"),
            "captured_at": _fetched_at(http.get("timestamp")), "body_bytes": len(raw), "document_title": document_facts(body, raw)["document_title"],
            "document_body_sha256": hashlib.sha256(raw).hexdigest() if raw else None,
            "declarations": [d.as_dict() for d in parse_icon_declarations(url, body, max_icons=max_icons)],
        }
    except Exception:
        return None


def reusable_document(doc: dict[str, Any] | None, max_document_bytes: int) -> bool:
    """A stored page stands in for the page fetch only when that fetch would have returned the same document."""
    return bool(
        doc and doc.get("http_status") == 200 and not doc.get("location") and not doc.get("content_encoding")
        and _is_html(doc.get("content_type")) and 0 < (doc.get("body_bytes") or 0) <= min(MAX_REUSED_BODY_BYTES, max_document_bytes)
    )


def _age_seconds(doc: dict[str, Any]) -> float | None:
    """Seconds between the HTTP stage fetching the page and the favicon stage using it."""
    captured = doc.get("captured_at")
    return round(max(0.0, time.time() - captured), 1) if isinstance(captured, (int, float)) else None


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


def fill_icon_fields(record: dict[str, Any], fetcher: Any, *, url: str, ip: str, declared: list[FaviconDeclaration], max_icons: int,
                     icon_store: Any = None, selection: str = "all", fallback: str = "always_if_no_image") -> None:
    """Fetch the icons of ``declared`` for the page at ``url`` (reached through ``ip``) and write the favicon fields of ``record``."""
    selection_report: dict[str, Any] = {}
    decls, resources = acquire_favicons(url, None, connect_ip=ip, fetcher=fetcher, max_icons=max_icons, declarations=declared,
                                        on_icon=icon_store.save if icon_store is not None else None,
                                        selection=selection, fallback=fallback, fingerprint=_FINGERPRINTS,
                                        report=selection_report)
    if selection_report:
        # columns exist only under browser_models, so records of the other modes keep their shape
        chosen = selection_report["chosen"]
        record.update(icon_rule_version=selection_report["rule_version"],
                      icon_chosen_chromium=_display_url(chosen["chromium"]) if chosen["chromium"] else None,
                      icon_chosen_firefox=_display_url(chosen["firefox"]) if chosen["firefox"] else None,
                      icon_chosen_spec=_display_url(chosen["spec"]) if chosen["spec"] else None,
                      icon_models_differ=selection_report["differ"])
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


def probe_identity(fetcher: WebFetcher, *, scheme: str, ip: str, port: int, hostname: str | None, max_icons: int,
                   icon_store: Any = None, selection: str = "all", fallback: str = "always_if_no_image",
                   stored_document: dict[str, Any] | None = None, max_document_bytes: int = 0) -> dict[str, Any]:
    """Fetch ``scheme://host:port/`` through ``ip`` and acquire its favicon. Never raises.

    ``stored_document`` (see ``capture_http_document``) replaces the page fetch for a plain-HTTP bare-IP job when
    ``reusable_document`` accepts it; the record then says ``document_source: reused`` and how old the page was.
    Only plain HTTP is covered: the TLS stages are handshake-only, so no HTTPS page and no name-based page exists to reuse.
    """
    host = hostname or ip
    url = f"{scheme}://{host}:{port}/"
    record: dict[str, Any] = {
        "kind": "hostname" if hostname else "direct_ip", "url": url, "scheme": scheme, "hostname": hostname,
        "document_outcome": None, "document_source": "fetched", "document_age_seconds": None, "http_status": None, "final_url": None, "content_type": None,
        "favicon_url": None, "favicon_file": None, "favicon_sha256": None, "favicon_bytes": None, "favicon_content_type": None,
        "favicon_decode_status": None, "favicon_mmh3": None, "favicon_md5": None, "favicon_outcome": "not_attempted",
        "favicon_is_image": False,
        "document_title": None, "document_body_sha256": None, "icon_declared_count": 0, "icon_declared_kinds": {},
        "icon_offhost_hosts": [], "icon_embedded_images": 0,
        "favicon_candidates": 0, "error": None,
    }
    try:
        declared = None
        html = None
        if scheme == "http" and hostname is None and reusable_document(stored_document, max_document_bytes):
            declared = [FaviconDeclaration(**d) for d in stored_document["declarations"]]
            record.update(document_outcome="ok", document_source="reused", http_status=200, final_url=url,
                          content_type=stored_document["content_type"], document_title=stored_document["document_title"],
                          document_body_sha256=stored_document["document_body_sha256"],
                          document_age_seconds=_age_seconds(stored_document))
        else:
            result, body = fetcher.fetch(url, connect_ip=ip, kind="document", context=f"scanner:{ip}:{port}")
            record.update(document_outcome=result.outcome, http_status=result.http_status,
                          final_url=result.final_url, content_type=result.content_type)
            if body and _is_html(result.content_type):
                html = body.decode("utf-8", errors="replace")
            record.update(document_facts(html, body))
            body = None         # the raw bytes are not needed once the page facts are taken
            if result.outcome not in ("ok", "http_status") and result.http_status is None:
                record["favicon_outcome"] = "document_failed"
                return record
        if declared is None:
            declared = parse_icon_declarations(url, html, max_icons=max_icons) if html is not None else []
        html = None         # the page can be megabytes; icon fetches below may wait a long time for pacing
        fill_icon_fields(record, fetcher, url=url, ip=ip, declared=declared, max_icons=max_icons, icon_store=icon_store,
                         selection=selection, fallback=fallback)
    except Exception as exc:   # one bad endpoint must never abort the stage
        record["error"] = f"{type(exc).__name__}: {exc}"[:300]
        record["favicon_outcome"] = "error"
    return record


class RecordLog:
    """Append-only log of favicon records, one JSON line each, written the moment a lookup finishes.

    The stage can run for many hours and its results otherwise exist only in memory; the log lets a killed run
    keep every lookup it completed and lets a repeat run pick up where it stopped.
    """

    def __init__(self, path: Any) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._fh: Any = None
        self._closed = False
        self.dropped = 0        # appends refused because the log was already closed

    def load(self) -> dict[tuple[str, int, str | None], dict[str, Any]]:
        found: dict[tuple[str, int, str | None], dict[str, Any]] = {}
        path = outputs.resolve(self.path)          # a finished run keeps this log compressed
        if not path.exists():
            return found
        with outputs.open_text(path) as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                    found[(rec["ip"], rec["port"], rec.get("hostname"))] = rec
                except (ValueError, KeyError, TypeError):
                    continue        # a line cut short by the kill
        return found

    def append(self, rec: dict[str, Any]) -> None:
        line = json.dumps(rec, default=str) + "\n"
        with self._lock:
            if self._closed:
                self.dropped += 1
                return
            if self._fh is None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._fh = self.path.open("a", encoding="utf-8", newline="\n")
            self._fh.write(line)
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._fh is not None:
                self._fh.close()
                self._fh = None


_WORKER_STACK_BYTES = 256 * 1024
_SMALL_STACK_FROM = 64
STOP_GRACE_SECONDS = 3.0
_POLL_SECONDS = 0.5


def _set_worker_stack(size: int) -> int | None:
    """Set the stack size of threads created from now on; returns the previous size, or None if it cannot be set."""
    try:
        return threading.stack_size(size)
    except (ValueError, RuntimeError):
        return None


class _DaemonPool:
    """Minimal thread pool whose threads are daemons, so a job that never returns cannot hold the process open.

    ``ThreadPoolExecutor`` joins all of its threads at interpreter exit and in ``shutdown(wait=True)``; one stuck
    job then blocks both. Here a stuck thread is simply abandoned. Threads start on demand, and with many workers
    they get a small stack (most of them sleep in the pacer).
    """

    def __init__(self, workers: int) -> None:
        self._max = max(1, workers)
        self._small_stack = self._max > _SMALL_STACK_FROM
        self._tasks: queue.SimpleQueue = queue.SimpleQueue()
        self._started = 0
        self._released = False

    def submit(self, fn: Any, *args: Any) -> Future:
        fut: Future = Future()
        self._tasks.put((fut, fn, args))
        if self._started < self._max:
            self._started += 1
            previous = _set_worker_stack(_WORKER_STACK_BYTES) if self._small_stack else None
            try:
                threading.Thread(target=self._work, daemon=True, name="favicon-worker").start()
            finally:
                if previous is not None:
                    _set_worker_stack(previous)
        return fut

    def _work(self) -> None:
        while True:
            task = self._tasks.get()
            if task is None:
                return
            fut, fn, args = task
            if not fut.set_running_or_notify_cancel():
                continue
            try:
                fut.set_result(fn(*args))
            except BaseException as exc:      # handed to the collecting thread
                fut.set_exception(exc)

    def release(self) -> None:
        """Let idle threads exit; threads still inside a job are left behind."""
        if not self._released:
            self._released = True
            for _ in range(self._started):
                self._tasks.put(None)


def run_favicon_stage(fetcher: WebFetcher, jobs: list[dict[str, Any]], *, workers: int, max_icons: int, killed: Any = lambda: False,
                      icon_store: Any = None, on_record: Any = None, done: dict[tuple[str, int, str | None], dict[str, Any]] | None = None,
                      selection: str = "all", fallback: str = "always_if_no_image",
                      documents: dict[tuple[str, int], dict[str, Any]] | None = None, max_document_bytes: int = 0,
                      grace: float = STOP_GRACE_SECONDS, record_sink: Any = None) -> list[dict[str, Any]]:
    """``jobs``: dicts with scheme/ip/port/hostname. Returns one record per job, order preserved.

    With ``record_sink`` the final record of every job (fetched, reused or skipped) is handed to
    ``record_sink(job_index, record)`` instead of being collected, and the return value is empty.

    ``on_record`` receives each record fetched in this call as soon as it exists; ``done`` holds records from an
    earlier attempt, which are reused instead of fetched again. ``documents`` maps (ip, port) to the stored page of
    the HTTP stage (see ``capture_http_document``).

    ``killed`` is polled every half second. Once it is true no further address is started; lookups already running
    get ``grace`` seconds to finish, and whatever has not finished by then is recorded as skipped and left behind
    (its thread is a daemon), so the stage always returns.
    """
    abandoned = threading.Event()
    settle = threading.Lock()       # one decision per job: sunk by its worker, or skipped by wind_down, never both

    def prior_of(job: dict[str, Any]) -> dict[str, Any] | None:
        return done.get((job["ip"], job["port"], job.get("hostname"))) if done else None

    def skipped(job: dict[str, Any]) -> dict[str, Any]:
        return {"kind": "hostname" if job.get("hostname") else "direct_ip", "scheme": job["scheme"], "hostname": job.get("hostname"),
                "favicon_outcome": "skipped_kill_switch", "ip": job["ip"], "port": job["port"]}

    def one(job: dict[str, Any]) -> dict[str, Any]:
        prior = prior_of(job)
        if prior is not None:
            return prior
        if killed():
            return skipped(job)
        rec = probe_identity(fetcher, scheme=job["scheme"], ip=job["ip"], port=job["port"], hostname=job.get("hostname"), max_icons=max_icons,
                              icon_store=icon_store, selection=selection, fallback=fallback,
                              stored_document=(documents or {}).get((job["ip"], job["port"])), max_document_bytes=max_document_bytes)
        rec["ip"], rec["port"] = job["ip"], job["port"]
        if rec.get("favicon_outcome") == "document_failed" and rec.get("document_outcome") == "timeout" and killed():
            return skipped(job)     # cut short by the kill switch, not a verdict on the address
        if on_record is not None and not abandoned.is_set():
            try:
                on_record(rec)
            except OSError:
                pass        # a full disk must not cost the lookup that already succeeded
        return rec
    if not jobs:
        return []
    # One address at a time: every job for the same ip runs in sequence on one worker, so a scanned server never
    # sees the bare-IP request and several name-based requests at once. All ports of an address share one pacer
    # slot, so giving them separate workers would only leave one of the workers asleep in the pacer.
    groups: dict[str, list[int]] = {}
    for idx, job in enumerate(jobs):
        groups.setdefault(job["ip"], []).append(idx)
    out: list[dict[str, Any] | None] = [None] * len(jobs)

    def run_group(indexes: list[int]) -> None:
        for i in indexes:
            if abandoned.is_set():
                return
            rec = one(jobs[i])
            with settle:
                if abandoned.is_set():
                    return
                if record_sink is None:
                    out[i] = rec
                else:
                    record_sink(i, rec)
                    out[i] = True
    pool = _DaemonPool(workers)
    cap = 2 * max(1, workers)
    # Longest chains first, so the few addresses with many names do not set the tail of the stage.
    pending = iter(sorted(groups.values(), key=len, reverse=True))
    inflight: dict[Future, list[int]] = {}
    finished: queue.SimpleQueue = queue.SimpleQueue()     # futures in completion order, filled by the workers' done callbacks
    failure: BaseException | None = None

    def note_failure(exc: BaseException) -> None:
        nonlocal failure
        if failure is None:
            failure = exc

    def collect(timeout: float) -> None:
        """Wait up to ``timeout`` for one finished group, then take every other one that is already done.

        Blocking on a queue costs the same with 4,000 groups in flight as with one; ``concurrent.futures.wait`` over
        all of them registers a waiter on each future every call, which at thousands of workers took a large share
        of the interpreter's time.
        """
        nonlocal failure
        try:
            batch = [finished.get(timeout=timeout)]
        except queue.Empty:
            return
        while True:
            try:
                batch.append(finished.get_nowait())
            except queue.Empty:
                break
        for fut in batch:
            if inflight.pop(fut, None) is None:       # cancelled by wind_down, already accounted for
                continue
            exc = fut.exception()
            if exc is not None and failure is None:
                failure = exc

    def wind_down(patience: float) -> None:
        """Cancel what has not begun, wait up to ``patience`` for the rest, then walk away from whatever is stuck."""
        give_up = time.monotonic() + patience
        for fut in list(inflight):
            if fut.cancel():
                del inflight[fut]
        while inflight and time.monotonic() < give_up:
            collect(min(_POLL_SECONDS, max(0.01, give_up - time.monotonic())))
        with settle:
            abandoned.set()
            for i, rec in enumerate(out):     # never started or still stuck: the record of a job that begins after the kill
                if rec is None:
                    rec = prior_of(jobs[i]) or skipped(jobs[i])
                    if record_sink is None:
                        out[i] = rec
                    else:
                        try:
                            record_sink(i, rec)
                        except Exception as exc:
                            note_failure(exc)
                            break
                        out[i] = True
        pool.release()

    try:
        while not killed() and failure is None:
            while len(inflight) < cap:
                indexes = next(pending, None)
                if indexes is None:
                    break
                fut = pool.submit(run_group, indexes)
                inflight[fut] = indexes
                fut.add_done_callback(finished.put)
            if not inflight:
                break
            collect(_POLL_SECONDS)
        else:
            wind_down(grace)
        pool.release()
    except BaseException:
        wind_down(min(grace, 1.0))
        raise
    if failure is not None:
        raise failure
    return [] if record_sink is not None else [r for r in out if r is not None]


# ---- Several worker processes --------------------------------------------------------------------------------------
# One interpreter does the TLS, the decoding and the hashing of every request, so a single process tops out at one core.
# The jobs are split by address: every job of an address goes to the same process, whose pacer alone then guarantees
# the pause for that address. A job does not depend on the others, so the merged records equal a single-process run.

_BACKSTOP_SECONDS = 10.0      # after the stage grace, how long a worker process may take to exit before it is terminated


def partition_by_ip(jobs: list[dict[str, Any]], parts: int) -> list[list[int]]:
    """Indexes of ``jobs`` per partition, every address in exactly one. Deterministic.

    The longest chains are placed first, each on the partition holding the fewest jobs so far. Indexes inside a
    partition keep the original job order.
    """
    groups: dict[str, list[int]] = {}
    for idx, job in enumerate(jobs):
        groups.setdefault(job["ip"], []).append(idx)
    out: list[list[int]] = [[] for _ in range(max(1, parts))]
    for chain in sorted(groups.values(), key=lambda c: (-len(c), c[0])):
        min(out, key=len).extend(chain)
    return [sorted(p) for p in out if p]


def split_cap(total: int, parts: int) -> int:
    """Share of a global cap for each of ``parts`` processes: rounded down, so the sum never exceeds ``total``."""
    return max(1, total // parts)


class FetcherFactory:
    """Builds the confined fetcher inside a worker process from picklable ingredients (no off-host fetching).

    Only the endpoints (and sampled addresses) of the addresses the process owns are approved for it, so a redirect
    hop to an address owned by another process is refused before any connection, as is any unapproved endpoint.
    """

    def __init__(self, cfg: Any, sampled_ips: list[str], endpoints: set[tuple[str, int]], max_active_requests: int | None = None) -> None:
        self.cfg, self.sampled_ips, self.endpoints = cfg, sorted(set(sampled_ips)), set(endpoints)
        self.max_active_requests = max_active_requests

    def __call__(self, pacer: Any, owned: Any = None, killed: Any = None) -> Any:
        cfg = self.cfg
        sampled = [ip for ip in self.sampled_ips if owned is None or ip in owned]
        endpoints = {e for e in self.endpoints if owned is None or e[0] in owned}
        if self.max_active_requests is not None:
            # the configuration is a frozen dataclass: the share of this process goes into a copy
            cfg = dataclasses.replace(cfg, favicon=SimpleNamespace(**{**vars(cfg.favicon), "max_active_requests": self.max_active_requests}))
        return _make_local_fetcher(cfg, fetch_policy(cfg, sampled), RedirectResolver(cfg.dns.resolvers, cfg.dns.timeout),
                                   endpoints, pacer, killed or (lambda: False))


def _skipped(job: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "hostname" if job.get("hostname") else "direct_ip", "scheme": job["scheme"], "hostname": job.get("hostname"),
            "favicon_outcome": "skipped_kill_switch", "ip": job["ip"], "port": job["port"]}


def _failed(job: dict[str, Any], why: str) -> dict[str, Any]:
    return {**_skipped(job), "favicon_outcome": "error", "error": why[:300]}


class SharedFlag:
    """A stop flag in shared memory that takes no lock, with the ``is_set``/``set``/``clear`` of an event.

    A ``multiprocessing.Event`` guards its state with a lock held while the flag is read or written. A process killed
    inside that window leaves the lock taken for good, and every other process then blocks in ``is_set`` and the
    parent in ``set``. A single byte is read and written atomically, so no lock is needed.
    """

    def __init__(self, ctx: Any) -> None:
        self._value = ctx.RawValue(ctypes.c_bool, False)

    def is_set(self) -> bool:
        return bool(self._value.value)

    def set(self) -> None:
        self._value.value = True

    def clear(self) -> None:
        self._value.value = False

    def wait(self, timeout: float | None = None) -> bool:
        """Sleep in short slices until the flag is set or ``timeout`` seconds have passed."""
        end = None if timeout is None else time.monotonic() + timeout
        while not self.is_set():
            left = None if end is None else end - time.monotonic()
            if left is not None and left <= 0:
                break
            time.sleep(0.05 if left is None else min(0.05, left))
        return self.is_set()


def _worker_main(index: int, factory: Any, jobs: list[dict[str, Any]], settings: dict[str, Any], store_root: Any,
                 documents: dict[tuple[str, int], dict[str, Any]], done: dict[tuple[str, int, str | None], dict[str, Any]],
                 stop: Any, conn: Any, offhost_conn: Any = None) -> None:
    """``conn`` is the sending end of this process's own pipe, so a process killed mid-send blocks no other.

    Messages: ``("log", record)`` for a record fetched here, ``("rec", position, record)`` for every final record
    (position in ``jobs``), then ``("end", icon files)``, or ``("error", text)`` if the stage itself failed.
    """
    lock = threading.Lock()

    def send(message: tuple) -> None:
        with lock:
            conn.send(message)
    try:
        stopped = stop.is_set
        limiter = SubnetLimiter(settings["subnet_cap"]) if settings.get("subnet_cap") else None
        pacer = IpPacer(settings["pace"], stopped, stop_event=stop, poll=2.0, limiter=limiter)
        store = IconStore(store_root) if store_root is not None else None
        fetcher = factory(pacer, frozenset(j["ip"] for j in jobs), stopped)
        if offhost_conn is not None:       # icons on other hosts are fetched by the parent's service, once for all processes
            fetcher = RoutingFetcher(fetcher, OffhostClient(offhost_conn))
        run_favicon_stage(fetcher, jobs, workers=settings["workers"],
                          max_icons=settings["max_icons"], killed=stopped, icon_store=store, selection=settings["selection"],
                          fallback=settings["fallback"], documents=documents, max_document_bytes=settings["max_document_bytes"],
                          done=done, on_record=lambda rec: send(("log", rec)), grace=settings["grace"],
                          record_sink=lambda i, rec: send(("rec", i, rec)))
        send(("end", store.files() if store is not None else {}))
    except BaseException as exc:
        try:
            send(("error", f"{type(exc).__name__}: {exc}"))
        except (OSError, ValueError):
            pass


def run_favicon_stage_processes(factory: Any, jobs: list[dict[str, Any]], *, processes: int, workers: int, pace: float, max_icons: int,
                                killed: Any = lambda: False, icon_store: Any = None, selection: str = "all",
                                fallback: str = "always_if_no_image", documents: dict[tuple[str, int], dict[str, Any]] | None = None,
                                max_document_bytes: int = 0, on_record: Any = None,
                                done: dict[tuple[str, int, str | None], dict[str, Any]] | None = None,
                                grace: float = STOP_GRACE_SECONDS, record_sink: Any = None,
                                on_failure: Any = None, subnet_cap: int = 0, offhost_service: Any = None) -> list[dict[str, Any]]:
    """Like ``run_favicon_stage`` but over ``processes`` worker processes; one record per job, original order.

    ``factory(pacer, owned, killed)`` returns the fetcher (``owned``: the addresses of the process) and must be
    picklable (see ``FetcherFactory``). Each process gets its own pacer, fetcher, fingerprint cache and
    ``workers // processes`` threads (at least one), so the number of concurrent requests stays at most what
    ``workers`` says. Records stream back as the lookups finish: ``on_record`` and ``record_sink(job_index, record)``
    are called here, in the calling thread, as ``run_favicon_stage`` calls them.

    One difference from a single process: a process is approved only for its own addresses, so a redirect hop to an
    endpoint owned by another process is refused (``policy_refused``), exactly like a hop to any endpoint that is not
    approved; with one process the hop would be followed. This keeps every address contacted and paced by one process.

    With ``offhost_service`` (an ``OffhostService``) every process sends the icon URLs that lie on other hosts to the
    service in this process, which fetches each URL once, paces each destination address and counts the caps for all.

    ``killed`` is polled here and mirrored to the workers through an event, so a stop reaches every process within a
    poll; a process still running well after ``grace`` is terminated and its unfinished jobs recorded as skipped. A
    process that dies or raises yields ``error`` records for its unfinished jobs, and ``on_failure(reason, jobs_lost)``
    is called for it, so the caller can mark the stage as failed. Those error records are handed to ``record_sink``
    but not to ``on_record``: they are not lookups, and a resumed attempt must repeat them.
    """
    if not jobs:
        return []
    out: list[dict[str, Any] | None] = [None] * len(jobs)
    sunk: set[int] = set()

    def deliver(k: int, rec: dict[str, Any]) -> None:
        if k in sunk:
            return
        sunk.add(k)
        if record_sink is None:
            out[k] = rec
        else:
            record_sink(k, rec)

    def prior_of(job: dict[str, Any]) -> dict[str, Any] | None:
        return done.get((job["ip"], job["port"], job.get("hostname"))) if done else None

    def settle_rest(indexes: list[int], why: str | None) -> None:
        """Records for the jobs of a partition that never reported: a stop skips them, a failure is an error."""
        lost = 0
        for k in indexes:
            if k not in sunk:
                prior = prior_of(jobs[k])
                lost += prior is None
                deliver(k, prior or (_failed(jobs[k], why) if why else _skipped(jobs[k])))
        if why and lost and on_failure is not None:
            on_failure(why, lost)

    if killed():
        settle_rest(list(range(len(jobs))), None)
        return [] if record_sink is not None else [r for r in out if r is not None]
    parts = partition_by_ip(jobs, processes)
    store_root = icon_store.root if icon_store is not None else None
    ctx = multiprocessing.get_context("spawn")
    stop = SharedFlag(ctx)
    settings = {"pace": pace, "workers": split_cap(workers, len(parts)), "max_icons": max_icons, "selection": selection,
                "fallback": fallback, "max_document_bytes": max_document_bytes, "grace": grace,
                "subnet_cap": max(1, subnet_cap // len(parts)) if subnet_cap else 0}      # the cap is split over the processes
    procs, conns, sends = [], [], []
    for i, indexes in enumerate(parts):
        recv_end, send_end = ctx.Pipe(duplex=False)
        conns.append(recv_end)
        mine = [jobs[k] for k in indexes]
        owned = {j["ip"] for j in mine}
        keys = {(j["ip"], j["port"]) for j in mine}
        docs = {key: doc for key, doc in (documents or {}).items() if key in keys}
        earlier = {key: rec for key, rec in (done or {}).items() if key[0] in owned}
        off_end = offhost_service.open_channel(ctx) if offhost_service is not None else None
        procs.append(ctx.Process(target=_worker_main, name=f"favicon-{i}", daemon=True,
                                 args=(i, factory, mine, settings, store_root, docs, earlier, stop, send_end, off_end)))
        sends.append(send_end)
        if off_end is not None:
            sends.append(off_end)
    finished: set[int] = set()

    def handle(i: int, message: tuple) -> None:
        kind = message[0]
        if kind == "log":
            if on_record is not None:
                try:
                    on_record(message[1])
                except OSError:
                    pass        # a full disk must not cost the lookup that already succeeded
        elif kind == "rec":
            deliver(parts[i][message[1]], message[2])
        elif kind == "end":
            if icon_store is not None:
                icon_store.adopt(message[1])
            settle_rest(parts[i], f"favicon worker process {i}: incomplete result")
            finished.add(i)
        elif kind == "error":
            settle_rest(parts[i], f"favicon worker process {i}: {message[1]}")
            finished.add(i)

    def lost(i: int) -> None:
        """Process ``i`` is gone without a result: error records for what it left. The others carry on."""
        settle_rest(parts[i], f"favicon worker process {i}: exited with code {procs[i].exitcode} without a result")
        finished.add(i)

    def drain(i: int) -> None:
        while i not in finished:
            try:
                if not conns[i].poll(0):
                    return
                handle(i, conns[i].recv())
            except (EOFError, OSError):
                procs[i].join(2.0)          # the process is gone: whatever it did not report is lost
                lost(i)
                return

    try:
        for p in procs:
            p.start()
        for c in sends:                                # only the child holds a sending end now, so its death shows as EOF
            c.close()
        stopped_at: float | None = None
        while len(finished) < len(parts):
            live = [conns[i] for i in range(len(parts)) if i not in finished]
            ready = multiprocessing.connection.wait(live, timeout=_POLL_SECONDS)
            for i, c in enumerate(conns):
                if c in ready:
                    drain(i)
            if stopped_at is None and killed():
                stopped_at = time.monotonic()
                stop.set()
            for i, p in enumerate(procs):
                if i not in finished and not p.is_alive():
                    drain(i)                           # it may have answered just before exiting
                    if i not in finished:
                        lost(i)
            if stopped_at is not None and time.monotonic() - stopped_at > grace + _BACKSTOP_SECONDS:
                for i, p in enumerate(procs):
                    if i not in finished:
                        p.terminate()
                        drain(i)
                        settle_rest(parts[i], None)
                        finished.add(i)
    finally:
        for p in procs:                 # children first: the flag is lock-free, but nothing may wait on a child that is stuck
            if p.is_alive():
                p.terminate()
        for p in procs:
            if p.pid is not None:
                p.join(5.0)
        stop.set()
        for c in conns + sends:
            c.close()
        if icon_store is not None:
            icon_store.remove_temporary()              # a terminated process leaves its half-written files behind
    return [] if record_sink is not None else [r for r in out if r is not None]
