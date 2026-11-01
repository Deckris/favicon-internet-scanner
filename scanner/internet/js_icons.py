"""Icons set by JavaScript, found with a headless browser, for pages the plain fetch left without an icon.

Only a page whose static icon declarations and ``/favicon.ico`` fallback both gave no image is loaded in a browser,
so the stage costs nothing for the pages that already have an icon. The browser is a guest on the scanned address:

* a page load starts only after the per-address pause and the per-network cap of the pacer have been granted;
* every request the page makes passes ``BrowserRequestPolicy``: only the page's own address and port, and only
  documents, scripts, stylesheets and XHR/fetch calls. Images, fonts and media are blocked, and so is every other
  host. The browser never loads the icon itself;
* the icon URLs the page ended up declaring (and, with manifest parsing, the manifest's icons) are read from the
  DOM and fetched afterwards through the same guarded fetcher as every other icon, so hashing, storage, the
  off-host caps and their approval flag are unchanged;
* a page has a hard wall-clock budget, and a shard a page cap.

The browser driver is an object with ``start``, ``render`` and ``close`` so that tests run without a browser.
Playwright is imported only when a real driver starts; when it or its Chromium is missing the stage records
``js_icons=unavailable`` and the scan carries on.
"""
from __future__ import annotations

import html
import queue
import threading
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Callable
from urllib.parse import urlsplit

from scanner.favicon_discovery import manifest_icon_links, parse_icon_declarations, policy_for
from scanner.internet import profile

SOURCE = "javascript"
ALLOWED_RESOURCE_TYPES = frozenset({"document", "script", "stylesheet", "xhr", "fetch"})
MAX_REQUESTS_PER_PAGE = 60
BUDGET_GRACE_SECONDS = 2.0       # beyond the page timeout before the stage walks away from a driver that does not return
MAX_MANIFEST_BYTES = 262_144


class DriverUnavailable(Exception):
    """The browser package or the browser itself cannot be used on this host."""


@dataclass(frozen=True)
class RenderRequest:
    url: str
    ip: str
    port: int
    timeout_seconds: float
    wait_ms: int


@dataclass
class RenderedPage:
    links: list[dict[str, Any]] = field(default_factory=list)     # rel, href, sizes, type, media of the link elements after the scripts ran
    manifest_url: str | None = None
    requests: int = 0
    blocked: int = 0
    blocked_hosts: list[str] = field(default_factory=list)
    render_ms: int = 0
    error: str | None = None


class BrowserRequestPolicy:
    """Decides every request of one page load. The driver calls ``decide`` for each and obeys the answer."""

    def __init__(self, ip: str, allowed_endpoints: Any, *, max_requests: int = MAX_REQUESTS_PER_PAGE) -> None:
        self.ip, self.allowed_endpoints, self.max_requests = ip, frozenset(allowed_endpoints), max_requests
        self.requests = 0
        self.blocked = 0
        self.blocked_hosts: list[str] = []
        self._lock = threading.Lock()

    def decide(self, url: str, resource_type: str) -> bool:
        with self._lock:
            self.requests += 1
            ok = self._allowed(url, resource_type)
            if not ok:
                self.blocked += 1
                host = (urlsplit(url).hostname or url[:40]) if "://" in url else url[:40]
                if host not in self.blocked_hosts and len(self.blocked_hosts) < 20:
                    self.blocked_hosts.append(host)
            return ok

    def _allowed(self, url: str, resource_type: str) -> bool:
        if self.requests > self.max_requests or resource_type not in ALLOWED_RESOURCE_TYPES:
            return False
        try:
            parts = urlsplit(url)
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError:
            return False
        return parts.scheme in ("http", "https") and parts.hostname == self.ip and (self.ip, port) in self.allowed_endpoints


def candidate_pages(records: Any, cap: int) -> tuple[list[dict[str, Any]], int]:
    """The records that qualify, in job order, at most ``cap`` of them, and how many more qualified than the cap allows.

    A page qualifies when it was served as a page, no icon image was found (declared, or at /favicon.ico) and it was
    reached by its bare address: a name-based page would need the browser to resolve the name, which it must not.
    """
    picked: list[dict[str, Any]] = []
    over = 0
    for rec in records:
        if (rec.get("kind") == "direct_ip" and not rec.get("favicon_is_image") and rec.get("error") is None
                and rec.get("document_outcome") in ("ok", "http_status") and rec.get("http_status") == 200
                and rec.get("favicon_outcome") not in (None, "not_attempted", "skipped_kill_switch", "skipped_network_busy", "document_failed", "error")):
            if len(picked) < cap:
                picked.append(rec)
            else:
                over += 1
    return picked, over


def synthetic_html(links: list[dict[str, Any]]) -> str:
    """The icon link elements the browser's DOM ended up with, as markup that ``parse_icon_declarations`` reads."""
    parts = []
    for link in links:
        attrs = {k: link.get(k) for k in ("rel", "href", "sizes", "type", "media") if link.get(k)}
        if attrs.get("href"):
            parts.append("<link " + " ".join(f'{k}="{html.escape(str(v), quote=True)}"' for k, v in attrs.items()) + ">")
    return "<html><head>" + "".join(parts) + "</head></html>"


def _is_icon_link(link: dict[str, Any]) -> bool:
    return "icon" in (link.get("rel") or "").lower().replace("apple-touch-icon", "icon").split()


@dataclass
class StageResult:
    status: str = "ok"                                  # ok, unavailable, stopped
    detail: str | None = None
    replacements: dict[tuple[str, int, str | None], dict[str, Any]] = field(default_factory=dict)
    rows: list[dict[str, Any]] = field(default_factory=list)
    candidates: int = 0
    over_cap: int = 0

    def counts(self) -> dict[str, Any]:
        rows = self.rows
        extra = {"js_icons_detail": self.detail} if self.detail else {}
        return {**extra,
            "js_icons": self.status, "js_pages_candidates": self.candidates, "js_pages_over_cap": self.over_cap,
            "js_pages_attempted": sum(1 for r in rows if r["status"] != "skipped"),
            "js_pages_timeout": sum(1 for r in rows if r["status"] == "timeout"),
            "js_pages_with_icon_links": sum(1 for r in rows if r["icon_urls"]),
            "js_icons_found": len(self.replacements),
            "js_manifest_icons_used": sum(1 for r in rows if r.get("manifest_used")),
            "js_requests_blocked": sum(r.get("blocked", 0) for r in rows),
        }


def run_stage(candidates: list[dict[str, Any]], *, cfg_js: Any, driver_factory: Callable[[], Any], fetcher: Any, pacer: Any,
              allowed_endpoints: Any, fill: Callable[..., None], max_icons: int, icon_store: Any = None, selection: str = "all",
              concurrency: int = 1, killed: Callable[[], bool] = lambda: False, manifest: bool = True) -> StageResult:
    """Render ``candidates`` (see ``candidate_pages``) and fetch the icons found. Never raises for a bad page.

    ``fill(record, fetcher, url=, ip=, declared=, max_icons=, icon_store=, selection=, fallback=)`` writes the favicon
    fields of a record (``favicon.fill_icon_fields``). A record gets replaced only if an icon image was found.
    """
    result = StageResult(candidates=len(candidates))
    if not candidates:
        return result
    policy_decl = policy_for(manifest)
    work: queue.SimpleQueue = queue.SimpleQueue()
    for rec in candidates:
        work.put(rec)
    lock = threading.Lock()
    unavailable: list[str] = []

    def one(driver: Any, rec: dict[str, Any]) -> dict[str, Any]:
        ip, port = rec["ip"], rec["port"]
        url = rec["url"]
        row: dict[str, Any] = {"url": url, "ip": ip, "port": port, "status": "ok", "icon_urls": [], "manifest_url": None,
                               "manifest_used": False, "image_found": False, "requests": 0, "blocked": 0, "blocked_hosts": [],
                               "render_ms": None, "total_ms": None, "error": None}
        began = time.monotonic()
        if killed() or not pacer.wait(ip):
            row["status"] = "skipped"
            return row
        budget = float(cfg_js.page_timeout_seconds)
        policy = BrowserRequestPolicy(ip, allowed_endpoints)
        box: list[Any] = []

        def render() -> None:
            try:
                box.append(driver.render(RenderRequest(url, ip, port, budget, int(cfg_js.wait_ms)), policy))
            except BaseException as exc:         # whatever the driver does, the page is only recorded
                box.append(exc)
        thread = threading.Thread(target=render, daemon=True, name="js-render")
        thread.start()
        thread.join(budget + BUDGET_GRACE_SECONDS)
        page: RenderedPage | None = box[0] if box and isinstance(box[0], RenderedPage) else None
        if not box:
            row["status"] = "timeout"
            outcome = "timeout"
        elif page is None or page.error:
            row["status"] = "error"
            row["error"] = (page.error if page else f"{type(box[0]).__name__}: {box[0]}")[:200]
            outcome = "error"
        else:
            outcome = "ok"
        pacer.done(ip, SimpleNamespace(outcome=outcome, http_status=None, retry_after_seconds=None))
        row.update(requests=policy.requests, blocked=policy.blocked, blocked_hosts=list(policy.blocked_hosts))
        if page is not None:
            row.update(render_ms=page.render_ms, manifest_url=page.manifest_url)
        if row["status"] == "ok" and page is not None:
            declared_links = [link for link in page.links if _is_icon_link(link)]
            if not declared_links and manifest and page.manifest_url:
                extra = _manifest_links(fetcher, page.manifest_url, ip, port, policy_decl, max_icons)
                declared_links, row["manifest_used"] = extra, bool(extra)
            declared = parse_icon_declarations(url, synthetic_html(declared_links), max_icons=max_icons)
            row["icon_urls"] = [d.resolved_url[:200] for d in declared if d.resolved_url and d.policy_status == "selected"]
            if row["icon_urls"]:
                candidate = dict(rec)
                try:
                    fill(candidate, fetcher, url=url, ip=ip, declared=declared, max_icons=max_icons, icon_store=icon_store,
                         selection=selection, fallback="only_if_undeclared")
                except Exception as exc:
                    row["status"], row["error"] = "error", f"{type(exc).__name__}: {exc}"[:200]
                    candidate = None
                if candidate is not None and candidate.get("favicon_is_image"):
                    row["image_found"] = True
                    total = round((time.monotonic() - began) * 1000)
                    candidate.update(favicon_source=SOURCE, js_icon_urls=row["icon_urls"], js_render_ms=page.render_ms, js_total_ms=total,
                                     js_manifest_used=row["manifest_used"])
                    with lock:
                        result.replacements[(rec["ip"], rec["port"], rec.get("hostname"))] = candidate
        row["total_ms"] = round((time.monotonic() - began) * 1000)
        return row

    def worker() -> None:
        driver = None
        try:
            driver = driver_factory()
            driver.start()
        except DriverUnavailable as exc:
            unavailable.append(str(exc))
            return
        except Exception as exc:
            unavailable.append(f"{type(exc).__name__}: {exc}"[:200])
            return
        try:
            while not unavailable and not killed():
                try:
                    rec = work.get_nowait()
                except queue.Empty:
                    return
                row = one(driver, rec)
                with lock:
                    result.rows.append(row)
                if row["status"] == "timeout":       # the driver may be wedged inside the abandoned render: start a fresh one
                    try:
                        driver.close()
                        driver = driver_factory()
                        driver.start()
                    except Exception as exc:
                        unavailable.append(f"{type(exc).__name__}: {exc}"[:200])
                        return
        finally:
            try:
                driver.close()
            except Exception:
                pass

    threads = [threading.Thread(target=worker, daemon=True, name=f"js-worker-{n}") for n in range(max(1, min(concurrency, len(candidates))))]
    [t.start() for t in threads]
    [t.join() for t in threads]
    if unavailable and not result.rows:
        result.status, result.detail = "unavailable", unavailable[0]
    elif killed() and len(result.rows) < len(candidates):
        result.status = "stopped"
    return result


def _manifest_links(fetcher: Any, manifest_url: str, ip: str, port: int, policy: dict, limit: int) -> list[dict[str, Any]]:
    """The manifest's icons, when the manifest lies on the page's own address; any other host's manifest is not requested."""
    try:
        parts = urlsplit(manifest_url)
        if parts.hostname != ip or (parts.port or (443 if parts.scheme == "https" else 80)) != port:
            return []
        res, body = fetcher.fetch(manifest_url, connect_ip=ip, kind="document", context=f"scanner:{ip}:{port}")
    except Exception:
        return []
    if not body or res.http_status != 200 or len(body) > MAX_MANIFEST_BYTES:
        return []
    links = manifest_icon_links(manifest_url, body.decode("utf-8", errors="replace"), policy=policy, limit=limit)
    return [{**link, "rel": "icon"} for link in links]


# ---- Real browser ----------------------------------------------------------------------------------------------------

_COLLECT_LINKS = """() => {
  const out = [];
  document.querySelectorAll('link[rel]').forEach(l => {
    const rel = (l.getAttribute('rel') || '').toLowerCase();
    if (/(^|\\s)(icon|shortcut|apple-touch-icon|apple-touch-icon-precomposed|manifest)(\\s|$)/.test(rel))
      out.push({rel, href: l.href, sizes: l.getAttribute('sizes'), type: l.getAttribute('type'), media: l.getAttribute('media')});
  });
  return out;
}"""
_NO_SIDE_CHANNELS = "for (const n of ['WebSocket','EventSource','RTCPeerConnection','webkitRTCPeerConnection']) { try { window[n] = undefined; } catch (e) {} }"


class PlaywrightDriver:
    """One Chromium per driver; the stage runs one driver per worker thread (Playwright's sync API is bound to its thread)."""

    def __init__(self, user_agent: str) -> None:
        self.user_agent = user_agent
        self._pw = self._browser = None

    def start(self) -> None:
        try:
            from playwright.sync_api import sync_playwright       # optional dependency, see requirements-javascript.txt
        except ImportError as exc:
            raise DriverUnavailable("the playwright package is not installed") from exc
        try:
            self._pw = sync_playwright().start()
            # no name can resolve: pages are reached by address only, whatever a script asks for
            self._browser = self._pw.chromium.launch(headless=True, args=["--host-resolver-rules=MAP * ~NOTFOUND",
                                                                          "--disable-background-networking", "--disable-sync"])
        except Exception as exc:
            self.close()
            raise DriverUnavailable(f"chromium cannot start: {type(exc).__name__}: {exc}"[:200]) from exc

    def render(self, request: RenderRequest, policy: BrowserRequestPolicy) -> RenderedPage:
        began = time.monotonic()
        context = self._browser.new_context(ignore_https_errors=True, user_agent=self.user_agent, service_workers="block",
                                            accept_downloads=False, java_script_enabled=True)
        try:
            context.add_init_script(_NO_SIDE_CHANNELS)
            page = context.new_page()
            page.route("**/*", lambda route, req: route.continue_() if policy.decide(req.url, req.resource_type) else route.abort())
            page.set_default_timeout(request.timeout_seconds * 1000)
            page.goto(request.url, wait_until="domcontentloaded", timeout=request.timeout_seconds * 1000)
            if request.wait_ms:
                page.wait_for_timeout(request.wait_ms)
            links = page.evaluate(_COLLECT_LINKS)
        except Exception as exc:
            return RenderedPage(error=f"{type(exc).__name__}: {exc}"[:200], requests=policy.requests, blocked=policy.blocked,
                                render_ms=round((time.monotonic() - began) * 1000))
        finally:
            context.close()
        manifest = next((l["href"] for l in links if "manifest" in (l.get("rel") or "").split()), None)
        return RenderedPage(links=links, manifest_url=manifest, requests=policy.requests, blocked=policy.blocked,
                            blocked_hosts=list(policy.blocked_hosts), render_ms=round((time.monotonic() - began) * 1000))

    def close(self) -> None:
        for closer in (getattr(self._browser, "close", None), getattr(self._pw, "stop", None)):
            try:
                if closer:
                    closer()
            except Exception:
                pass
        self._pw = self._browser = None


def default_driver_factory(cfg: Any) -> Callable[[], Any]:
    return lambda: PlaywrightDriver(cfg.fetch.user_agent)


def apply_to_shard(cfg: Any, store: Any, fjobs: list[dict[str, Any]], *, fetcher: Any, pacer: Any, allowed_endpoints: Any,
                   icon_store: Any, killed: Callable[[], bool]) -> StageResult:
    """The pipeline's hook: pick the pages from the stored records, run the stage, store the replaced records."""
    from scanner.internet.favicon import fill_icon_fields
    js = cfg.favicon.javascript
    candidates, over = candidate_pages(store.iter_favicons(), js.max_pages_per_shard)
    concurrency = js.concurrency or profile.javascript_concurrency(profile.detect_cores(), profile.detect_memory_gb())
    result = run_stage(candidates, cfg_js=js, driver_factory=default_driver_factory(cfg), fetcher=fetcher, pacer=pacer,
                       allowed_endpoints=allowed_endpoints, fill=fill_icon_fields, max_icons=cfg.favicon.max_icons_per_page,
                       icon_store=icon_store, selection=cfg.favicon.icon_selection, concurrency=concurrency, killed=killed)
    result.over_cap = over
    position = {(j["ip"], j["port"], j.get("hostname")): i for i, j in enumerate(fjobs)}
    for key, rec in result.replacements.items():
        store.put_favicon(position[key], rec)
    return result
