"""Positive control for the favicon path. Talks to 127.0.0.1 only.

Three throwaway local servers stand in for scanned hosts, so the real fetcher, parser and image
check are exercised end to end without touching the Internet:

* ``declared``  - the page declares ``<link rel=icon>`` and serves a real PNG
* ``fallback``  - the page declares nothing; ``/favicon.ico`` is a real PNG
* ``catchall``  - every path returns an HTML 200 page (must NOT be counted as an icon)
"""
from __future__ import annotations

import io
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from scanner.internet import favicon as fav
from scanner.safety import TargetPolicy


def _png() -> bytes:
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), (40, 90, 200)).save(buf, format="PNG")
    return buf.getvalue()


def _handler(kind: str, icon: bytes) -> type[BaseHTTPRequestHandler]:
    class H(BaseHTTPRequestHandler):
        def log_message(self, *_a: Any) -> None:
            return

        def _send(self, status: int, ctype: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:      # noqa: N802
            path = self.path.split("?", 1)[0]
            page = b"<html><head><title>selftest</title>%s</head><body>hello</body></html>"
            if kind == "catchall":
                self._send(200, "text/html", page % b"")
            elif path == "/" and kind == "declared":
                self._send(200, "text/html", page % b'<link rel="icon" href="/static/brand.png">')
            elif path == "/":
                self._send(200, "text/html", page % b"")
            elif (path == "/static/brand.png" and kind == "declared") or (path == "/favicon.ico" and kind == "fallback"):
                self._send(200, "image/png", icon)
            else:
                self._send(404, "text/plain", b"not found")
    return H


class _NoDns:
    def resolve_a(self, _hostname: str) -> list[str]:
        return []


def run_selftest(cfg: Any) -> dict[str, Any]:
    icon = _png()
    servers = {k: ThreadingHTTPServer(("127.0.0.1", 0), _handler(k, icon)) for k in ("declared", "fallback", "catchall")}
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers.values()]
    for t in threads:
        t.start()
    cases: list[dict[str, Any]] = []
    try:
        endpoints = {("127.0.0.1", s.server_address[1]) for s in servers.values()}
        fetcher = fav.GuardedFetcher(
            TargetPolicy.for_tests(["127.0.0.1/32"]), _NoDns(), user_agent=cfg.fetch.user_agent, allowed_endpoints=endpoints,
            document_limits=fav._limits(cfg, cfg.fetch.max_document_bytes), favicon_limits=fav._limits(cfg, cfg.fetch.max_favicon_bytes))
        expect = {"declared": True, "fallback": True, "catchall": False}
        for kind, server in servers.items():
            rec = fav.probe_identity(fetcher, scheme="http", ip="127.0.0.1", port=server.server_address[1], hostname=None, max_icons=4)
            ok = rec["favicon_is_image"] is expect[kind] and rec["error"] is None
            cases.append({"case": kind, "expected_image": expect[kind], "got_image": rec["favicon_is_image"],
                          "outcome": rec["favicon_outcome"], "favicon_url": rec["favicon_url"], "ok": ok})
    finally:
        for s in servers.values():
            s.shutdown()
            s.server_close()
    return {"ok": all(c["ok"] for c in cases), "cases": cases}
