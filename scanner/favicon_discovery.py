"""Shared favicon declaration policy for brand collection and the scanner.

Parses static HTML `<link>` elements into ``FaviconDeclaration`` records. The
same parser backs both official brand-reference collection and scanned
candidate sites, so a single policy decides what counts as a favicon.
"""
from __future__ import annotations

import base64
from html.parser import HTMLParser
from typing import Any
from urllib.parse import unquote_to_bytes, urljoin, urlsplit

from scanner.models import FaviconDeclaration

FAVICON_POLICY: dict = {
    "version": "favicon-policy-1.0",
    "rels": ["icon", "shortcut icon", "apple-touch-icon", "apple-touch-icon-precomposed"],
    "max_icons": 8,
    "fallback": "/favicon.ico",
    "manifest": False,
    "javascript": False,
    "data_uri": "decode_local",
}

MAX_HTML_CHARS = 2_000_000
MAX_DATA_URI_SOURCE_CHARS = 8_000_000
MAX_DATA_URI_BYTES = 5 * 1024 * 1024


class _LinkParser(HTMLParser):
    """Collects `<link>` (and the first `<base>`) in document order."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_href: str | None = None
        self.links: list[dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        fields = {name.lower(): value for name, value in attrs}
        if tag == "base" and self.base_href is None and fields.get("href"):
            self.base_href = fields["href"]
            return
        if tag != "link" or not fields.get("href"):
            return
        rel_tokens = (fields.get("rel") or "").lower().split()
        self.links.append({
            "href": fields["href"],
            "rel_tokens": rel_tokens,
            "sizes": fields.get("sizes"),
            "type": fields.get("type"),
            "media": fields.get("media"),
        })


def _classify_rel(tokens: list[str]) -> str | None:
    unique = set(tokens)
    if "icon" in unique:
        return "icon"
    if "apple-touch-icon-precomposed" in unique:
        return "apple-touch-icon-precomposed"
    if "apple-touch-icon" in unique:
        return "apple-touch-icon"
    if "manifest" in unique:
        return "manifest"
    return None


def _safe_urljoin(base: str, href: str) -> str | None:
    try:
        return urljoin(base, href)
    except ValueError:
        return None


def _resolve_href(href: str, base: str) -> tuple[str | None, str | None]:
    """Returns ``(resolved_url, terminal_policy_status)``; status is None when resolvable."""
    href = href.strip()
    if not href:
        return None, "unsupported_scheme"
    resolved = _safe_urljoin(base, href)
    if resolved is None:
        return None, "unsupported_scheme"
    scheme = urlsplit(resolved).scheme.lower()
    if scheme not in ("http", "https"):
        return None, "unsupported_scheme"
    return resolved, None


def decode_data_uri(href: str) -> tuple[bytes | None, str | None, str]:
    """Decode a `data:` URI locally, bounded. Never used to trigger a network fetch."""
    if "," not in href:
        return None, None, "decode_failure"
    header, payload = href.split(",", 1)
    header = header[len("data:"):]
    is_base64 = header.endswith(";base64")
    mime = (header[:-7] if is_base64 else header).split(";")[0] or None
    if len(payload) > MAX_DATA_URI_SOURCE_CHARS:
        return None, mime, "size_limit"
    try:
        data = base64.b64decode(payload, validate=False) if is_base64 else unquote_to_bytes(payload)
    except Exception:
        return None, mime, "decode_failure"
    if len(data) > MAX_DATA_URI_BYTES:
        return None, mime, "size_limit"
    return data, mime, "ok"


def parse_icon_declarations(page_url: str, html: str, *, max_icons: int = FAVICON_POLICY["max_icons"]) -> list[FaviconDeclaration]:
    text = html or ""
    if len(text) > MAX_HTML_CHARS:
        text = text[:MAX_HTML_CHARS]
    parser = _LinkParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        pass

    base = page_url
    if parser.base_href:
        resolved_base = _safe_urljoin(page_url, parser.base_href)
        if resolved_base is not None:
            base = resolved_base

    declarations: list[FaviconDeclaration] = []
    seen: set[str] = set()
    selected_count = 0
    for order, link in enumerate(parser.links, start=1):
        rel_kind = _classify_rel(link["rel_tokens"])
        if rel_kind is None:
            continue
        href = str(link["href"])
        rel_str = " ".join(link["rel_tokens"]) or None
        common = {
            "page_url": page_url, "order": order, "rel": rel_str,
            "sizes": link["sizes"], "type": link["type"], "media": link["media"], "declared_href": href,
        }

        if rel_kind == "manifest":
            resolved = _safe_urljoin(base, href)
            declarations.append(FaviconDeclaration(**common, kind="manifest", resolved_url=resolved, policy_status="not_in_policy"))
            continue

        if href.lower().startswith("data:"):
            kind = "data"
            if href.lower().startswith("data:image/") and "," in href:
                resolved, terminal_status = href, None
            else:
                resolved, terminal_status = None, "unsupported_scheme"
        else:
            kind = rel_kind
            resolved, terminal_status = _resolve_href(href, base)

        if terminal_status is not None:
            declarations.append(FaviconDeclaration(**common, kind=kind, resolved_url=None, policy_status=terminal_status))
            continue

        assert resolved is not None
        if resolved in seen:
            status = "duplicate"
        else:
            seen.add(resolved)
            if selected_count < max_icons:
                status = "selected"
                selected_count += 1
            else:
                status = "over_limit"
        declarations.append(FaviconDeclaration(**common, kind=kind, resolved_url=resolved, policy_status=status))
    return declarations


__all__ = ["FAVICON_POLICY", "parse_icon_declarations", "decode_data_uri"]
