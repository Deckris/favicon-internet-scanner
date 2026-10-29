"""Icon selection modes and the /favicon.ico fallback modes of the favicon stage."""
from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from scanner.favicon_acquire import acquire_favicons
from scanner.favicon_discovery import parse_icon_declarations, rank_icon_declarations
from scanner.internet import favicon as fav
from scanner.models import FetchResult
from tests.helpers import make_png

PAGE = "https://origin.test/"
PNG = make_png()


class Site:
    """Serves a page plus a set of icon paths; every other favicon request answers 404."""

    def __init__(self, html: str, icons: set[str]) -> None:
        self.html, self.icons, self.calls = html, icons, []

    def fetch(self, url, *, connect_ip, kind, context=""):
        self.calls.append((url, kind))
        path = urlsplit(url).path
        if kind == "document":
            body, status, ctype = self.html.encode(), 200, "text/html"
        elif path in self.icons:
            body, status, ctype = PNG, 200, "image/png"
        else:
            body, status, ctype = b"", 404, "text/plain"
        return FetchResult(
            kind=kind, requested_url=url, connect_ip=connect_ip, host_header=None, sni=None, outcome="ok" if status == 200 else "http_status",
            failure_category=None, http_status=status, content_type=ctype, content_encoding=None, retry_after=None,
            body_sha256="x" * 64, body_bytes=len(body), redirect_chain=(), final_url=url, certificate=None,
        ), (body or None)

    def icon_urls(self):
        return [url for url, kind in self.calls if kind == "favicon"]


THREE = ('<link rel="icon" href="/a.png"><link rel="icon" href="/b.png" sizes="32x32">'
         '<link rel="apple-touch-icon" href="/c.png" sizes="180x180">')


def run(html, icons, **kw):
    site = Site(html, icons)
    decls, resources = acquire_favicons(PAGE, html, connect_ip=None, fetcher=site, **kw)
    return site, decls, resources


def test_all_fetches_every_declared_icon():
    site, decls, resources = run(THREE, {"/a.png", "/b.png", "/c.png"}, selection="all")
    assert site.icon_urls() == [PAGE + "a.png", PAGE + "b.png", PAGE + "c.png"]
    assert len(resources) == 3 and len(decls) == 3


def test_first_image_stops_after_the_first_decoded_icon_and_stores_the_same_icon():
    every, _, resources_all = run(THREE, {"/a.png", "/b.png", "/c.png"}, selection="all")
    first, decls, resources_first = run(THREE, {"/a.png", "/b.png", "/c.png"}, selection="first_image")
    assert first.icon_urls() == [PAGE + "a.png"]
    assert len(decls) == 3, "every declaration is still reported"
    assert resources_first[0].favicon_sha256 == resources_all[0].favicon_sha256
    assert resources_first[0].resolved_url == resources_all[0].resolved_url


def test_first_image_keeps_going_while_icons_fail():
    site, _, resources = run(THREE, {"/c.png"}, selection="first_image")
    assert site.icon_urls() == [PAGE + "a.png", PAGE + "b.png", PAGE + "c.png"]
    assert resources[-1].fingerprint["image_ok"]


def test_browser_mode_tries_the_best_candidate_first():
    site, _, resources = run(THREE, {"/a.png", "/b.png", "/c.png"}, selection="browser")
    assert site.icon_urls() == [PAGE + "b.png"]
    assert resources[0].resolved_url == PAGE + "b.png"


def test_browser_mode_falls_back_to_the_next_candidate():
    site, _, resources = run(THREE, {"/a.png"}, selection="browser")
    assert site.icon_urls() == [PAGE + "b.png", PAGE + "a.png"]
    assert resources[-1].fingerprint["image_ok"]


def test_rank_prefers_icon_over_touch_icon_image_type_and_size_near_32_and_later_declaration():
    html = ('<link rel="apple-touch-icon" href="/t.png" sizes="32x32">'
            '<link rel="icon" href="/big.png" sizes="256x256">'
            '<link rel="icon" href="/svg" type="image/svg+xml" sizes="any">'
            '<link rel="icon" href="/odd" type="text/plain" sizes="32x32">'
            '<link rel="icon" href="/p1.png" sizes="32x32"><link rel="icon" href="/p2.png" sizes="32x32">')
    ranked = [d.declared_href for d in rank_icon_declarations(parse_icon_declarations(PAGE, html))]
    assert ranked == ["/p2.png", "/p1.png", "/svg", "/big.png", "/odd", "/t.png"]


def test_duplicate_declarations_keep_their_provenance_in_every_mode():
    html = '<link rel="icon" href="/a.png"><link rel="shortcut icon" href="/a.png">'
    for mode in ("all", "first_image", "browser"):
        _, _, resources = run(html, {"/a.png"}, selection=mode)
        assert resources[0].declaration_orders == (1, 2)


def test_fallback_default_probes_favicon_ico_when_no_declared_icon_decoded():
    site, decls, _ = run('<link rel="icon" href="/gone.png">', {"/favicon.ico"})
    assert site.icon_urls() == [PAGE + "gone.png", PAGE + "favicon.ico"]
    assert decls[-1].kind == "fallback"


def test_only_if_undeclared_skips_the_probe_when_the_page_declares_an_icon():
    site, decls, resources = run('<link rel="icon" href="/gone.png">', {"/favicon.ico"}, fallback="only_if_undeclared")
    assert site.icon_urls() == [PAGE + "gone.png"]
    assert all(d.kind != "fallback" for d in decls) and not resources[0].fingerprint


def test_only_if_undeclared_still_probes_when_nothing_is_declared_or_the_page_is_missing():
    site, _, resources = run("<html></html>", {"/favicon.ico"}, fallback="only_if_undeclared")
    assert site.icon_urls() == [PAGE + "favicon.ico"] and resources[0].fingerprint["image_ok"]
    site = Site("", {"/favicon.ico"})
    acquire_favicons(PAGE, None, connect_ip=None, fetcher=site, fallback="only_if_undeclared")
    assert site.icon_urls() == [PAGE + "favicon.ico"]


def test_unknown_modes_are_rejected():
    with pytest.raises(ValueError):
        acquire_favicons(PAGE, "", connect_ip=None, fetcher=Site("", set()), selection="best")
    with pytest.raises(ValueError):
        acquire_favicons(PAGE, "", connect_ip=None, fetcher=Site("", set()), fallback="never")


def test_probe_identity_records_the_same_favicon_whichever_selection_is_used():
    records = {}
    for mode in ("all", "first_image"):
        site = Site(THREE, {"/a.png", "/b.png", "/c.png"})
        records[mode] = fav.probe_identity(site, scheme="https", ip="203.0.113.7", port=443, hostname="origin.test", max_icons=4, selection=mode)
    assert records["all"]["favicon_sha256"] == records["first_image"]["favicon_sha256"]
    assert records["all"]["favicon_url"] == records["first_image"]["favicon_url"]
    assert records["all"]["icon_declared_count"] == records["first_image"]["icon_declared_count"] == 3
    assert records["first_image"]["favicon_candidates"] == 1 and records["all"]["favicon_candidates"] == 3
