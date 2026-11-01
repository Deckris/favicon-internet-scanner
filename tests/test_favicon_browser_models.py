"""The browser-model icon selection: rankings per model and the fetch walk of the ``browser_models`` mode."""
from __future__ import annotations

from scanner.favicon_acquire import acquire_favicons
from scanner.icon_selection import RULE_VERSION, IconCandidate, attempt_order, rank, winners
from scanner.internet import favicon as fav
from scanner.models import FetchResult
from urllib.parse import urlsplit
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


def cand(order, href=None, **kw):
    return IconCandidate(href=href or f"/i{order}.png", order=order, rel=kw.pop("rel", "icon"), **kw)


def hrefs(items):
    return [c.href for c in items]


def test_unsized_ties_go_to_the_first_in_chromium_and_the_last_in_spec_and_firefox():
    cands = [cand(1), cand(2), cand(3)]
    assert hrefs(rank("chromium", cands)) == ["/i1.png", "/i2.png", "/i3.png"]
    assert hrefs(rank("spec", cands)) == ["/i3.png", "/i2.png", "/i1.png"]
    assert rank("firefox", cands)[0].href == "/i3.png"
    w = winners(cands)
    assert w["chromium"].order == 1 and w["spec"].order == 3 and w["firefox"].order == 3


def test_chromium_prefers_sizes_near_16_and_32_and_any_scores_as_a_perfect_fit():
    cands = [cand(1, sizes="192x192"), cand(2, sizes="48x48"), cand(3, sizes="32x32"), cand(4, sizes="any")]
    assert [c.order for c in rank("chromium", cands)] == [3, 4, 2, 1]
    assert [c.order for c in rank("spec", cands)] == [4, 3, 2, 1]


def test_a_size_equal_to_16_ties_with_an_unsized_icon_and_the_first_declared_wins_in_chromium():
    cands = [cand(1), cand(2, sizes="16x16")]
    assert rank("chromium", cands)[0].order == 1
    assert rank("spec", cands)[0].order == 2


def test_apple_touch_and_mask_icons_are_dropped_for_the_desktop_models():
    cands = [cand(1, rel="apple-touch-icon", sizes="180x180"), cand(2, rel="mask-icon"), cand(3, rel="apple-touch-icon-precomposed")]
    for model in ("chromium", "firefox", "spec"):
        assert rank(model, cands) == []
    assert winners(cands) == {"chromium": None, "firefox": None, "spec": None}


def test_non_image_type_ranks_last_in_the_spec_model():
    cands = [cand(1, type="text/plain"), cand(2, sizes="64x64")]
    assert [c.order for c in rank("spec", cands)] == [2, 1]


def test_firefox_takes_the_last_svg_over_everything_else():
    cands = [cand(1, sizes="16x16"), cand(2, "/a.svg", type="image/svg+xml"), cand(3, "/b.svg"), cand(4, "/x.ico", type="image/x-icon")]
    assert [c.order for c in rank("firefox", cands)][:2] == [3, 2]


def test_firefox_width_16_beats_ico_and_ico_beats_a_larger_size():
    cands = [cand(1, "/big.png", sizes="32x32"), cand(2, "/fav.ico", type="image/vnd.microsoft.icon"), cand(3, "/small.png", sizes="16x16")]
    assert [c.order for c in rank("firefox", cands)] == [3, 2, 1]
    without16 = cands[:2]
    assert [c.order for c in rank("firefox", without16)] == [2, 1]


def test_firefox_smallest_at_or_above_16_with_the_last_declared_on_equal_width():
    cands = [cand(1, sizes="48x48"), cand(2, sizes="32x32"), cand(3, sizes="32x32"), cand(4, sizes="8x8")]
    assert [c.order for c in rank("firefox", cands)] == [3, 2, 1, 4]


def test_firefox_never_uses_rich_icons_and_falls_back_to_the_last_icon_otherwise():
    assert rank("firefox", [cand(1, sizes="96x96"), cand(2, sizes="180x180")]) == []
    cands = [cand(1), cand(2, sizes="8x8"), cand(3, sizes="128x128")]
    assert [c.order for c in rank("firefox", cands)] == [2, 1]
    assert hrefs(rank("firefox", [cand(1), cand(2)])) == ["/i2.png", "/i1.png"]


def test_a_failed_icon_is_followed_by_the_next_one_except_in_firefox():
    cands = [cand(1), cand(2), cand(3)]
    assert len(attempt_order("chromium", cands)) == 3
    assert len(attempt_order("spec", cands)) == 3
    assert [c.order for c in attempt_order("firefox", cands)] == [3]


def test_unknown_model_is_rejected():
    import pytest
    with pytest.raises(ValueError):
        rank("safari", [])


def run(html, icons, **kw):
    site = Site(html, icons)
    report: dict = {}
    decls, resources = acquire_favicons(PAGE, html, connect_ip=None, fetcher=site, selection="browser_models", report=report, **kw)
    return site, decls, resources, report


TWO = '<link rel="icon" href="/a.png"><link rel="icon" href="/b.png">'


def test_models_that_agree_cost_one_fetch_and_the_report_says_so():
    html = '<link rel="icon" href="/a.png" sizes="16x16"><link rel="icon" href="/b.png" sizes="64x64">'
    site, _, resources, report = run(html, {"/a.png", "/b.png"})
    assert site.icon_urls() == [PAGE + "a.png"]
    assert report["rule_version"] == RULE_VERSION and report["differ"] is False
    assert set(report["chosen"].values()) == {PAGE + "a.png"} and len(resources) == 1


def test_models_that_disagree_fetch_each_winner_once():
    site, _, resources, report = run(TWO, {"/a.png", "/b.png"})
    assert site.icon_urls() == [PAGE + "a.png", PAGE + "b.png"]
    assert report["chosen"] == {"chromium": PAGE + "a.png", "firefox": PAGE + "b.png", "spec": PAGE + "b.png"}
    assert report["differ"] is True
    assert resources[0].resolved_url == PAGE + "a.png"       # Chromium's choice leads the resources


def test_a_failed_winner_moves_chromium_and_spec_on_but_not_firefox():
    site, _, resources, report = run(TWO, {"/a.png"})
    assert report["chosen"] == {"chromium": PAGE + "a.png", "firefox": None, "spec": PAGE + "a.png"}
    assert site.icon_urls() == [PAGE + "a.png", PAGE + "b.png"]


def test_no_declared_icon_falls_back_to_favicon_ico():
    site, decls, resources, report = run("<html></html>", {"/favicon.ico"})
    assert site.icon_urls() == [PAGE + "favicon.ico"]
    assert decls[-1].kind == "fallback" and report["differ"] is False
    assert report["chosen"] == {"chromium": None, "firefox": None, "spec": None}


def test_only_apple_touch_icons_count_as_undeclared_for_the_only_if_undeclared_fallback():
    html = '<link rel="apple-touch-icon" href="/t.png">'
    site, _, _, _ = run(html, {"/favicon.ico"}, fallback="only_if_undeclared")
    assert site.icon_urls() == [PAGE + "favicon.ico"]


def test_probe_identity_records_the_rule_version_and_each_models_icon():
    site = Site(TWO, {"/a.png", "/b.png"})
    rec = fav.probe_identity(site, scheme="https", ip="203.0.113.7", port=443, hostname="origin.test", max_icons=4, selection="browser_models")
    assert rec["icon_rule_version"] == RULE_VERSION and rec["icon_models_differ"] is True
    assert rec["icon_chosen_chromium"].endswith("/a.png") and rec["icon_chosen_spec"].endswith("/b.png")
    assert rec["favicon_url"].endswith("/a.png") and rec["favicon_candidates"] == 2


def test_other_modes_keep_the_old_record_columns():
    site = Site(TWO, {"/a.png"})
    rec = fav.probe_identity(site, scheme="https", ip="203.0.113.7", port=443, hostname="origin.test", max_icons=4, selection="first_image")
    assert "icon_rule_version" not in rec


def test_a_repeated_url_counts_at_every_position_it_was_declared_in():
    html = ('<link rel="icon" href="/u1.png" sizes="16x16"><link rel="icon" href="/u2.png" sizes="16x16">'
            '<link rel="icon" href="/u1.png" sizes="16x16">')
    site, decls, resources, report = run(html, {"/u1.png", "/u2.png"})
    assert report["chosen"] == {"chromium": PAGE + "u1.png", "firefox": PAGE + "u1.png", "spec": PAGE + "u1.png"}
    assert site.icon_urls() == [PAGE + "u1.png"] and len(resources) == 1


def test_a_repeat_with_better_sizes_is_not_lost():
    html = '<link rel="icon" href="/a.png" sizes="128x128"><link rel="icon" href="/b.png" sizes="16x16"><link rel="icon" href="/a.png" sizes="16x16">'
    _, _, _, report = run(html, {"/a.png", "/b.png"})
    assert report["chosen"]["spec"] == PAGE + "a.png" and report["chosen"]["chromium"] == PAGE + "b.png"


def test_data_uri_svg_and_ico_icons_are_recognised():
    from scanner.icon_selection import is_ico, is_svg
    assert is_svg(cand(1, href="data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="))
    assert is_svg(cand(1, href="DATA:image/svg+xml,%3Csvg/%3E"))
    assert is_ico(cand(1, href="data:image/x-icon;base64,AAAB"))
    assert not is_svg(cand(1, href="data:image/png;base64,AAAA"))
    assert rank("firefox", [cand(1, sizes="16x16"), cand(2, href="data:image/svg+xml,%3Csvg/%3E")])[0].order == 2


def test_hostile_sizes_attributes_are_ignored_without_raising():
    import random

    from scanner.icon_selection import parse_sizes, pixel_score
    assert parse_sizes("16x16 ²x² ٣x٣ 0x16 1x" + "9" * 400 + " " + "9" * 5000 + "x1") == (False, [(16, 16)])
    assert parse_sizes("any 16x16 " + "16x16 " * 500)[0] is True
    assert pixel_score(cand(1, sizes="9" * 400 + "x" + "9" * 400)) == 1.0
    rng = random.Random(7)
    alphabet = "0123456789xX any\u00b2\u0663\uff11-+.e _\t\x00"
    for _ in range(2000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        is_any, found = parse_sizes(text)
        assert all(0 < w < 100000 and 0 < h < 100000 for w, h in found)
        assert 0.0 < pixel_score(cand(1, sizes=text)) <= 1.0
        rank("firefox", [cand(1, sizes=text), cand(2)])
