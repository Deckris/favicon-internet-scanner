"""Which declared icon a desktop browser shows in the tab, as three small pure models.

The rankings take the icons a page declares and return them in the order the model would try them; the first
entry is the model's winner when every download works, and the walk down the list is what happens when one fails.
Nothing here fetches anything.

``chromium``  components/favicon/core/favicon_handler.cc. Each candidate is scored against the desired pixel
              sizes 16 and 32 (16 and ceil(2 * 16) for the two desktop scales); ``sizes="any"`` and a missing
              ``sizes`` score 1.0 on desktop. The candidates are stable-sorted by score and a later candidate
              replaces the best one only when its score is strictly higher, so the first declared icon wins
              ties. A failed download moves on to the next candidate. The score used for a declared size is
              ``1 / (1 + |log2(size / desired)|)`` for the closest desired size, which approximates the
              browser's own metric rather than copying it.
``firefox``   browser/modules/FaviconLoader.sys.mjs (``selectIcons``, preferred width 16). Priority 1: an SVG
              (the last declared one), else an icon of width 16, else an ICO. Priority 2: the smallest icon that
              is at least 16 wide, the last declared one on equal width. Priority 3: the last icon that is not
              rich. Rich icons (width >= 96) are never used for the tab. There is no fallback after a failed
              load, so only the first ranked icon is ever tried.
``spec``      HTML Standard, rel=icon: the most appropriate icon by type, media and sizes, and among equally
              appropriate icons the last one in tree order. An unusable icon makes the agent take the next most
              appropriate one. Appropriateness is scored like the Chromium score above, with a non-image ``type``
              ranking last; ``media`` is not evaluated.

Safari is not modelled: its selection rule has not been verified.

``apple-touch-icon`` and ``mask-icon`` declarations are dropped, as the desktop tab does not use them.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable

RULE_VERSION = "icon-selection-browser-models-1"
MODELS = ("chromium", "firefox", "spec")

_DESIRED_PIXELS = (16, 32)
_FIREFOX_PREFERRED_WIDTH = 16
_FIREFOX_RICH_WIDTH = 96
_ICO_TYPES = ("image/x-icon", "image/vnd.microsoft.icon", "image/ico", "image/icon")
_NOT_DESKTOP_RELS = ("apple-touch-icon", "apple-touch-icon-precomposed", "mask-icon")


@dataclass(frozen=True)
class IconCandidate:
    """One declared icon. ``order`` is the position of its ``<link>`` in the document."""
    href: str
    order: int
    rel: str | None = None
    type: str | None = None
    sizes: str | None = None

    @classmethod
    def from_declaration(cls, decl) -> "IconCandidate":
        return cls(href=decl.resolved_url or decl.declared_href, order=decl.order, rel=decl.rel, type=decl.type, sizes=decl.sizes)


_MAX_SIZE_DIGITS = 5            # a side of 99999 px is far beyond any icon
_MAX_SIZE_TOKENS = 64
_ASCII_DIGITS = frozenset("0123456789")


def _side(text: str) -> int | None:
    if not 0 < len(text) <= _MAX_SIZE_DIGITS or not set(text) <= _ASCII_DIGITS:
        return None
    return int(text) or None


def parse_sizes(sizes: str | None) -> tuple[bool, list[tuple[int, int]]]:
    """``(any, [(width, height), ...])`` from a ``sizes`` attribute; tokens that do not parse are ignored.

    Only ASCII digits of at most ``_MAX_SIZE_DIGITS`` places count, and only the first ``_MAX_SIZE_TOKENS`` tokens
    are read, so a hostile attribute cannot raise or cost more than a bounded amount of work."""
    is_any = False
    found: list[tuple[int, int]] = []
    for token in (sizes or "")[:2048].lower().split()[:_MAX_SIZE_TOKENS]:
        if token == "any":
            is_any = True
            continue
        width, sep, height = token.partition("x")
        w, h = (_side(width), _side(height)) if sep else (None, None)
        if w is not None and h is not None:
            found.append((w, h))
    return is_any, found


def _width(cand: IconCandidate) -> int | None:
    """The width Firefox compares: the widest declared size, None when the icon declares none (or ``any``)."""
    _, found = parse_sizes(cand.sizes)
    return max((w for w, _ in found), default=None)


def _mime(cand: IconCandidate) -> str:
    return (cand.type or "").split(";")[0].strip().lower()


def _path(cand: IconCandidate) -> str:
    return cand.href.split("#")[0].split("?")[0].lower()


def _data_mime(cand: IconCandidate) -> str:
    """The media type named by a ``data:`` URI, or an empty string for any other address."""
    if cand.href[:5].lower() != "data:":
        return ""
    return cand.href[5:].split(",", 1)[0].split(";")[0].strip().lower()


def is_svg(cand: IconCandidate) -> bool:
    mime = _mime(cand) or _data_mime(cand)
    return mime == "image/svg+xml" or (not mime and _path(cand).endswith(".svg"))


def is_ico(cand: IconCandidate) -> bool:
    mime = _mime(cand) or _data_mime(cand)
    return mime in _ICO_TYPES or (not mime and _path(cand).endswith(".ico"))


def desktop_candidates(cands: Iterable[IconCandidate]) -> list[IconCandidate]:
    """Candidates in document order, without the icon kinds a desktop tab does not use."""
    kept = []
    for cand in sorted(cands, key=lambda c: c.order):
        tokens = (cand.rel or "").lower().split()
        if any(t in _NOT_DESKTOP_RELS for t in tokens):
            continue
        kept.append(cand)
    return kept


def pixel_score(cand: IconCandidate) -> float:
    """How well the declared sizes fit a 16 or 32 px tab icon, in (0, 1]; undeclared and ``any`` fit perfectly."""
    is_any, found = parse_sizes(cand.sizes)
    if is_any or not found:
        return 1.0
    best = 0.0
    for width, _ in found:
        for desired in _DESIRED_PIXELS:
            best = max(best, 1.0 / (1.0 + abs(math.log2(width / desired))))
    return best


def rank_chromium(cands: Iterable[IconCandidate]) -> list[IconCandidate]:
    return sorted(desktop_candidates(cands), key=lambda c: (-pixel_score(c), c.order))


def rank_spec(cands: Iterable[IconCandidate]) -> list[IconCandidate]:
    def key(c: IconCandidate):
        mime = _mime(c)
        unusable = bool(mime) and not mime.startswith("image/")
        return (unusable, -pixel_score(c), -c.order)
    return sorted(desktop_candidates(cands), key=key)


def rank_firefox(cands: Iterable[IconCandidate]) -> list[IconCandidate]:
    pool = [c for c in desktop_candidates(cands) if (_width(c) or 0) < _FIREFOX_RICH_WIDTH]

    def latest(items):
        return sorted(items, key=lambda c: -c.order)

    tiers: list[list[IconCandidate]] = [
        latest(c for c in pool if is_svg(c)),
        latest(c for c in pool if not is_svg(c) and _width(c) == _FIREFOX_PREFERRED_WIDTH),
        latest(c for c in pool if not is_svg(c) and is_ico(c)),
        sorted((c for c in pool if (_width(c) or 0) >= _FIREFOX_PREFERRED_WIDTH), key=lambda c: (_width(c), -c.order)),
        latest(pool),
    ]
    ranked: list[IconCandidate] = []
    for tier in tiers:
        for cand in tier:
            if cand not in ranked:
                ranked.append(cand)
    return ranked


_RANKERS = {"chromium": rank_chromium, "firefox": rank_firefox, "spec": rank_spec}
# Firefox does not try another icon when the preferred one fails to load.
RETRIES_AFTER_FAILURE = {"chromium": True, "firefox": False, "spec": True}


def rank(model: str, cands: Iterable[IconCandidate]) -> list[IconCandidate]:
    try:
        ranker = _RANKERS[model]
    except KeyError:
        raise ValueError(f"unknown icon model {model!r}") from None
    return ranker(list(cands))


def attempt_order(model: str, cands: Iterable[IconCandidate]) -> list[IconCandidate]:
    """The icons the model would actually try, in order: the whole ranking, or only its first entry."""
    ranked = rank(model, cands)
    return ranked if RETRIES_AFTER_FAILURE[model] else ranked[:1]


def winners(cands: Iterable[IconCandidate]) -> dict[str, IconCandidate | None]:
    """The first-ranked icon of every model, assuming every download works."""
    cands = list(cands)
    return {model: next(iter(rank(model, cands)), None) for model in MODELS}


__all__ = ["RULE_VERSION", "MODELS", "IconCandidate", "parse_sizes", "pixel_score", "rank", "attempt_order", "winners",
           "rank_chromium", "rank_firefox", "rank_spec", "desktop_candidates", "is_svg", "is_ico"]
