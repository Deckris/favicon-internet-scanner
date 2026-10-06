"""Acquire favicon resources for the declarations a page advertises.

One fetch per unique resolved URL; every declaration referencing a resource is
kept as provenance. `data:` URIs are decoded locally and never fetched. The
`/favicon.ico` fallback is only added when no declared icon yielded a decoded
image.
"""
from __future__ import annotations

from dataclasses import replace
from urllib.parse import urlsplit

from pipeline.favicon_hash import fingerprint as default_fingerprint
from scanner.favicon_discovery import FAVICON_POLICY, decode_data_uri, parse_icon_declarations
from scanner.models import FaviconDeclaration, FaviconResource


def _same_host_port(page_url: str, icon_url: str) -> bool:
    try:
        page = urlsplit(page_url)
        icon = urlsplit(icon_url)
        page_port = page.port or (443 if page.scheme == "https" else 80)
        icon_port = icon.port or (443 if icon.scheme == "https" else 80)
        return (page.hostname or "").lower() == (icon.hostname or "").lower() and page_port == icon_port
    except ValueError:
        # Let the fetcher's URL validation record the bad declaration, then try
        # the next icon/fallback. A bad port must not discard the whole page.
        return False


def _favicon_ico_url(page_url: str) -> str:
    parts = urlsplit(page_url)
    return f"{parts.scheme}://{parts.netloc}{FAVICON_POLICY['fallback']}"


def _append_order(resource: FaviconResource, order: int) -> FaviconResource:
    orders = tuple(sorted(set(resource.declaration_orders) | {order}))
    return replace(resource, declaration_orders=orders)


def _resource_has_image(resource: FaviconResource) -> bool:
    return bool(resource.fingerprint and resource.fingerprint.get("image_ok"))


def _fetch_resource(url: str, order: int, *, page_url: str, connect_ip: str | None, fetcher, fingerprint, on_icon=None) -> FaviconResource:
    icon_connect_ip = connect_ip if _same_host_port(page_url, url) else None
    fetch_result, body = fetcher.fetch(url, connect_ip=icon_connect_ip, kind="favicon", context=page_url)
    fp_dict = None
    decode_status = None
    sha256 = fetch_result.body_sha256
    nbytes = fetch_result.body_bytes
    if body:
        fp = fingerprint(body)
        fp_dict = fp.as_dict()
        decode_status = fp.decode_status
        sha256 = fp.content_sha256
        nbytes = fp.size_bytes
        if on_icon is not None and fp.image_ok:
            on_icon(sha256, body)
    return FaviconResource(
        resolved_url=url, final_url=fetch_result.final_url, declaration_orders=(order,),
        fetch=fetch_result, content_type_claimed=fetch_result.content_type,
        favicon_bytes=nbytes, favicon_sha256=sha256, decode_status=decode_status, fingerprint=fp_dict,
    )


def _decode_resource(data_uri: str, order: int, *, fingerprint, on_icon=None) -> FaviconResource:
    data, mime, status = decode_data_uri(data_uri)
    if data is None:
        return FaviconResource(
            resolved_url=data_uri, final_url=None, declaration_orders=(order,), fetch=None,
            content_type_claimed=mime, favicon_bytes=0, favicon_sha256=None, decode_status=status, fingerprint=None,
        )
    fp = fingerprint(data)
    if on_icon is not None and fp.image_ok:
        on_icon(fp.content_sha256, data)
    return FaviconResource(
        resolved_url=data_uri, final_url=None, declaration_orders=(order,), fetch=None,
        content_type_claimed=mime, favicon_bytes=fp.size_bytes, favicon_sha256=fp.content_sha256,
        decode_status=fp.decode_status, fingerprint=fp.as_dict(),
    )


def acquire_favicons(
    page_url: str,
    html: str | None,
    *,
    connect_ip: str | None,
    fetcher,
    max_icons: int = FAVICON_POLICY["max_icons"],
    fingerprint=default_fingerprint,
    on_icon=None,
) -> tuple[list[FaviconDeclaration], list[FaviconResource]]:
    declarations: list[FaviconDeclaration] = (
        parse_icon_declarations(page_url, html, max_icons=max_icons) if html is not None else []
    )
    resources: list[FaviconResource] = []
    index_by_url: dict[str, int] = {}
    max_order = 0

    for decl in declarations:
        max_order = max(max_order, decl.order)
        if decl.policy_status == "duplicate" and decl.resolved_url in index_by_url:
            idx = index_by_url[decl.resolved_url]
            resources[idx] = _append_order(resources[idx], decl.order)
            continue
        if decl.policy_status != "selected":
            continue
        assert decl.resolved_url is not None
        if decl.kind == "data":
            resource = _decode_resource(decl.resolved_url, decl.order, fingerprint=fingerprint, on_icon=on_icon)
        else:
            resource = _fetch_resource(decl.resolved_url, decl.order, page_url=page_url, connect_ip=connect_ip, fetcher=fetcher, fingerprint=fingerprint, on_icon=on_icon)
        index_by_url[decl.resolved_url] = len(resources)
        resources.append(resource)

    if not any(_resource_has_image(resource) for resource in resources):
        fallback_url = _favicon_ico_url(page_url)
        order = max_order + 1
        if fallback_url in index_by_url:
            idx = index_by_url[fallback_url]
            resources[idx] = _append_order(resources[idx], order)
            policy_status = "duplicate"
        else:
            resource = _fetch_resource(fallback_url, order, page_url=page_url, connect_ip=connect_ip, fetcher=fetcher, fingerprint=fingerprint, on_icon=on_icon)
            index_by_url[fallback_url] = len(resources)
            resources.append(resource)
            policy_status = "selected"
        declarations = [*declarations, FaviconDeclaration(
            page_url=page_url, order=order, rel=None, kind="fallback", sizes=None, type=None, media=None,
            declared_href=FAVICON_POLICY["fallback"], resolved_url=fallback_url, policy_status=policy_status,
        )]

    return declarations, resources


def first_icon_only(resources: list[FaviconResource]) -> list[FaviconResource]:
    """Ablation helper: what the old first-icon-only parser would have kept."""
    return resources[:1]


__all__ = ["acquire_favicons", "first_icon_only"]
