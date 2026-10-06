"""End-to-end favicon acquisition bugs found by the real isolated services."""
from scanner.internet import favicon
from tests.helpers import FakeFetcher


def test_bad_declared_port_does_not_lose_a_good_fallback():
    class BadDeclaration(FakeFetcher):
        def fetch(self, url, *, connect_ip, kind, context=""):
            result, body = super().fetch(url, connect_ip=connect_ip, kind=kind, context=context)
            if kind == "document":
                body = b'<html><link rel="icon" href="http://1.1.1.1:99999999/icon.png"></html>'
            elif ":99999999" in url:
                from dataclasses import replace
                result = replace(result, outcome="protocol_error", http_status=None)
                body = None
            return result, body
    record = favicon.probe_identity(BadDeclaration(), scheme="http", ip="1.1.1.1", port=80,
                                     hostname=None, max_icons=4)
    assert record["error"] is None
    assert record["favicon_is_image"] and record["favicon_url"].endswith("/favicon.ico")


def test_large_png_is_refused_before_pixel_decode():
    import io
    from PIL import Image
    from pipeline.favicon_hash import fingerprint
    buf = io.BytesIO()
    Image.new("RGB", (1025, 1025)).save(buf, "PNG")
    result = fingerprint(buf.getvalue())
    assert not result.image_ok and result.decode_status == "pixel_limit"
