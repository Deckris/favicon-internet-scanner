"""Reusing the page the HTTP stage fetched for a plain-HTTP bare-IP job."""
from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from scanner.internet import favicon as fav
from scanner.internet.config import load_config
from scanner.models import FetchResult
from scanner.safety import TargetPolicy
from scanner.zgrab_runner import ZGrabTarget, run_zgrab_batches
from tests.helpers import make_png, write_config

IP = "198.51.100.130"
HTML = ('<html><head><title>  Shop   front </title><link rel="icon" href="/a.png">'
        '<link rel="icon" href="/b.png" sizes="32x32"></head><body>hi</body></html>')
PNG = make_png()


def zgrab_line(*, ip=IP, status="success", code=200, headers=None, body=HTML, domain=None):
    obj = {"ip": ip, "data": {"http": {"status": status, "result": {"response": {
        "status_code": code, "headers": headers if headers is not None else {"content_type": ["text/html; charset=utf-8"]}, "body": body}}}}}
    if domain:
        obj["domain"] = domain
    return json.dumps(obj)


class Site:
    """The same page and icons the stored document describes, served live."""

    def __init__(self, html=HTML, code=200, headers=None):
        self.html, self.code, self.calls = html, code, []

    def fetch(self, url, *, connect_ip, kind, context=""):
        self.calls.append((url, kind))
        if kind == "document":
            body, status, ctype = self.html.encode(), self.code, "text/html; charset=utf-8"
        elif urlsplit(url).path in ("/a.png", "/b.png"):
            body, status, ctype = PNG, 200, "image/png"
        else:
            body, status, ctype = b"", 404, "text/plain"
        return FetchResult(
            kind=kind, requested_url=url, connect_ip=connect_ip, host_header=None, sni=None, outcome="ok" if status == 200 else "http_status",
            failure_category=None, http_status=status, content_type=ctype, content_encoding=None, retry_after=None,
            body_sha256="x" * 64, body_bytes=len(body), redirect_chain=(), final_url=url, certificate=None,
        ), (body or None)

    def kinds(self):
        return [kind for _, kind in self.calls]


def stored(**kw):
    got = fav.capture_http_document(zgrab_line(**kw), port=80, max_icons=4)
    assert got is not None
    return got[1]


def probe(site, doc=None, *, scheme="http", hostname=None, limit=1 << 20):
    return fav.probe_identity(site, scheme=scheme, ip=IP, port=80, hostname=hostname, max_icons=4,
                              stored_document=doc, max_document_bytes=limit)


def test_capture_keeps_facts_and_declarations_but_not_the_body():
    key, doc = fav.capture_http_document(zgrab_line(), port=80, max_icons=4)
    assert key == (IP, 80)
    assert doc["http_status"] == 200 and doc["content_type"].startswith("text/html") and doc["document_title"] == "Shop front"
    assert doc["body_bytes"] == len(HTML.encode()) and len(doc["document_body_sha256"]) == 64
    assert [d["declared_href"] for d in doc["declarations"]] == ["/a.png", "/b.png"]
    assert "body" not in doc and "hi</body>" not in json.dumps(doc)


@pytest.mark.parametrize("line", [
    zgrab_line(status="io-timeout"), zgrab_line(domain="www.example.test"), zgrab_line(body=None), "not json", "{}",
])
def test_capture_ignores_lines_that_are_not_a_bare_ip_page(line):
    assert fav.capture_http_document(line, port=80, max_icons=4) is None


def test_reused_document_gives_the_same_record_without_asking_for_the_page():
    live_site, reused_site = Site(), Site()
    live = probe(live_site)
    reused = probe(reused_site, stored())
    assert "document" in live_site.kinds() and "document" not in reused_site.kinds()
    assert (live["document_source"], reused["document_source"]) == ("fetched", "reused")
    same = ("document_outcome", "http_status", "final_url", "content_type", "document_title", "document_body_sha256",
            "favicon_url", "favicon_sha256", "favicon_outcome", "icon_declared_count", "icon_declared_kinds", "favicon_is_image")
    assert {k: live[k] for k in same} == {k: reused[k] for k in same}
    assert reused_site.kinds() == live_site.kinds()[1:], "only the page request is saved"


@pytest.mark.parametrize("change", [
    {"code": 301, "headers": {"content_type": ["text/html"], "location": ["http://x.test/"]}},
    {"code": 404},
    {"headers": {"content_type": ["text/html"], "content_encoding": ["gzip"]}},
    {"headers": {"content_type": ["text/plain"]}},
    {"headers": {}},
    {"body": ""},
])
def test_pages_that_a_fetch_could_answer_differently_are_fetched(change):
    site = Site()
    record = probe(site, stored(**change))
    assert "document" in site.kinds() and record["document_source"] == "fetched"


def test_large_pages_and_other_job_kinds_are_fetched():
    big = stored(body="<html>" + "x" * 250_000 + "</html>")
    for doc, kw in [(big, {}), (stored(), {"scheme": "https"}), (stored(), {"hostname": "www.example.test"}), (stored(), {"limit": 100})]:
        site = Site()
        assert probe(site, doc, **kw)["document_source"] == "fetched" and "document" in site.kinds()


def test_run_favicon_stage_hands_each_job_its_own_stored_page():
    jobs = [{"scheme": "http", "ip": IP, "port": 80, "hostname": None}, {"scheme": "http", "ip": "198.51.100.131", "port": 80, "hostname": None}]
    site = Site()
    out = fav.run_favicon_stage(site, jobs, workers=2, max_icons=4, documents={(IP, 80): stored()}, max_document_bytes=1 << 20)
    assert [r["document_source"] for r in out] == ["reused", "fetched"]
    assert site.kinds().count("document") == 1


def test_runner_passes_every_output_line_to_the_sink(tmp_path):
    cfg = SimpleNamespace(
        vantage=SimpleNamespace(id="v", interface="eth0", source_ipv4="198.51.100.200", gateway_ipv4="198.51.100.254"),
        measurement=SimpleNamespace(zgrab_connect_timeout=2, zgrab_target_timeout=4, zgrab_senders=5, zgrab_batch_size=10),
        fetch=SimpleNamespace(user_agent="test-agent (+https://example.org/scan; contact optout@example.org)"))
    policy = TargetPolicy.for_tests(["198.51.100.128/25"], exclusions=[])
    out = zgrab_line(ip="198.51.100.130") + "\n" + zgrab_line(ip="198.51.100.131", status="io-timeout") + "\n"
    seen = []
    run_zgrab_batches([ZGrabTarget("198.51.100.130", None, 80), ZGrabTarget("198.51.100.131", None, 80)], scheme="http", mode="direct_ip",
                      cfg=cfg, policy=policy, run_dir=tmp_path,
                      executor=lambda command, **kw: SimpleNamespace(returncode=0, stdout=out, stderr=""),
                      document_sink=lambda line, port: seen.append((json.loads(line)["ip"], port)))
    assert seen == [("198.51.100.130", 80), ("198.51.100.131", 80)]


def test_the_setting_is_off_unless_asked_for(tmp_path):
    assert load_config(write_config(tmp_path)).favicon.reuse_http_document is False


def test_pipeline_reuses_the_http_page_when_asked(tmp_path):
    from tests.helpers import FakeFetcher
    from tests.test_pipeline import IP_HTTP, go, row, rows_of, tools

    results = {}
    for reuse in (False, True):
        work = tmp_path / str(reuse)
        work.mkdir()
        favicon = {"enabled": True, "max_hostnames_per_endpoint": 3, "workers": 2, "max_icons_per_page": 4, "reuse_http_document": reuse}
        fetcher = FakeFetcher()
        run_dir = go(load_config(write_config(work, favicon=favicon)), tools(), fetcher=fetcher)
        http_row = row(rows_of(run_dir), IP_HTTP, None)
        asked = [url for url, _, kind in fetcher.calls if kind == "document" and f"//{IP_HTTP}:80/" in url]
        results[reuse] = (http_row, asked, run_dir)
    off, on = results[False], results[True]
    assert off[0]["direct_document_source"] == "fetched" and len(off[1]) == 1 and not (off[2] / "normalized" / "http_documents.jsonl").exists()
    assert on[0]["direct_document_source"] == "reused" and on[1] == []
    assert (on[2] / "normalized" / "http_documents.jsonl").exists()
    assert on[0]["direct_document_title"] == off[0]["direct_document_title"]
    assert json.loads((on[2] / "manifest.json").read_text())["stage_counts"]["favicon_documents_reused"] == 1
