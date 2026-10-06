"""Tarpit flag and the no-traffic enrichments (page facts, icons declared elsewhere)."""
import csv

import yaml

from scanner.internet import favicon as fav
from scanner.internet.config import load_config
from scanner.internet.enrich import clean_text, parse_synack_csv, tarpit_assessment
from scanner.models import FetchResult
from tests.helpers import FakeFetcher, make_png, write_config
from tests.test_pipeline import IP_OK, go, rows_of, tools

TARPIT, MIXED, ONE = "1.1.1.6", "1.1.1.7", "1.1.1.8"


def ep(protocol="tcp_only", window=64240, doc=None, status=200):
    return {"protocol": protocol, "window": window, "doc_sha256": doc, "doc_status": status if doc else None}


def test_silent_open_on_many_ports_is_medium_confidence():
    r = tarpit_assessment([ep()] * 5, 5, 4)
    assert r["tarpit_suspect"] and r["tarpit_confidence"] == "medium" and r["tarpit_signals"] == ["silent_open_many"]
    assert "5/5" in r["tarpit_reason"]
    assert not tarpit_assessment([ep()] * 3, 5, 4)["tarpit_suspect"]                                   # below the threshold
    assert not tarpit_assessment([ep()] * 4 + [ep("http")], 5, 4)["tarpit_suspect"]                     # one real answer clears it
    assert not tarpit_assessment([ep(), ep("tls_unestablished"), ep(), ep()], 5, 4)["tarpit_suspect"]
    assert not tarpit_assessment([ep()] * 2, 2, 2)["tarpit_suspect"]                                    # too few scanned ports to judge


def test_zero_and_tiny_syn_ack_window_is_high_confidence_even_on_one_port():
    zero = tarpit_assessment([ep("http", window=0)], 5, 4)
    assert zero["tarpit_suspect"] and zero["tarpit_confidence"] == "high" and "zero_window" in zero["tarpit_signals"]
    tiny = tarpit_assessment([ep("tcp_only", window=5)], 5, 4)
    assert tiny["tarpit_confidence"] == "high" and tiny["tarpit_signals"] == ["tiny_window"]
    assert not tarpit_assessment([ep("http", window=246), ep("https", window=65535)], 5, 4)["tarpit_suspect"]   # normal windows
    assert not tarpit_assessment([ep("tcp_only", window=None)], 5, 4)["tarpit_suspect"]                         # no window data, no verdict


def test_identical_content_alone_is_low_confidence_and_never_flags():
    same = [ep("http", doc="a" * 64), ep("https", doc="a" * 64), ep("http", doc="a" * 64)]
    r = tarpit_assessment(same, 5, 4)
    assert r["tarpit_signals"] == ["identical_content"] and r["tarpit_confidence"] == "low" and not r["tarpit_suspect"]
    different = [ep("http", doc="a" * 64), ep("https", doc="b" * 64), ep("http", doc="c" * 64)]
    assert tarpit_assessment(different, 5, 4)["tarpit_signals"] == []
    assert tarpit_assessment(same[:2], 5, 4)["tarpit_signals"] == []                                   # two ports are not enough


def test_synack_csv_parsing_tolerates_missing_and_bad_columns():
    got = parse_synack_csv("\n".join(["1.1.1.1,0,64", "2.2.2.2", "3.3.3.3,abc,x", "1.1.1.1,9,9", ""]))
    assert got["1.1.1.1"] == {"window": 0, "ttl": 64}                    # first row wins
    assert got["2.2.2.2"] == {"window": None, "ttl": None}
    assert got["3.3.3.3"] == {"window": None, "ttl": None}


def _tarpit_config(tmp_path):
    p = write_config(tmp_path)
    d = yaml.safe_load(p.read_text())
    d["tarpit"] = {"min_open_ports": 3}
    p.write_text(yaml.safe_dump(d))
    return load_config(p)


def test_pipeline_flags_tarpits_by_window_and_silence_but_not_single_port_hosts(tmp_path):
    cfg = _tarpit_config(tmp_path)
    ft = tools(
        l4={80: [TARPIT, MIXED, ONE], 443: [TARPIT, MIXED], 8080: [TARPIT, MIXED]},
        tls={(TARPIT, 80): "reset", (TARPIT, 443): "reset", (TARPIT, 8080): "reset",
             (MIXED, 80): "reset", (MIXED, 443): "ok", (MIXED, 8080): "reset", (ONE, 80): "reset"},
        tls_sni={}, http={}, ptr={}, a={}, nxdomain=set())
    ft.windows[(MIXED, 80)] = 0                      # a zero window on one port is enough, whatever else the host does
    run_dir = go(cfg, ft)
    eps = {(r["target_ip"], r["port"]): r for r in rows_of(run_dir)}
    assert all(eps[(TARPIT, p)]["tarpit_suspect"] for p in (80, 443, 8080))
    assert all(eps[(TARPIT, p)]["protocol"] == "tcp_only" for p in (80, 443, 8080))
    assert all(eps[(TARPIT, p)]["tarpit_confidence"] == "medium" for p in (80, 443, 8080))
    assert all(eps[(MIXED, p)]["tarpit_confidence"] == "high" and "zero_window" in eps[(MIXED, p)]["tarpit_signals"] for p in (80, 443, 8080))
    assert eps[(MIXED, 80)]["synack_window"] == 0 and eps[(MIXED, 443)]["synack_window"] == 64240 and eps[(ONE, 80)]["synack_ttl"] == 64
    assert not eps[(ONE, 80)]["tarpit_suspect"]
    assert any(c[0].endswith("zmap") and "saddr,window,ttl" in c for c in ft.commands if "--dryrun" not in c)
    with (run_dir / "ip_results.csv").open(encoding="utf-8") as fh:
        by_ip = {r["ip"]: r for r in csv.DictReader(fh)}
    assert by_ip[TARPIT]["tarpit_suspect"] == "yes" and "3/3" in by_ip[TARPIT]["tarpit_reason"]
    assert by_ip[MIXED]["tarpit_suspect"] == "yes" and by_ip[MIXED]["tarpit_confidence"] == "high"
    assert by_ip[TARPIT]["tarpit_signals"] == "silent_open_many" and by_ip[ONE]["tarpit_suspect"] == "no"
    import json
    summary = json.loads((run_dir / "report" / "summary.json").read_text())
    assert summary["tarpit_suspect_ips"] == 2 and summary["tarpit_ips_by_confidence"] == {"high": 1, "medium": 1}


def test_tarpit_threshold_is_validated(tmp_path):
    p = write_config(tmp_path)
    d = yaml.safe_load(p.read_text())
    d["tarpit"] = {"min_open_ports": 1}
    p.write_text(yaml.safe_dump(d))
    try:
        load_config(p)
    except Exception as exc:
        assert "tarpit.min_open_ports" in str(exc)
    else:
        raise AssertionError("threshold below 3 must be rejected")


class PageFetcher:
    """Serves one HTML page; icons come back as a PNG. Records every request."""

    def __init__(self, html: str) -> None:
        self.html, self.calls = html, []

    def fetch(self, url, *, connect_ip, kind, context=""):
        self.calls.append((url, connect_ip, kind))
        body = make_png() if kind == "favicon" else self.html.encode()
        return FetchResult(
            kind=kind, requested_url=url, connect_ip=connect_ip, host_header=None, sni=None, outcome="ok",
            failure_category=None, http_status=200, content_type="image/png" if kind == "favicon" else "text/html",
            content_encoding=None, retry_after=None, body_sha256="a" * 64, body_bytes=len(body),
            redirect_chain=(), final_url=url, certificate=None), body


def test_probe_records_title_and_icons_declared_on_other_hosts():
    page = ('<html><head><title>  Shop\n login\x07 </title>'
            '<link rel="icon" href="https://cdn.elsewhere.example/i.png">'
            '<link rel="apple-touch-icon" href="/touch.png"></head></html>')
    rec = fav.probe_identity(PageFetcher(page), scheme="https", ip=IP_OK, port=443, hostname=None, max_icons=4)
    assert rec["document_title"] == "Shop login"                          # whitespace collapsed, control chars gone
    assert rec["document_body_sha256"] and rec["icon_declared_count"] == 2
    assert rec["icon_offhost_hosts"] == ["cdn.elsewhere.example"]
    assert rec["icon_declared_kinds"]                                      # per-kind counts recorded


def test_embedded_data_icon_is_decoded_locally_and_url_is_shortened():
    import base64
    uri = "data:image/png;base64," + base64.b64encode(make_png()).decode()
    f = PageFetcher(f'<html><head><link rel="icon" href="{uri}"></head></html>')
    rec = fav.probe_identity(f, scheme="http", ip=IP_OK, port=80, hostname=None, max_icons=4)
    assert rec["favicon_is_image"] and rec["icon_embedded_images"] == 1
    assert len(rec["favicon_url"]) < 120 and "embedded" in rec["favicon_url"]
    assert [c for c in f.calls if c[2] == "favicon"] == []                 # nothing was requested for it


def test_page_without_html_still_gets_a_record():
    rec = fav.probe_identity(FakeFetcher(), scheme="http", ip=IP_OK, port=80, hostname=None, max_icons=4)
    assert rec["document_title"] is None and rec["icon_offhost_hosts"] == []


def test_clean_text_bounds_and_strips():
    assert clean_text("a\tb\x00c") == "a b c"
    assert len(clean_text("x" * 500)) == 120
    assert clean_text("   ") is None and clean_text(None) is None
