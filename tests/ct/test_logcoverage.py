import json
from pathlib import Path

from scanner.ct import logcoverage as lc

FIXTURE = Path(__file__).parent / "fixtures" / "log_list.json"


def test_load_from_path_and_dict():
    data = lc.load_log_list(FIXTURE)
    assert lc.load_log_list(data) is data
    assert lc.load_log_list(str(FIXTURE)) == json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_compare_covered_missing_unknown():
    log_list = lc.load_log_list(FIXTURE)
    watched = ["https://ct.alpha.example/2026", "ct.beta.example/log/", "https://ct.unlisted.invalid/", "https://ct.old.example/"]
    result = lc.compare(watched, log_list)
    assert result["covered"] == ["https://ct.alpha.example/2026/", "https://ct.beta.example/log/"]
    assert result["missing"] == [{"url": "https://ct.delta.example/", "type": "rfc6962"},
                                 {"url": "https://mon.tile.example/", "type": "tiled"}]
    assert result["unknown"] == ["ct.unlisted.invalid"]


def test_pending_and_retired_not_required():
    result = lc.compare([], lc.load_log_list(FIXTURE))
    urls = {m["url"] for m in result["missing"]}
    assert "https://ct.gamma.example/" not in urls and "https://ct.old.example/" not in urls
    assert len(urls) == 4


def test_url_normalisation():
    assert lc.normalize_url("HTTPS://CT.Example/Path/") == "ct.example/Path"
    assert lc.normalize_url("http://ct.example") == lc.normalize_url("https://ct.example/")


def test_tiled_watched_by_monitoring_url():
    result = lc.compare(["https://mon.tile.example"], lc.load_log_list(FIXTURE))
    assert result["covered"] == ["https://mon.tile.example/"]


def test_empty_list():
    assert lc.compare(["https://x.test/"], {}) == {"covered": [], "missing": [], "unknown": ["x.test"]}
