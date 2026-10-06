"""Saving favicon images: the content-addressed store, the probe hook, and the favicon-only re-fetch."""
import json
from pathlib import Path

import pytest

from scanner.internet import favicon as fav
from scanner.internet import icon_store, pipeline, refetch
from scanner.internet.config import ConfigError, load_config
from scanner.models import FetchResult
from tests.helpers import FakeFetcher, FakeTools, make_png, write_config
from tests.test_pipeline import IP_OK, tools

PNG = make_png()


def test_image_extension_by_content():
    assert icon_store.image_extension(PNG) == "png"
    assert icon_store.image_extension(b"\x00\x00\x01\x00rest") == "ico"
    assert icon_store.image_extension(b"GIF89a....") == "gif"
    assert icon_store.image_extension(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "webp"
    assert icon_store.image_extension(b'<?xml version="1.0"?><svg xmlns="x"/>') == "svg.txt"   # never a runnable .svg
    assert icon_store.image_extension(b"junk") == "bin"


def test_store_writes_each_image_once_and_indexes_observations(tmp_path):
    store = icon_store.IconStore(tmp_path / "favicons")
    rel = store.save("a" * 64, PNG)
    assert rel == f"favicons/{'a' * 64}.png" and store.save("a" * 64, PNG) == rel
    assert (tmp_path / rel).read_bytes() == PNG and len(store) == 1
    recs = [
        {"favicon_sha256": "a" * 64, "favicon_is_image": True, "ip": "1.1.1.1", "port": 443, "scheme": "https", "hostname": None,
         "url": "https://1.1.1.1:443/", "document_title": "T", "favicon_url": "https://1.1.1.1:443/f.png", "favicon_bytes": len(PNG)},
        {"favicon_sha256": "a" * 64, "favicon_is_image": True, "ip": "1.1.1.2", "port": 80, "scheme": "http", "hostname": "x.test",
         "url": "http://x.test:80/", "document_title": None, "favicon_url": None, "favicon_bytes": len(PNG)},
        {"favicon_sha256": "b" * 64, "favicon_is_image": False, "ip": "1.1.1.3", "port": 80},
    ]
    assert store.write_index(recs) == 1
    entry = json.loads((tmp_path / "favicons" / "index.jsonl").read_text().splitlines()[0])
    assert entry["file"] == rel and len(entry["observations"]) == 2


def test_probe_stores_decoded_icons_but_not_html(tmp_path):
    store = icon_store.IconStore(tmp_path / "favicons")
    rec = fav.probe_identity(FakeFetcher(), scheme="http", ip=IP_OK, port=80, hostname=None, max_icons=4, icon_store=store)
    assert rec["favicon_is_image"] and rec["favicon_file"] == store.path_for(rec["favicon_sha256"])
    assert (tmp_path / rec["favicon_file"]).read_bytes() == PNG
    assert len(store) == 1

    class HtmlOnly(FakeFetcher):
        def fetch(self, url, *, connect_ip, kind, context=""):
            res, _ = super().fetch(url, connect_ip=connect_ip, kind=kind, context=context)
            body = b"<html>login</html>"
            return res, body
    other = icon_store.IconStore(tmp_path / "none")
    rec = fav.probe_identity(HtmlOnly(), scheme="http", ip=IP_OK, port=80, hostname=None, max_icons=4, icon_store=other)
    assert not rec["favicon_is_image"] and rec["favicon_file"] is None and len(other) == 0
    assert not (tmp_path / "none").exists() or not list((tmp_path / "none").glob("*.bin"))


def test_probe_without_a_store_is_unchanged():
    rec = fav.probe_identity(FakeFetcher(), scheme="http", ip=IP_OK, port=80, hostname=None, max_icons=4)
    assert rec["favicon_is_image"] and rec["favicon_file"] is None


@pytest.fixture
def source(tmp_path):
    cfg = load_config(write_config(tmp_path))
    run_dir = pipeline.run(cfg, run_id="src", executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)
    return cfg, run_dir


def test_pipeline_stores_images_and_rows_point_at_them(source):
    cfg, run_dir = source
    rows = [json.loads(l) for l in (run_dir / "normalized" / "endpoints.jsonl").read_text().splitlines()]
    files = [r["direct_favicon_file"] for r in rows if r["direct_favicon_is_image"]]
    assert files and all((run_dir / f).is_file() for f in files)
    assert (run_dir / "favicons" / "index.jsonl").is_file()
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["stage_counts"]["favicon_images_stored"] >= 1


def test_store_can_be_switched_off(tmp_path):
    cfg = load_config(write_config(tmp_path, favicon={"enabled": True, "max_hostnames_per_endpoint": 3, "workers": 2,
                                                       "max_icons_per_page": 4, "store_images": False}))
    run_dir = pipeline.run(cfg, run_id="off", executor=tools(), fetcher=FakeFetcher(), skip_preflight=True, offline_preflight=True)
    assert not (run_dir / "favicons").exists()


def test_refetch_plan_rebuilds_the_jobs_from_a_finished_run(source):
    cfg, run_dir = source
    everything = refetch.plan(cfg, run_dir, all_jobs=True)
    images_only = refetch.plan(cfg, run_dir, all_jobs=False)
    assert everything["jobs_to_run"] >= images_only["jobs_to_run"] >= 1
    assert images_only["confirm_token"] != everything["confirm_token"]


def test_refetch_saves_images_and_matches_the_first_run(source):
    cfg, run_dir = source
    out = refetch.run_refetch(cfg, run_dir, fetcher=FakeFetcher(), executor=tools(), offline_preflight=True, skip_preflight=True)
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["complete"] and manifest["kind"] == "favicon_refetch" and manifest["source_run"] == "src"
    summary = manifest["summary"]
    assert summary["images_stored"] >= 1 and summary["compared_with_source"]["same_hash"] >= 1
    assert summary["compared_with_source"]["different_hash"] == 0 and summary["compared_with_source"]["lost_image"] == 0
    index = [json.loads(l) for l in (out / "favicons" / "index.jsonl").read_text().splitlines()]
    assert index and all((out / e["file"]).is_file() for e in index)


def test_refetch_refuses_a_run_from_a_different_config(source, tmp_path_factory):
    _, run_dir = source
    other = load_config(write_config(tmp_path_factory.mktemp("other"), run_label="another"))
    with pytest.raises(ConfigError, match="different config"):
        refetch.plan(other, run_dir, all_jobs=False)
