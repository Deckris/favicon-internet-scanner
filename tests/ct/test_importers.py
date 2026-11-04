from pathlib import Path

import pytest

from scanner.ct.importers import load_crtsh_export

FIXTURES = Path(__file__).parent / "fixtures"


def test_json_export():
    table = load_crtsh_export(FIXTURES / "crtsh_export.json")
    rows = list(table)
    assert all(o.source == "import" for o in rows)
    assert set(table.names()) == {"www.alpha.example", "alpha.example", "beta.test", "xn--bcher-kva.example"}
    alpha = [o for o in rows if o.cert_id == "1000001"]
    assert sorted(o.name for o in alpha) == ["alpha.example", "www.alpha.example"]  # the wildcard reduces to alpha.example, which the table keeps once
    assert {o.seen_at for o in alpha} == {"2025-03-01T10:15:30Z"}
    assert alpha[0].issuer == "C=XX, O=Example Test CA, CN=Example Test CA R1"


def test_json_falls_back_to_not_before_and_skips_invalid():
    rows = list(load_crtsh_export(FIXTURES / "crtsh_export.json"))
    beta = [o for o in rows if o.name == "beta.test"]
    assert [o.seen_at for o in beta] == ["2025-03-02T00:00:00Z"]
    assert not [o for o in rows if o.cert_id == "1000004"]
    assert not [o for o in rows if o.name in ("198.51.100.7", "not a name")]


def test_idna_and_trailing_dot_collapse():
    rows = [o for o in load_crtsh_export(FIXTURES / "crtsh_export.json") if o.cert_id == "1000003"]
    assert [o.name for o in rows] == ["xn--bcher-kva.example"]  # both spellings normalise to one name, kept once


def test_csv_export():
    table = load_crtsh_export(FIXTURES / "crtsh_export.csv")
    rows = list(table)
    assert set(table.names()) == {"www.gamma.example", "gamma.example", "delta.invalid"}
    gamma = [o for o in rows if o.cert_id == "2000001"]
    assert {o.seen_at for o in gamma} == {"2025-04-01T08:00:00Z"}
    delta = [o for o in rows if o.cert_id == "2000002"]
    assert [o.seen_at for o in delta] == ["2025-04-02T00:00:00Z"]
    assert not [o for o in rows if o.cert_id == "2000003"]


def test_empty_and_invalid_files(tmp_path):
    empty = tmp_path / "e.json"
    empty.write_text("  \n", encoding="utf-8")
    assert len(load_crtsh_export(empty)) == 0
    bad = tmp_path / "b.json"
    bad.write_text("[{", encoding="utf-8")
    with pytest.raises(ValueError):
        load_crtsh_export(bad)
