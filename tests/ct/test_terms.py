from scanner.ct.models import Observation
from scanner.ct.terms import TermFilter


def obs(name):
    return Observation(name=name, source="import", seen_at="2026-01-01T00:00:00Z")


def test_substring_default_and_case():
    flt = TermFilter.from_terms(["Pay", "login"])
    assert flt.matches("secure-LOGIN.example.com") == ["login"]
    assert flt.matches("payments.example.com") == ["pay"]
    assert flt.matches("example.org") == []


def test_no_builtin_terms():
    assert TermFilter.from_terms([]).matches("anything.example.com") == []


def test_label_boundary():
    flt = TermFilter.from_terms(["pay", "shop"], label_boundary=True)
    assert flt.matches("pay.example.com") == ["pay"]
    assert flt.matches("my-pay-portal.example.com") == ["pay"]
    assert flt.matches("shop-pay.example.com") == ["pay", "shop"]
    assert flt.matches("payments.example.com") == []
    assert flt.matches("toppay.example.com") == []


def test_label_boundary_dotted_term():
    flt = TermFilter.from_terms(["a.example"], label_boundary=True)
    assert flt.matches("a.example.com") == ["a.example"]
    assert flt.matches("xa.example.com") == []


def test_from_file(tmp_path):
    path = tmp_path / "terms.txt"
    path.write_text("# comment\n\nAlpha\n  beta  \nalpha\n", encoding="utf-8")
    flt = TermFilter.from_file(path)
    assert flt.terms == ("alpha", "beta")


def test_filter_observations():
    flt = TermFilter.from_terms(["beta"])
    rows = [obs("beta.example.com"), obs("gamma.example.com"), obs("x-beta.example.org")]
    assert [o.name for o in flt.filter(rows)] == ["beta.example.com", "x-beta.example.org"]
