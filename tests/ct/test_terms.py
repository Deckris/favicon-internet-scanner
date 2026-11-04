import pytest

from scanner.ct.models import Observation
from scanner.ct.terms import TermFilter


def obs(name):
    return Observation(name=name, source="import", seen_at="2026-01-01T00:00:00Z")


def test_substring_default_and_case():
    flt = TermFilter.from_terms(["Widget", "gadget"])
    assert flt.matches("my-GADGET.example.com") == ["gadget"]
    assert flt.matches("widgets.example.com") == ["widget"]
    assert flt.matches("example.org") == []


def test_no_builtin_terms():
    assert TermFilter.from_terms([]).matches("anything.example.com") == []


def test_label_boundary():
    flt = TermFilter.from_terms(["widget", "gadget"], label_boundary=True)
    assert flt.matches("widget.example.com") == ["widget"]
    assert flt.matches("my-widget-console.example.com") == ["widget"]
    assert flt.matches("gadget-widget.example.com") == ["widget", "gadget"]
    assert flt.matches("widgets.example.com") == []
    assert flt.matches("topwidget.example.com") == []


def test_label_boundary_hyphenated_term():
    flt = TermFilter.from_terms(["my-widget"], label_boundary=True)
    assert flt.matches("my-widget.example.com") == ["my-widget"]
    assert flt.matches("a-my-widget-b.example.com") == ["my-widget"]
    assert flt.matches("my.widget.example.com") == []
    assert flt.matches("my-widgets.example.com") == []
    assert flt.matches("xmy-widget.example.com") == []


def test_non_ascii_term_matches_punycode_name():
    for boundary in (False, True):
        flt = TermFilter.from_terms(["münchen", "alpha"], label_boundary=boundary)
        assert flt.matches("xn--mnchen-3ya.example.com") == ["münchen"]
        assert flt.matches("www.xn--mnchen-3ya.de") == ["münchen"]
        assert flt.matches("alpha.example.com") == ["alpha"]
    assert TermFilter.from_terms(["München"]).matches("münchen.example.com") == ["münchen"]


def test_label_boundary_dotted_term():
    flt = TermFilter.from_terms(["a.example"], label_boundary=True)
    assert flt.matches("a.example.com") == ["a.example"]
    assert flt.matches("xa.example.com") == []


def test_from_file(tmp_path):
    path = tmp_path / "terms.txt"
    path.write_text("# comment\n\nAlpha\n  beta  \nalpha\n", encoding="utf-8")
    flt = TermFilter.from_file(path)
    assert flt.terms == ("alpha", "beta")


@pytest.mark.parametrize("content", ["", "\n\n", "# only a comment\n  \n# another\n"])
def test_from_file_without_terms_raises(tmp_path, content):
    path = tmp_path / "terms.txt"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError):
        TermFilter.from_file(path)


def test_filter_observations():
    flt = TermFilter.from_terms(["beta"])
    rows = [obs("beta.example.com"), obs("gamma.example.com"), obs("x-beta.example.org")]
    assert [o.name for o in flt.filter(rows)] == ["beta.example.com", "x-beta.example.org"]
