import pytest

from scanner.ct.names import (
    iter_names, normalize_name, public_suffix, registrable_domain, wildcard_base, write_names,
)


@pytest.mark.parametrize("raw,expected", [
    ("  WWW.Example.COM. ", "www.example.com"),
    ("bücher.example.org", "xn--bcher-kva.example.org"),
    ("xn--bcher-kva.example.org", "xn--bcher-kva.example.org"),
])
def test_normalize_valid(raw, expected):
    assert normalize_name(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", ".", "192.0.2.1", "2001:db8::1", "a..example.com", "-a.example.com",
    "a b.example.com", "*.*.example.com", "*.", "*.example.com", "a.*.example.com", "*", "localhost", "x" * 64 + ".example.com",
    ("a" * 60 + ".") * 5 + "com",
])
def test_normalize_invalid(raw):
    assert normalize_name(raw) is None


def test_write_names(tmp_path):
    path = tmp_path / "names.txt"
    count = write_names(path, ["B.example.com", "a.example.com", "*.c.example.com", "bad..name", "b.example.com."])
    assert count == 2
    assert path.read_bytes() == b"a.example.com\nb.example.com\n"


def test_iter_names_text(tmp_path):
    path = tmp_path / "list.txt"
    path.write_text("# header\n\nA.example.com\nnot valid\n*.a.example.com\nb.example.org\n", encoding="utf-8")
    assert list(iter_names(path)) == ["a.example.com", "b.example.org"]


def test_iter_names_without_dedupe(tmp_path):
    path = tmp_path / "list.txt"
    path.write_text("a.example.com\nA.example.com\nb.example.org\n", encoding="utf-8")
    assert list(iter_names(path, dedupe=False)) == ["a.example.com", "a.example.com", "b.example.org"]
    assert list(iter_names(path)) == ["a.example.com", "b.example.org"]


def test_iter_names_jsonl(tmp_path):
    path = tmp_path / "rows.jsonl"
    path.write_text(
        '{"name": "A.example.com", "source": "import"}\n'
        "\n"
        "not json\n"
        '{"other": 1}\n'
        '{"name": "a.example.com"}\n'
        '{"name": "198.51.100.7"}\n'
        '{"name": "b.example.test"}\n',
        encoding="utf-8",
    )
    assert list(iter_names(path)) == ["a.example.com", "b.example.test"]


def test_jsonl_extension_is_what_selects_the_format(tmp_path):
    path = tmp_path / "rows.dat"
    path.write_text('{"name": "a.example.com"}\n', encoding="utf-8")
    assert list(iter_names(path)) == []


@pytest.mark.parametrize("name,expected", [
    ("www.example.com", "example.com"),
    ("example.com", "example.com"),
    ("a.b.example.co.uk", "example.co.uk"),
    ("example.co.uk", "example.co.uk"),
    ("co.uk", None),
    ("com", None),
    ("*.widget.example.com.au", None),
    ("www.xn--bcher-kva.example.org", "example.org"),
    ("192.0.2.1", None),
])
def test_registrable_domain(name, expected):
    assert registrable_domain(name) == expected


@pytest.mark.parametrize("name,expected", [
    ("a.b.co.at", "b.co.at"),
    ("x.github.io", "x.github.io"),
    ("a.b.com.gr", "b.com.gr"),
    ("a.b.example.com", "example.com"),
    ("ec2-1.compute-1.amazonaws.com", None),                 # *.compute-1.amazonaws.com is itself a suffix
    ("x.ec2-1.compute-1.amazonaws.com", "x.ec2-1.compute-1.amazonaws.com"),
    ("a.foo.ck", "a.foo.ck"),                                # *.ck wildcard rule
    ("foo.ck", None),
    ("www.ck", "www.ck"),                                    # !www.ck exception rule
    ("a.www.ck", "www.ck"),
    ("github.io", None),
    ("example.co.uk", "example.co.uk"),
    ("a.example.unlistedtld", "example.unlistedtld"),        # default rule
    ("a.xn--bcher-kva.xn--p1ai", "xn--bcher-kva.xn--p1ai"),
    ("a.b.xn--55qx5d.cn", "b.xn--55qx5d.cn"),                # rule listed in Unicode in the file
    ("xn--55qx5d.cn", None),
])
def test_registrable_domain_public_suffix_list(name, expected):
    assert registrable_domain(name) == expected


@pytest.mark.parametrize("name,expected", [
    ("www.example.com", "com"),
    ("a.b.co.at", "co.at"),
    ("x.github.io", "github.io"),
    ("co.uk", "co.uk"),
    ("www.ck", "ck"),
    ("a.foo.ck", "foo.ck"),
    ("a.example.unlistedtld", "unlistedtld"),
    ("a.b.xn--55qx5d.cn", "xn--55qx5d.cn"),
    ("192.0.2.1", None),
    ("*.example.com", None),
])
def test_public_suffix(name, expected):
    assert public_suffix(name) == expected


@pytest.mark.parametrize("raw,expected", [
    ("*.a.example.com", "a.example.com"),
    (" *.EXAMPLE.com. ", "example.com"),
    ("*.bücher.example.org", "xn--bcher-kva.example.org"),
    ("a.example.com", None),
    ("*.*.example.com", None),
    ("*.", None),
    ("*.192.0.2.1", None),
])
def test_wildcard_base(raw, expected):
    assert wildcard_base(raw) == expected
