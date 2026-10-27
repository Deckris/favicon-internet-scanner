from scanner.internet.pipeline import _icon_scope


def test_icon_scope_labels() -> None:
    assert _icon_scope(True, True) == "domain_verified"
    assert _icon_scope(False, True) == "served_at_ip"
    assert _icon_scope(True, False) == "none"
    assert _icon_scope(False, False) == "none"
