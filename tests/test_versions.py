"""Unit tests for version parsing and detection helpers in bind9_setup."""
import bind9_setup as b


def test_parse_bind_versions_sorted_newest_first():
    html = '<a href="9.18.1/">9.18.1/</a> <a href="9.20.7/">9.20.7/</a> <a href="9.18.33/">9.18.33/</a>'
    assert b.parse_bind_versions(html) == ["9.20.7", "9.18.33", "9.18.1"]


def test_parse_bind_versions_excludes_dev_branches():
    html = '9.21.0/ 9.20.7/ 9.99.1/'
    versions = b.parse_bind_versions(html)
    assert "9.21.0" not in versions
    assert "9.99.1" not in versions
    assert "9.20.7" in versions


def test_parse_bind_versions_drops_prereleases():
    # rc/beta suffixes do not match the x.y.z(?=/) pattern.
    html = '9.20.7/ 9.20.8rc1/ 9.20.9-beta/'
    assert b.parse_bind_versions(html) == ["9.20.7"]


def test_parse_bind_versions_empty():
    assert b.parse_bind_versions("nothing here") == []


def test_parse_bind_versions_dedupes():
    html = '9.20.7/ 9.20.7/ 9.20.7/'
    assert b.parse_bind_versions(html) == ["9.20.7"]


def test_parse_named_version():
    assert b.parse_named_version("BIND 9.18.33-1~deb12u1 (Extended Support)") == (9, 18)
    assert b.parse_named_version("BIND 9.20.7") == (9, 20)
    assert b.parse_named_version("garbage") is None


def test_doh_supported():
    assert b.doh_supported(9, 18) is True
    assert b.doh_supported(9, 20) is True
    assert b.doh_supported(9, 16) is False
    assert b.doh_supported(10, 0) is True
    assert b.doh_supported(8, 99) is False
