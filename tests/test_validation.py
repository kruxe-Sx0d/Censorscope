"""Tests for domain input validation."""

import pytest

from censorscope.validation import validate_domain


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("  Example.COM  ", "example.com"),
        ("example.com.", "example.com"),
        ("sub.domain.example.co.uk", "sub.domain.example.co.uk"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("123.example", "123.example"),
    ],
)
def test_valid_domains(raw, expected):
    assert validate_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "https://example.com",
        "http://example.com/path",
        "example.com/path",
        "example.com:443",
        "user@example.com",
        "example.com?x=1",
        "exa mple.com",
        "127.0.0.1",
        "8.8.8.8",
        "::1",
        "2001:db8::1",
        "localhost",
        "-bad.example",
        "bad-.example",
        "bad_label.example",
        "example..com",
        "a" * 64 + ".example",
        ("a" * 63 + ".") * 4 + "com",
    ],
)
def test_invalid_domains(raw):
    with pytest.raises(ValueError):
        validate_domain(raw)


def test_non_string_input():
    with pytest.raises(ValueError):
        validate_domain(None)
