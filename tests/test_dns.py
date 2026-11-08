"""Tests for the DNS probe (fully mocked, no network)."""

import socket
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from censorscope.probes import dns as dns_probe


def _system_answer(*addresses):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in addresses]


@pytest.fixture
def mock_dns(monkeypatch):
    """Patch system resolver and public resolver with configurable answers."""
    state = {"system": None, "8.8.8.8": None, "1.1.1.1": None}

    def fake_getaddrinfo(host, port, family=0, type=0):
        behavior = state["system"]
        if isinstance(behavior, Exception):
            raise behavior
        return _system_answer(*behavior)

    class FakeResolver:
        def __init__(self, configure=True):
            self.nameservers = []
            self.timeout = None
            self.lifetime = None

        def resolve(self, qname, rdtype):
            behavior = state[self.nameservers[0]]
            if isinstance(behavior, Exception):
                raise behavior
            return [SimpleNamespace(address=a) for a in behavior]

    monkeypatch.setattr(dns_probe.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(dns_probe.dns.resolver, "Resolver", FakeResolver)
    return state


def test_consistent_public_answers(mock_dns):
    mock_dns["system"] = ["93.184.216.34"]
    mock_dns["8.8.8.8"] = ["93.184.216.34"]
    mock_dns["1.1.1.1"] = ["93.184.216.34"]
    result = dns_probe.run("example.com", timeout=1.0)
    assert result.status == "success"
    assert result.details["answers_differ"] is False
    assert result.details["non_public_addresses"] == {}
    assert result.error is None


def test_loopback_answer_is_flagged(mock_dns):
    mock_dns["system"] = ["127.0.0.1"]
    mock_dns["8.8.8.8"] = ["93.184.216.34"]
    mock_dns["1.1.1.1"] = ["93.184.216.34"]
    result = dns_probe.run("example.com")
    assert result.status == "warning"
    assert "127.0.0.1" in result.details["non_public_addresses"]
    assert "loopback" in result.details["non_public_addresses"]["127.0.0.1"]
    assert result.details["answers_differ"] is True


def test_nxdomain_everywhere(mock_dns):
    mock_dns["system"] = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    mock_dns["8.8.8.8"] = dns.resolver.NXDOMAIN()
    mock_dns["1.1.1.1"] = dns.resolver.NXDOMAIN()
    result = dns_probe.run("nonexistent.example")
    assert result.status == "error"
    assert result.details["nxdomain"] is True
    assert result.error


def test_differing_answers_warn(mock_dns):
    mock_dns["system"] = ["1.2.3.4"]
    mock_dns["8.8.8.8"] = ["5.6.7.8"]
    mock_dns["1.1.1.1"] = ["5.6.7.8"]
    result = dns_probe.run("example.com")
    assert result.status == "warning"
    assert result.details["answers_differ"] is True


def test_resolver_timeout_is_partial_failure(mock_dns):
    mock_dns["system"] = ["93.184.216.34"]
    mock_dns["8.8.8.8"] = dns.exception.Timeout()
    mock_dns["1.1.1.1"] = ["93.184.216.34"]
    result = dns_probe.run("example.com", timeout=0.1)
    assert result.status == "warning"
    assert "timed out" in result.details["resolvers"]["google"]["error"]
    assert result.details["resolvers"]["google"]["duration_ms"] >= 0


def test_all_resolvers_fail(mock_dns):
    mock_dns["system"] = socket.gaierror(socket.EAI_AGAIN, "Temporary failure")
    mock_dns["8.8.8.8"] = dns.exception.Timeout()
    mock_dns["1.1.1.1"] = dns.resolver.NoNameservers()
    result = dns_probe.run("example.com")
    assert result.status == "error"
    assert result.error


@pytest.mark.parametrize(
    ("address", "expected_flag"),
    [
        ("10.0.0.1", "private"),
        ("192.168.1.1", "private"),
        ("172.16.0.1", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link_local"),
        ("224.0.0.1", "multicast"),
        ("240.0.0.1", "reserved"),
        ("0.0.0.0", "unspecified"),
        ("::1", "loopback"),
        ("fe80::1", "link_local"),
        ("fc00::1", "private"),
    ],
)
def test_non_public_reasons(address, expected_flag):
    assert expected_flag in dns_probe.non_public_reasons(address)


def test_public_address_has_no_reasons():
    assert dns_probe.non_public_reasons("93.184.216.34") == []
    assert dns_probe.non_public_reasons("2606:2800:220:1::248") == []


def test_invalid_address():
    assert dns_probe.non_public_reasons("not-an-ip") == ["invalid"]
