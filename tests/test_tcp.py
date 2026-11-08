"""Tests for the TCP probe (fully mocked, no network)."""

import errno
import socket
from unittest.mock import MagicMock

import pytest

from censorscope.probes import tcp as tcp_probe

ADDRS = ["93.184.216.34"]


@pytest.fixture
def mock_tcp(monkeypatch):
    state = {80: None, 443: None}

    def fake_create_connection(address, timeout=None):
        behavior = state[address[1]]
        if isinstance(behavior, Exception):
            raise behavior
        return MagicMock()

    monkeypatch.setattr(tcp_probe.socket, "create_connection", fake_create_connection)
    return state


def test_both_ports_connect(mock_tcp):
    result = tcp_probe.run("example.com", timeout=1.0, addresses=ADDRS)
    assert result.status == "success"
    assert result.details["ports"]["80"]["outcome"] == "connected"
    assert result.details["ports"]["443"]["outcome"] == "connected"
    assert result.error is None


def test_one_port_refused(mock_tcp):
    mock_tcp[80] = ConnectionRefusedError()
    result = tcp_probe.run("example.com", addresses=ADDRS)
    assert result.status == "warning"
    assert result.details["ports"]["80"]["outcome"] == "refused"
    assert result.details["ports"]["443"]["outcome"] == "connected"


def test_both_ports_timeout(mock_tcp):
    mock_tcp[80] = TimeoutError()
    mock_tcp[443] = TimeoutError()
    result = tcp_probe.run("example.com", timeout=0.1, addresses=ADDRS)
    assert result.status == "error"
    assert result.details["ports"]["443"]["outcome"] == "timeout"
    assert "timed out" in result.error


def test_network_unreachable(mock_tcp):
    mock_tcp[80] = OSError(errno.ENETUNREACH, "Network is unreachable")
    mock_tcp[443] = OSError(errno.ENETUNREACH, "Network is unreachable")
    result = tcp_probe.run("example.com", addresses=ADDRS)
    assert result.status == "error"
    assert result.details["ports"]["80"]["outcome"] == "unreachable"


def test_custom_ports(mock_tcp):
    mock_tcp[8080] = None
    result = tcp_probe.run("example.com", ports=(8080,), addresses=ADDRS)
    assert result.status == "success"
    assert "8080" in result.details["ports"]


def test_duration_recorded(mock_tcp):
    result = tcp_probe.run("example.com", addresses=ADDRS)
    assert result.duration_ms >= 0
    assert result.details["ports"]["80"]["duration_ms"] >= 0


def test_empty_addresses_skips_connections(monkeypatch):
    def fail_connect(*args, **kwargs):
        raise AssertionError("must not attempt connection without addresses")

    monkeypatch.setattr(tcp_probe.socket, "create_connection", fail_connect)
    result = tcp_probe.run("example.com", addresses=[])
    assert result.status == "error"
    assert "No DNS addresses" in result.summary


def test_addresses_none_resolves_via_system(monkeypatch):
    resolved = []

    def fake_getaddrinfo(host, port, family=0, type=0):
        resolved.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    connected = []

    def fake_create_connection(address, timeout=None):
        connected.append(address)
        return MagicMock()

    monkeypatch.setattr(tcp_probe.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(tcp_probe.socket, "create_connection", fake_create_connection)
    result = tcp_probe.run("example.com")
    assert result.status == "success"
    assert resolved == ["example.com"]
    assert connected == [("93.184.216.34", 80), ("93.184.216.34", 443)]


def test_system_resolution_failure(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(tcp_probe.socket, "getaddrinfo", fake_getaddrinfo)
    result = tcp_probe.run("nonexistent.example")
    assert result.status == "error"
    assert "No DNS addresses" in result.summary


def test_connects_to_provided_address(monkeypatch):
    connected = []

    def fake_create_connection(address, timeout=None):
        connected.append(address)
        return MagicMock()

    monkeypatch.setattr(tcp_probe.socket, "create_connection", fake_create_connection)
    tcp_probe.run("example.com", addresses=ADDRS)
    assert connected == [(ADDRS[0], 80), (ADDRS[0], 443)]
