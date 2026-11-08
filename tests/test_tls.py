"""Tests for the TLS probe (fully mocked, no network)."""

import ssl
from unittest.mock import MagicMock

import pytest

from censorscope.probes import tls as tls_probe

ADDRS = ["93.184.216.34"]


@pytest.fixture
def mock_tls(monkeypatch):
    state = {"sni": None, "no_sni": None, "connected_to": []}

    def fake_create_connection(address, timeout=None):
        state["connected_to"].append(address)
        return MagicMock()

    def fake_wrap(self, sock, server_hostname=None, **kwargs):
        if server_hostname is None:
            assert self.check_hostname is False
            assert self.verify_mode == ssl.CERT_REQUIRED
            behavior = state["no_sni"]
        else:
            assert self.check_hostname is True
            assert self.verify_mode == ssl.CERT_REQUIRED
            behavior = state["sni"]
        if isinstance(behavior, Exception):
            raise behavior
        handshake = MagicMock()
        handshake.__enter__.return_value = handshake
        handshake.version.return_value = "TLSv1.3"
        handshake.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        return handshake

    monkeypatch.setattr(tls_probe.socket, "create_connection", fake_create_connection)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", fake_wrap)
    return state


def test_handshake_success(mock_tls):
    result = tls_probe.run("example.com", timeout=1.0, addresses=ADDRS)
    assert result.status == "success"
    assert result.details["sni"]["outcome"] == "success"
    assert result.details["sni"]["protocol"] == "TLSv1.3"
    assert result.details["sni_specific_failure"] is False
    assert result.error is None


def test_sni_fails_but_no_sni_succeeds(mock_tls):
    mock_tls["sni"] = ConnectionResetError()
    result = tls_probe.run("example.com", addresses=ADDRS)
    assert result.status == "warning"
    assert result.details["sni"]["outcome"] == "reset"
    assert result.details["no_sni"]["outcome"] == "success"
    assert result.details["sni_specific_failure"] is True


def test_certificate_error(mock_tls):
    mock_tls["sni"] = ssl.SSLCertVerificationError("certificate verify failed")
    mock_tls["no_sni"] = ssl.SSLCertVerificationError("certificate verify failed")
    result = tls_probe.run("example.com", addresses=ADDRS)
    assert result.status == "error"
    assert result.details["sni"]["outcome"] == "cert_error"
    assert result.details["sni_specific_failure"] is False
    assert "certificate verify failed" in result.error


def test_both_handshakes_fail(mock_tls):
    mock_tls["sni"] = ssl.SSLError("handshake failure")
    mock_tls["no_sni"] = ssl.SSLError("handshake failure")
    result = tls_probe.run("example.com", addresses=ADDRS)
    assert result.status == "error"
    assert result.details["sni"]["outcome"] == "handshake_error"


def test_timeout(mock_tls):
    mock_tls["sni"] = TimeoutError()
    mock_tls["no_sni"] = TimeoutError()
    result = tls_probe.run("example.com", timeout=0.1, addresses=ADDRS)
    assert result.status == "error"
    assert result.details["sni"]["outcome"] == "timeout"


def test_connection_error(mock_tls):
    mock_tls["sni"] = OSError("connection refused")
    mock_tls["no_sni"] = OSError("connection refused")
    result = tls_probe.run("example.com", addresses=ADDRS)
    assert result.status == "error"
    assert result.details["sni"]["outcome"] == "connection_error"


def test_no_sni_cert_error_does_not_mask_success(mock_tls):
    mock_tls["no_sni"] = ssl.SSLCertVerificationError("hostname mismatch")
    result = tls_probe.run("example.com", addresses=ADDRS)
    assert result.status == "success"
    assert result.details["no_sni"]["outcome"] == "cert_error"
    assert result.details["sni_specific_failure"] is False


def test_empty_addresses_skips_handshake(monkeypatch):
    def fail_connect(*args, **kwargs):
        raise AssertionError("must not attempt connection without addresses")

    monkeypatch.setattr(tls_probe.socket, "create_connection", fail_connect)
    result = tls_probe.run("example.com", addresses=[])
    assert result.status == "error"
    assert "No DNS addresses" in result.summary


def test_connects_to_ip_but_keeps_domain_sni(mock_tls, monkeypatch):
    used_sni = []
    original_wrap = ssl.SSLContext.wrap_socket

    def tracking_wrap(self, sock, server_hostname=None, **kwargs):
        used_sni.append(server_hostname)
        return original_wrap(self, sock, server_hostname=server_hostname, **kwargs)

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", tracking_wrap)
    result = tls_probe.run("example.com", addresses=ADDRS)
    assert result.status == "success"
    assert mock_tls["connected_to"] == [(ADDRS[0], 443), (ADDRS[0], 443)]
    assert used_sni == ["example.com", None]
