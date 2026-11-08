"""Tests for the diagnostic orchestrator (probes mocked)."""

import json

import pytest

from censorscope import diagnostics
from censorscope.models import ProbeResult


@pytest.fixture
def mock_probes(monkeypatch):
    calls = []

    def make_probe(name):
        def fake_run(target, timeout, addresses=None):
            calls.append((name, target, timeout, addresses))
            return ProbeResult(name=name, status="success", summary=f"{name} ok")

        return fake_run

    for module in (diagnostics.dns, diagnostics.tcp, diagnostics.tls, diagnostics.http):
        monkeypatch.setattr(module, "run", make_probe(module.__name__.rsplit(".", 1)[-1]))
    return calls


def test_runs_all_probes_in_order(mock_probes):
    report = diagnostics.run_diagnostic("Example.com", timeout=2.5)
    assert [c[0] for c in mock_probes] == ["dns", "tcp", "tls", "http"]
    assert all(c[1] == "example.com" and c[2] == 2.5 for c in mock_probes)
    assert report.target == "example.com"
    assert report.verdict == "no_problem_detected"
    assert len(report.probe_results) == 4
    assert report.duration_ms >= 0
    assert report.timestamp


def test_progress_callback(mock_probes):
    seen = []
    diagnostics.run_diagnostic("example.com", progress=seen.append)
    assert seen == ["dns", "tcp", "tls", "http"]


def test_probe_crash_does_not_abort(monkeypatch, mock_probes):
    def crash(target, timeout, addresses=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(diagnostics.tcp, "run", crash)
    report = diagnostics.run_diagnostic("example.com")
    assert len(report.probe_results) == 4
    tcp_result = next(r for r in report.probe_results if r.name == "tcp")
    assert tcp_result.status == "error"
    assert "RuntimeError: boom" in tcp_result.error
    assert report.verdict == "inconclusive"


def test_dns_addresses_are_reused(monkeypatch, mock_probes):
    def dns_run(target, timeout):
        return ProbeResult(
            name="dns",
            status="success",
            summary="ok",
            details={
                "resolvers": {
                    "system": {"addresses": ["93.184.216.34"], "error": None},
                    "google": {"addresses": ["93.184.216.34"], "error": None},
                    "cloudflare": {"addresses": ["93.184.216.34"], "error": None},
                }
            },
        )

    monkeypatch.setattr(diagnostics.dns, "run", dns_run)
    diagnostics.run_diagnostic("example.com")
    later = [c for c in mock_probes if c[0] != "dns"]
    assert all(c[3] == ["93.184.216.34"] for c in later)


def test_public_answers_used_when_system_fails(monkeypatch, mock_probes):
    def dns_run(target, timeout):
        return ProbeResult(
            name="dns",
            status="warning",
            summary="partial",
            details={
                "resolvers": {
                    "system": {"addresses": [], "error": "system resolver failed"},
                    "google": {"addresses": ["93.184.216.34"], "error": None},
                    "cloudflare": {"addresses": [], "error": "timeout"},
                }
            },
        )

    monkeypatch.setattr(diagnostics.dns, "run", dns_run)
    diagnostics.run_diagnostic("example.com")
    later = [c for c in mock_probes if c[0] != "dns"]
    assert all(c[3] == ["93.184.216.34"] for c in later)


def test_invalid_target_raises():
    with pytest.raises(ValueError):
        diagnostics.run_diagnostic("https://example.com")


def test_invalid_timeout_raises():
    with pytest.raises(ValueError):
        diagnostics.run_diagnostic("example.com", timeout=0)


def test_report_is_json_serializable(mock_probes):
    report = diagnostics.run_diagnostic("example.com")
    parsed = json.loads(report.to_json())
    assert parsed["target"] == "example.com"
    assert len(parsed["probe_results"]) == 4
    assert parsed["verdict"] == "no_problem_detected"
