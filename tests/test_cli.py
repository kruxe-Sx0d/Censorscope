"""Tests for the CLI (diagnostics mocked, no network)."""

import json

import pytest
from typer.testing import CliRunner

from censorscope import __version__, cli
from censorscope.models import DiagnosticReport, ProbeResult
from censorscope.validation import validate_domain

runner = CliRunner()


def make_report(verdict="no_problem_detected", confidence="high"):
    return DiagnosticReport(
        target="example.com",
        timestamp="2026-11-08T00:00:00+00:00",
        probe_results=[ProbeResult(name="dns", status="success", summary="consistent")],
        verdict=verdict,
        confidence=confidence,
        reasons=["synthetic reason"],
        duration_ms=123.4,
    )


@pytest.fixture
def mock_diagnostic(monkeypatch):
    state = {"report": make_report(), "calls": []}

    def fake_run(target, timeout, progress=None):
        validate_domain(target)
        state["calls"].append((target, timeout))
        if progress:
            progress("dns")
        return state["report"]

    monkeypatch.setattr(cli, "run_diagnostic", fake_run)
    return state


def test_help():
    result = runner.invoke(cli.app, ["--help"])
    assert result.exit_code == 0
    assert "check" in result.output
    assert "Exit codes" in result.output


def test_version():
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_check_normal_output(mock_diagnostic):
    result = runner.invoke(cli.app, ["check", "example.com"])
    assert result.exit_code == 0
    assert "example.com" in result.output
    assert "Censorscope" in result.output
    assert "Verdict" in result.output
    assert "synthetic reason" in result.output


def test_check_json_output(mock_diagnostic):
    result = runner.invoke(cli.app, ["check", "example.com", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["target"] == "example.com"
    assert parsed["verdict"] == "no_problem_detected"
    assert "╭" not in result.stdout
    assert "Verdict" not in result.stdout


def test_timeout_is_passed(mock_diagnostic):
    result = runner.invoke(cli.app, ["check", "example.com", "--timeout", "10"])
    assert result.exit_code == 0
    assert mock_diagnostic["calls"] == [("example.com", 10.0)]


def test_default_timeout(mock_diagnostic):
    runner.invoke(cli.app, ["check", "example.com"])
    assert mock_diagnostic["calls"] == [("example.com", 5.0)]


def test_invalid_domain_exit_code(mock_diagnostic):
    result = runner.invoke(cli.app, ["check", "https://example.com"])
    assert result.exit_code == 2
    assert "Error" in result.stderr
    assert mock_diagnostic["calls"] == []


def test_invalid_domain_json_mode(mock_diagnostic):
    result = runner.invoke(cli.app, ["check", "not a domain", "--json"])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "Error" in result.stderr


@pytest.mark.parametrize(
    ("verdict", "expected"),
    [
        ("no_problem_detected", 0),
        ("possible_network_interference", 1),
        ("possible_service_restriction", 1),
        ("inconclusive", 2),
    ],
)
def test_exit_codes(mock_diagnostic, verdict, expected):
    mock_diagnostic["report"] = make_report(verdict=verdict)
    result = runner.invoke(cli.app, ["check", "example.com", "--json"])
    assert result.exit_code == expected


def test_no_color_env(mock_diagnostic, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    result = runner.invoke(cli.app, ["check", "example.com"])
    assert result.exit_code == 0
    assert "\x1b[" not in result.output


def test_piped_output_has_no_ansi(mock_diagnostic):
    result = runner.invoke(cli.app, ["check", "example.com"])
    assert "\x1b[" not in result.output


def test_timeout_out_of_range():
    result = runner.invoke(cli.app, ["check", "example.com", "--timeout", "0.1"])
    assert result.exit_code == 2
