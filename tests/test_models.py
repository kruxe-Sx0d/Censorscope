"""Tests for data models and JSON serialization."""

import json

from censorscope.models import DiagnosticReport, ProbeResult


def test_probe_result_defaults():
    result = ProbeResult(name="dns", status="success", summary="ok")
    assert result.details == {}
    assert result.duration_ms == 0.0
    assert result.error is None


def test_probe_result_to_dict():
    result = ProbeResult(name="tcp", status="error", summary="failed", error="timeout")
    data = result.to_dict()
    assert data["name"] == "tcp"
    assert data["status"] == "error"
    assert data["error"] == "timeout"
    assert json.loads(json.dumps(data)) == data


def test_report_json_round_trip():
    report = DiagnosticReport(
        target="example.com",
        timestamp="2026-11-08T00:00:00+00:00",
        probe_results=[
            ProbeResult(
                name="dns",
                status="success",
                summary="ok",
                details={"addresses": ["1.2.3.4"]},
            ),
            ProbeResult(name="tcp", status="warning", summary="partial", duration_ms=12.5),
        ],
        verdict="inconclusive",
        confidence="low",
        reasons=["mixed evidence"],
        duration_ms=42.0,
    )
    payload = report.to_json()
    parsed = json.loads(payload)
    assert parsed["target"] == "example.com"
    assert parsed["verdict"] == "inconclusive"
    assert parsed["confidence"] == "low"
    assert parsed["probe_results"][0]["details"] == {"addresses": ["1.2.3.4"]}
    assert parsed["probe_results"][1]["duration_ms"] == 12.5
    assert parsed["reasons"] == ["mixed evidence"]


def test_report_to_dict_matches_json():
    report = DiagnosticReport(
        target="example.com",
        timestamp="t",
        probe_results=[],
        verdict="no_problem_detected",
        confidence="high",
        reasons=[],
        duration_ms=1.0,
    )
    assert json.loads(report.to_json()) == report.to_dict()
