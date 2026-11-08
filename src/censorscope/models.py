"""Data models for probe results and diagnostic reports."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

STATUS_SUCCESS = "success"
STATUS_WARNING = "warning"
STATUS_ERROR = "error"

VERDICT_INTERFERENCE = "possible_network_interference"
VERDICT_RESTRICTION = "possible_service_restriction"
VERDICT_OK = "no_problem_detected"
VERDICT_INCONCLUSIVE = "inconclusive"

CONFIDENCE_LOW = "low"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_HIGH = "high"


@dataclass
class ProbeResult:
    """Standardized outcome of a single network probe."""

    name: str
    status: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DiagnosticReport:
    """Full diagnostic report, serializable to JSON."""

    target: str
    timestamp: str
    probe_results: list[ProbeResult]
    verdict: str
    confidence: str
    reasons: list[str]
    duration_ms: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
