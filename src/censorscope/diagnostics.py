"""Diagnostic orchestrator: run all probes and build the final report."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime

from censorscope.classifier import classify
from censorscope.models import STATUS_ERROR, DiagnosticReport, ProbeResult
from censorscope.probes import dns, http, tcp, tls
from censorscope.validation import validate_domain

_PROBE_MODULES = (("dns", dns), ("tcp", tcp), ("tls", tls), ("http", http))


def _pick_addresses(dns_result: ProbeResult) -> list[str]:
    """Prefer system-resolved addresses, fall back to public resolver answers."""
    resolvers = dns_result.details.get("resolvers", {})
    system = resolvers.get("system", {}).get("addresses", [])
    if system:
        return system
    for name in ("google", "cloudflare"):
        addresses = resolvers.get(name, {}).get("addresses", [])
        if addresses:
            return addresses
    return []


def run_diagnostic(
    target: str,
    timeout: float = 5.0,
    progress: Callable[[str], None] | None = None,
) -> DiagnosticReport:
    """Validate the target, run every probe, and classify the collected evidence.

    Individual probe failures never abort the run. `progress`, when provided,
    is called with each probe's name before it starts. Addresses resolved by
    the DNS probe are reused by later probes so a broken system resolver
    cannot stall every connection attempt.
    """
    domain = validate_domain(target)
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    start = time.monotonic()
    results: list[ProbeResult] = []
    addresses: list[str] | None = None
    for name, module in _PROBE_MODULES:
        if progress is not None:
            progress(name)
        try:
            if name == "dns":
                result = module.run(domain, timeout)
                addresses = _pick_addresses(result)
            else:
                result = module.run(domain, timeout, addresses=addresses)
            results.append(result)
        except Exception as exc:
            results.append(
                ProbeResult(
                    name=name,
                    status=STATUS_ERROR,
                    summary=f"{name} probe failed unexpectedly",
                    error=f"{type(exc).__name__}: {exc}",
                )
            )

    verdict, confidence, reasons = classify(results)
    return DiagnosticReport(
        target=domain,
        timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
        probe_results=results,
        verdict=verdict,
        confidence=confidence,
        reasons=reasons,
        duration_ms=round((time.monotonic() - start) * 1000, 1),
    )
