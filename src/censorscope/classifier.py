"""Rule-based classifier: turn probe evidence into a cautious verdict."""

from __future__ import annotations

from censorscope.models import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    STATUS_ERROR,
    STATUS_SUCCESS,
    VERDICT_INCONCLUSIVE,
    VERDICT_INTERFERENCE,
    VERDICT_OK,
    VERDICT_RESTRICTION,
    ProbeResult,
)
from censorscope.probes.http import REGIONAL_PHRASES


def _probe(results: list[ProbeResult], name: str) -> ProbeResult | None:
    return next((r for r in results if r.name == name), None)


def classify(results: list[ProbeResult]) -> tuple[str, str, list[str]]:
    """Return (verdict, confidence, reasons) from collected probe evidence.

    Rules are ordered: explicit service-side signals first, then interference
    signals (strongest combinations first), then all-clear, then inconclusive.
    """
    dns = _probe(results, "dns")
    tcp = _probe(results, "tcp")
    tls = _probe(results, "tls")
    http = _probe(results, "http")

    dns_d = dns.details if dns else {}
    tls_d = tls.details if tls else {}
    http_d = http.details if http else {}

    dns_ok = dns is not None and dns.status == STATUS_SUCCESS
    non_public = dns_d.get("non_public_addresses", {})
    answers_differ = dns_d.get("answers_differ", False)
    nxdomain = dns_d.get("nxdomain", False)

    # Probe status semantics: tcp success = all ports connected, error = none;
    # tls success = handshake with real SNI worked.
    tcp_ok = tcp is not None and tcp.status == STATUS_SUCCESS
    tcp_all_failed = tcp is not None and tcp.status == STATUS_ERROR

    sni_ok = tls is not None and tls.status == STATUS_SUCCESS
    tls_failed = tls is not None and not sni_ok
    sni_specific = tls_d.get("sni_specific_failure", False)

    checks = http_d.get("checks", {})
    codes = [c["status_code"] for c in checks.values() if c.get("status_code") is not None]
    phrases = http_d.get("blocking_phrases", [])
    regional = [p for p in phrases if p in REGIONAL_PHRASES]
    http_ok = http is not None and http.status == STATUS_SUCCESS
    http_unreachable = http is not None and http.status == STATUS_ERROR

    # --- Rule 1: explicit service-side restriction signals -------------------
    if 451 in codes:
        reasons = ["HTTP 451 (Unavailable For Legal Reasons) returned by the service."]
        if regional:
            reasons.append(
                f"Response body contains regional restriction language: {regional[0]!r}."
            )
        reasons.append("The service itself is refusing access; this is not a network-level block.")
        return VERDICT_RESTRICTION, CONFIDENCE_HIGH, reasons

    if regional and (403 in codes or any(200 <= c < 300 for c in codes)):
        reasons = [
            f"Response body contains regional restriction language: {regional[0]!r}.",
            f"HTTP status code(s) observed: {', '.join(map(str, sorted(set(codes))))}.",
        ]
        if dns_ok and tcp_ok and sni_ok:
            reasons.append("DNS, TCP, and TLS all work, so the refusal comes from the service.")
            return VERDICT_RESTRICTION, CONFIDENCE_HIGH, reasons
        reasons.append("The service is reachable and explicitly refuses this region.")
        return VERDICT_RESTRICTION, CONFIDENCE_MEDIUM, reasons

    # --- Rule 2: possible network interference -------------------------------
    if non_public and answers_differ:
        reasons = [
            f"Non-public addresses returned by some resolvers: {', '.join(sorted(non_public))}.",
            "DNS answers differ between resolvers, which is consistent with DNS manipulation.",
        ]
        if tcp_all_failed or tls_failed:
            reasons.append("TCP/TLS connections also fail, corroborating interference.")
            return VERDICT_INTERFERENCE, CONFIDENCE_HIGH, reasons
        reasons.append("This pattern can also occur with split-horizon DNS; it is not proof.")
        return VERDICT_INTERFERENCE, CONFIDENCE_MEDIUM, reasons

    if sni_specific:
        reasons = [
            "TLS handshake fails with the real SNI but succeeds without SNI.",
            "This pattern is consistent with SNI-based interference, but is not definitive proof.",
        ]
        if answers_differ:
            reasons.append(
                "DNS answers also differ between resolvers, adding corroborating evidence."
            )
            return VERDICT_INTERFERENCE, CONFIDENCE_HIGH, reasons
        return VERDICT_INTERFERENCE, CONFIDENCE_MEDIUM, reasons

    if dns_ok and tcp_all_failed and tls_failed:
        reasons = [
            "DNS resolves to public addresses, but all TCP connections and TLS fail.",
            "Consistent with network-level blocking; a service outage could look the same.",
        ]
        return VERDICT_INTERFERENCE, CONFIDENCE_MEDIUM, reasons

    if dns_d.get("system_failed_public_ok") and (tcp_ok or sni_ok or http_ok):
        reasons = [
            "The system resolver fails while public resolvers answer, and the service "
            "is reachable at those public addresses.",
            "Consistent with DNS-level interference; a local resolver misconfiguration "
            "could produce the same pattern.",
        ]
        return VERDICT_INTERFERENCE, CONFIDENCE_MEDIUM, reasons

    if non_public:
        reasons = [
            f"Non-public addresses returned: {', '.join(sorted(non_public))}.",
            "May indicate a DNS sinkhole, but can also be intentional split-horizon configuration.",
        ]
        return VERDICT_INTERFERENCE, CONFIDENCE_LOW, reasons

    if answers_differ:
        reasons = [
            "DNS answers differ between resolvers.",
            "Differences alone are not proof of filtering: CDNs and geo-DNS commonly return "
            "different addresses.",
        ]
        return VERDICT_INTERFERENCE, CONFIDENCE_LOW, reasons

    # --- Rule 3: everything normal -------------------------------------------
    if dns_ok and tcp_ok and sni_ok and http_ok:
        reasons = [
            "DNS answers are consistent and public; TCP, TLS, and HTTP checks all passed.",
            "No problem detected does not guarantee the absence of filtering.",
        ]
        return VERDICT_OK, CONFIDENCE_HIGH, reasons

    # --- Rule 4: incomplete or contradictory evidence ------------------------
    reasons = [f"{r.name}: {r.summary}" for r in results if r.status != STATUS_SUCCESS]
    if not results:
        reasons = ["No probe results were collected."]
    if nxdomain:
        reasons.append("NXDOMAIN observed: the domain may not exist, or DNS may be manipulated.")
    if http_unreachable and tcp_ok:
        reasons.append("TCP connects but HTTP fails, which is contradictory.")
    reasons.append("Evidence is incomplete or contradictory; no reliable conclusion can be drawn.")
    return VERDICT_INCONCLUSIVE, CONFIDENCE_LOW, reasons
