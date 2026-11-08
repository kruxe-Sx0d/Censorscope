"""Tests for the rule-based classifier using synthetic probe results."""

from censorscope.classifier import classify
from censorscope.models import ProbeResult


def dns_result(
    status="success", differ=False, non_public=None, nxdomain=False, system_failed_public_ok=False
):
    return ProbeResult(
        name="dns",
        status=status,
        summary="dns " + status,
        details={
            "answers_differ": differ,
            "non_public_addresses": non_public or {},
            "nxdomain": nxdomain,
            "system_failed_public_ok": system_failed_public_ok,
        },
    )


def tcp_result(status="success", outcomes=("connected", "connected")):
    return ProbeResult(
        name="tcp",
        status=status,
        summary="tcp " + status,
        details={
            "ports": {
                str(port): {"outcome": outcome}
                for port, outcome in zip((80, 443), outcomes, strict=True)
            }
        },
    )


def tls_result(status="success", sni="success", no_sni="success", sni_specific=False):
    return ProbeResult(
        name="tls",
        status=status,
        summary="tls " + status,
        details={
            "sni": {"outcome": sni},
            "no_sni": {"outcome": no_sni},
            "sni_specific_failure": sni_specific,
        },
    )


def http_result(status="success", codes=(200, 200), phrases=()):
    return ProbeResult(
        name="http",
        status=status,
        summary="http " + status,
        details={
            "checks": {
                scheme: {"status_code": code}
                for scheme, code in zip(("https", "http"), codes, strict=True)
            },
            "blocking_phrases": list(phrases),
        },
    )


def test_all_normal():
    verdict, confidence, reasons = classify(
        [dns_result(), tcp_result(), tls_result(), http_result()]
    )
    assert verdict == "no_problem_detected"
    assert confidence == "high"
    assert reasons


def test_451_service_restriction():
    verdict, confidence, reasons = classify(
        [dns_result(), tcp_result(), tls_result(), http_result("warning", codes=(451, 451))]
    )
    assert verdict == "possible_service_restriction"
    assert confidence == "medium"
    assert any("451" in r for r in reasons)
    assert any("intermediary" in r for r in reasons)


def test_403_regional_restriction():
    verdict, confidence, _ = classify(
        [
            dns_result(),
            tcp_result(),
            tls_result(),
            http_result("warning", codes=(403, 403), phrases=("not available in your region",)),
        ]
    )
    assert verdict == "possible_service_restriction"
    assert confidence == "medium"


def test_regional_phrase_with_broken_tls_is_medium():
    verdict, confidence, _ = classify(
        [
            dns_result(),
            tcp_result(),
            tls_result("error", sni="handshake_error", no_sni="handshake_error"),
            http_result("warning", codes=(403, None), phrases=("geo restricted",)),
        ]
    )
    assert verdict == "possible_service_restriction"
    assert confidence == "medium"


def test_regional_phrase_on_200_is_inconclusive():
    verdict, confidence, reasons = classify(
        [
            dns_result(),
            tcp_result(),
            tls_result(),
            http_result("warning", phrases=("not available in your region",)),
        ]
    )
    assert verdict == "inconclusive"
    assert confidence == "low"
    assert any("corroborating" in r for r in reasons)


def test_non_regional_phrase_alone_is_inconclusive():
    verdict, confidence, reasons = classify(
        [
            dns_result(),
            tcp_result(),
            tls_result(),
            http_result("warning", phrases=("access denied",)),
        ]
    )
    assert verdict == "inconclusive"
    assert confidence == "low"
    assert any("corroborating" in r for r in reasons)


def test_dns_poisoning_pattern_high_confidence():
    verdict, confidence, reasons = classify(
        [
            dns_result("warning", differ=True, non_public={"127.0.0.1": ["loopback"]}),
            tcp_result("error", outcomes=("timeout", "timeout")),
            tls_result("error", sni="timeout", no_sni="timeout"),
            http_result("error", codes=(None, None)),
        ]
    )
    assert verdict == "possible_network_interference"
    assert confidence == "high"
    assert any("Non-public" in r for r in reasons)


def test_dns_poisoning_pattern_without_tcp_failure():
    verdict, confidence, _ = classify(
        [
            dns_result("warning", differ=True, non_public={"10.0.0.1": ["private"]}),
            tcp_result(),
            tls_result(),
            http_result(),
        ]
    )
    assert verdict == "possible_network_interference"
    assert confidence == "medium"


def test_sni_specific_failure():
    verdict, confidence, reasons = classify(
        [
            dns_result(),
            tcp_result(),
            tls_result("warning", sni="reset", no_sni="success", sni_specific=True),
            http_result("error", codes=(None, None)),
        ]
    )
    assert verdict == "possible_network_interference"
    assert confidence == "medium"
    assert any("SNI" in r for r in reasons)


def test_dns_ok_but_tcp_and_tls_fail():
    verdict, confidence, reasons = classify(
        [
            dns_result(),
            tcp_result("error", outcomes=("timeout", "timeout")),
            tls_result("error", sni="timeout", no_sni="timeout"),
            http_result("error", codes=(None, None)),
        ]
    )
    assert verdict == "possible_network_interference"
    assert confidence == "medium"
    assert any("outage" in r for r in reasons)


def test_dns_difference_alone_is_low_confidence():
    verdict, confidence, reasons = classify(
        [dns_result("warning", differ=True), tcp_result(), tls_result(), http_result()]
    )
    assert verdict == "possible_network_interference"
    assert confidence == "low"
    assert any("not proof" in r for r in reasons)


def test_non_public_without_difference_is_low():
    verdict, confidence, _ = classify(
        [
            dns_result("warning", non_public={"192.168.1.1": ["private"]}),
            tcp_result(),
            tls_result(),
            http_result(),
        ]
    )
    assert verdict == "possible_network_interference"
    assert confidence == "low"


def test_empty_results_inconclusive():
    verdict, confidence, reasons = classify([])
    assert verdict == "inconclusive"
    assert confidence == "low"
    assert reasons


def test_nxdomain_inconclusive():
    verdict, _, reasons = classify(
        [
            dns_result("error", nxdomain=True),
            tcp_result("error", outcomes=("dns_error", "dns_error")),
            tls_result("error", sni="connection_error", no_sni="connection_error"),
            http_result("error", codes=(None, None)),
        ]
    )
    assert verdict == "inconclusive"
    assert any("NXDOMAIN" in r for r in reasons)


def test_contradictory_tcp_ok_http_fails():
    verdict, _, reasons = classify(
        [dns_result(), tcp_result(), tls_result(), http_result("error", codes=(None, None))]
    )
    assert verdict == "inconclusive"
    assert any("contradictory" in r for r in reasons)


def test_missing_probes_handled():
    verdict, confidence, _ = classify([dns_result()])
    assert verdict == "inconclusive"
    assert confidence == "low"


def test_generic_403_alone_is_inconclusive():
    verdict, _, _ = classify(
        [dns_result(), tcp_result(), tls_result(), http_result("warning", codes=(403, 403))]
    )
    assert verdict == "inconclusive"


def test_system_dns_fails_public_works_and_service_reachable():
    verdict, confidence, reasons = classify(
        [
            dns_result("warning", system_failed_public_ok=True),
            tcp_result(),
            tls_result(),
            http_result(),
        ]
    )
    assert verdict == "possible_network_interference"
    assert confidence == "medium"
    assert any("system resolver" in r for r in reasons)
