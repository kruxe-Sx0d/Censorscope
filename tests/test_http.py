"""Tests for the HTTP probe using httpx.MockTransport (no network)."""

import httpx

from censorscope.probes import http as http_probe


def _transport(handler):
    return httpx.MockTransport(handler)


def test_200_ok():
    def handler(request):
        return httpx.Response(200, text="<html><title>Welcome</title></html>")

    result = http_probe.run("example.com", transport=_transport(handler))
    assert result.status == "success"
    assert result.details["checks"]["https"]["status_code"] == 200
    assert result.details["checks"]["http"]["status_code"] == 200
    assert result.details["blocking_phrases"] == []


def test_403_with_blocking_phrase():
    def handler(request):
        return httpx.Response(403, text="<html>Access Denied - request blocked</html>")

    result = http_probe.run("example.com", transport=_transport(handler))
    assert result.status == "warning"
    assert "access denied" in result.details["blocking_phrases"]
    assert "request blocked" in result.details["blocking_phrases"]


def test_451_is_notable():
    def handler(request):
        return httpx.Response(451, text="Unavailable For Legal Reasons")

    result = http_probe.run("example.com", transport=_transport(handler))
    assert result.status == "warning"
    assert "451" in result.summary


def test_regional_phrase_on_200():
    def handler(request):
        return httpx.Response(200, text="This content is not available in your region.")

    result = http_probe.run("example.com", transport=_transport(handler))
    assert result.status == "warning"
    assert "not available in your region" in result.details["blocking_phrases"]


def test_5xx_is_notable():
    def handler(request):
        return httpx.Response(503, text="Service Unavailable")

    result = http_probe.run("example.com", transport=_transport(handler))
    assert result.status == "warning"
    assert "503" in result.summary


def test_404_is_notable():
    def handler(request):
        return httpx.Response(404, text="Not Found")

    result = http_probe.run("example.com", transport=_transport(handler))
    assert result.status == "warning"


def test_redirects_recorded():
    def handler(request):
        return httpx.Response(301, headers={"location": "https://example.com/home"})

    result = http_probe.run("example.com", transport=_transport(handler))
    assert result.status == "success"
    assert result.details["checks"]["https"]["status_code"] == 301
    assert result.details["checks"]["https"]["redirects"] == ["https://example.com/home"]


def test_server_header_recorded():
    def handler(request):
        return httpx.Response(200, text="ok", headers={"server": "nginx"})

    result = http_probe.run("example.com", transport=_transport(handler))
    assert result.details["checks"]["https"]["server"] == "nginx"


def test_connect_error_both_schemes():
    def handler(request):
        raise httpx.ConnectError("connection failed")

    result = http_probe.run("example.com", transport=_transport(handler))
    assert result.status == "error"
    assert result.details["checks"]["https"]["status_code"] is None
    assert "ConnectError" in result.error


def test_timeout():
    def handler(request):
        raise httpx.ReadTimeout("timed out")

    result = http_probe.run("example.com", timeout=0.1, transport=_transport(handler))
    assert result.status == "error"
    assert "timeout" in result.details["checks"]["https"]["error"]


def test_https_fails_http_works():
    def handler(request):
        if request.url.scheme == "https":
            raise httpx.ConnectError("tls failure")
        return httpx.Response(200, text="plain ok")

    result = http_probe.run("example.com", transport=_transport(handler))
    assert result.status == "success"
    assert result.details["checks"]["https"]["error"]
    assert result.details["checks"]["http"]["status_code"] == 200


def test_content_inspection_is_limited():
    huge = b"x" * (http_probe.MAX_INSPECT_BYTES * 2)

    def handler(request):
        return httpx.Response(200, content=huge, headers={"content-type": "text/html"})

    result = http_probe.run("example.com", transport=_transport(handler))
    assert result.details["checks"]["https"]["inspected_bytes"] <= http_probe.MAX_INSPECT_BYTES


def test_binary_body_not_scanned():
    def handler(request):
        return httpx.Response(
            200, content=b"access denied", headers={"content-type": "image/png"}
        )

    result = http_probe.run("example.com", transport=_transport(handler))
    assert result.details["blocking_phrases"] == []


def test_phrase_detection_is_case_insensitive():
    def handler(request):
        return httpx.Response(403, text="ACCESS DENIED")

    result = http_probe.run("example.com", transport=_transport(handler))
    assert "access denied" in result.details["blocking_phrases"]


def test_user_agent_is_sent():
    seen = {}

    def handler(request):
        seen["ua"] = request.headers.get("user-agent")
        return httpx.Response(200, text="ok")

    http_probe.run("example.com", transport=_transport(handler))
    assert seen["ua"].startswith("censorscope/")


def test_malformed_proxy_env_is_ignored(monkeypatch):
    monkeypatch.setenv("no_proxy", "localhost,127.0.0.0/8,[::1],::1")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")

    def handler(request):
        return httpx.Response(200, text="ok")

    result = http_probe.run("example.com", transport=_transport(handler))
    assert result.status == "success"


def test_addresses_route_to_ip_with_host_and_sni():
    seen = []

    def handler(request):
        seen.append(
            (request.url.host, request.headers.get("host"), request.extensions.get("sni_hostname"))
        )
        return httpx.Response(200, text="ok")

    result = http_probe.run(
        "example.com", transport=_transport(handler), addresses=["93.184.216.34"]
    )
    assert result.status == "success"
    assert seen == [
        ("93.184.216.34", "example.com", "example.com"),
        ("93.184.216.34", "example.com", "example.com"),
    ]


def test_empty_addresses_skips_requests():
    def handler(request):
        raise AssertionError("must not request without addresses")

    result = http_probe.run("example.com", transport=_transport(handler), addresses=[])
    assert result.status == "error"
    assert "No DNS addresses" in result.summary
