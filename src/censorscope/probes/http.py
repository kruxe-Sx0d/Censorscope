"""HTTP probe: status codes, redirects, headers, and blocking indicators."""

from __future__ import annotations

import time

import httpx

from censorscope import __version__
from censorscope.models import STATUS_ERROR, STATUS_SUCCESS, STATUS_WARNING, ProbeResult

MAX_INSPECT_BYTES = 65536

BLOCKING_PHRASES = (
    "access denied",
    "request blocked",
    "not available in your region",
    "geo restricted",
    "geo-restricted",
    "service unavailable in your country",
    "not available in your country",
    "unavailable in your region",
)

REGIONAL_PHRASES = tuple(
    p for p in BLOCKING_PHRASES if "region" in p or "country" in p or "geo" in p
)


def _scan_body(headers: httpx.Headers, chunks: list[bytes]) -> tuple[list[str], int]:
    content_type = headers.get("content-type", "").lower()
    textual = (
        not content_type
        or "text" in content_type
        or "html" in content_type
        or "json" in content_type
        or "xml" in content_type
    )
    body = b"".join(chunks)[:MAX_INSPECT_BYTES]
    if not textual:
        return [], len(body)
    text = body.decode("utf-8", errors="replace").lower()
    return [phrase for phrase in BLOCKING_PHRASES if phrase in text], len(body)


def _check_url(client: httpx.Client, url: str, sni_hostname: str | None = None) -> dict:
    start = time.monotonic()
    entry: dict = {
        "url": url,
        "status_code": None,
        "redirects": [],
        "server": None,
        "blocking_phrases": [],
        "inspected_bytes": 0,
        "duration_ms": 0.0,
        "error": None,
    }
    headers = {"Host": sni_hostname} if sni_hostname else {}
    extensions = {"sni_hostname": sni_hostname} if sni_hostname else {}
    try:
        with client.stream("GET", url, headers=headers, extensions=extensions) as response:
            entry["status_code"] = response.status_code
            location = response.headers.get("location")
            if location:
                entry["redirects"] = [location]
            entry["server"] = response.headers.get("server")
            chunks = []
            size = 0
            for chunk in response.iter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_INSPECT_BYTES:
                    break
            entry["blocking_phrases"], entry["inspected_bytes"] = _scan_body(
                response.headers, chunks
            )
    except httpx.TimeoutException as exc:
        entry["error"] = f"timeout: {exc}"
    except httpx.HTTPError as exc:
        entry["error"] = f"{type(exc).__name__}: {exc}"
    entry["duration_ms"] = round((time.monotonic() - start) * 1000, 1)
    return entry


def run(
    target: str,
    timeout: float = 5.0,
    transport: httpx.BaseTransport | None = None,
    addresses: list[str] | None = None,
) -> ProbeResult:
    """Request the target over HTTPS and HTTP and inspect the responses.

    `transport` exists so tests can inject httpx.MockTransport. `addresses`
    lets the orchestrator reuse DNS probe answers: requests then go to the IP
    with the real domain in the Host header and TLS SNI. Redirects are recorded
    but not followed, keeping the probe bounded.
    """
    start = time.monotonic()
    if addresses is not None and not addresses:
        return ProbeResult(
            name="http",
            status=STATUS_ERROR,
            summary="No DNS addresses available; request not attempted",
            details={"checks": {}, "blocking_phrases": []},
            duration_ms=round((time.monotonic() - start) * 1000, 1),
            error="no addresses",
        )

    checks: dict[str, dict] = {}
    host = addresses[0] if addresses else target
    sni_hostname = target if addresses else None
    with httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        transport=transport,
        # Diagnostics must measure the direct network path, and malformed
        # proxy/no_proxy env values can crash httpx's URL parsing.
        trust_env=False,
        headers={"User-Agent": f"censorscope/{__version__}"},
    ) as client:
        for scheme in ("https", "http"):
            checks[scheme] = _check_url(client, f"{scheme}://{host}/", sni_hostname)

    phrases = sorted({p for check in checks.values() for p in check["blocking_phrases"]})
    codes = [check["status_code"] for check in checks.values() if check["status_code"]]
    reachable = [c for c in checks.values() if c["status_code"] is not None]
    suspicious_codes = sorted({c for c in codes if c in (403, 404, 451) or c >= 500})

    details = {"checks": checks, "blocking_phrases": phrases}

    if not reachable:
        status = STATUS_ERROR
        summary = "No HTTP response over HTTPS or HTTP"
        error = "; ".join(f"{scheme}: {check['error']}" for scheme, check in checks.items())
    elif phrases:
        status = STATUS_WARNING
        summary = f"Blocking indicators in response body: {', '.join(phrases)}"
        error = None
    elif suspicious_codes:
        status = STATUS_WARNING
        summary = f"Notable HTTP status code(s): {', '.join(map(str, suspicious_codes))}"
        error = None
    else:
        status = STATUS_SUCCESS
        summary = f"HTTP responding (status {', '.join(map(str, sorted(set(codes))))})"
        error = None

    return ProbeResult(
        name="http",
        status=status,
        summary=summary,
        details=details,
        duration_ms=round((time.monotonic() - start) * 1000, 1),
        error=error,
    )
