"""TLS probe: handshake with real SNI and a comparison connection without SNI."""

from __future__ import annotations

import socket
import ssl
import time

from censorscope.models import STATUS_ERROR, STATUS_SUCCESS, STATUS_WARNING, ProbeResult


def _handshake(target: str, port: int, timeout: float, sni: str | None) -> dict:
    start = time.monotonic()
    entry: dict = {"outcome": None, "duration_ms": 0.0, "error": None}
    context = ssl.create_default_context()
    if sni is None:
        # Chain verification stays enabled; only hostname matching is relaxed,
        # because without SNI many servers present a default certificate.
        context.check_hostname = False
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with context.wrap_socket(sock, server_hostname=sni) as tls:
                entry["outcome"] = "success"
                entry["protocol"] = tls.version()
                cipher = tls.cipher()
                entry["cipher"] = cipher[0] if cipher else None
    except ssl.SSLCertVerificationError as exc:
        entry["outcome"] = "cert_error"
        entry["error"] = str(exc)
    except ssl.SSLError as exc:
        entry["outcome"] = "handshake_error"
        entry["error"] = str(exc)
    except ConnectionResetError:
        entry["outcome"] = "reset"
        entry["error"] = "connection reset during handshake"
    except TimeoutError:
        entry["outcome"] = "timeout"
        entry["error"] = "handshake timed out"
    except OSError as exc:
        entry["outcome"] = "connection_error"
        entry["error"] = str(exc)
    entry["duration_ms"] = round((time.monotonic() - start) * 1000, 1)
    return entry


def run(
    target: str,
    timeout: float = 5.0,
    port: int = 443,
    addresses: list[str] | None = None,
) -> ProbeResult:
    """Compare TLS behavior with the real SNI and without SNI.

    `addresses` lets the orchestrator reuse DNS probe answers; the real
    domain is still used for SNI and certificate verification.
    """
    start = time.monotonic()
    if addresses is None:
        try:
            infos = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
            addresses = sorted({info[4][0] for info in infos})
        except OSError:
            addresses = []
    if not addresses:
        return ProbeResult(
            name="tls",
            status=STATUS_ERROR,
            summary="No DNS addresses available; handshake not attempted",
            details={"port": port},
            duration_ms=round((time.monotonic() - start) * 1000, 1),
            error="no addresses",
        )

    with_sni = _handshake(addresses[0], port, timeout, sni=target)
    without_sni = _handshake(addresses[0], port, timeout, sni=None)

    sni_specific_failure = (
        with_sni["outcome"] != "success" and without_sni["outcome"] == "success"
    )

    details = {
        "port": port,
        "sni": with_sni,
        "no_sni": without_sni,
        "sni_specific_failure": sni_specific_failure,
    }

    if with_sni["outcome"] == "success":
        status = STATUS_SUCCESS
        summary = f"TLS handshake succeeded ({with_sni.get('protocol')})"
        error = None
    elif sni_specific_failure:
        status = STATUS_WARNING
        summary = "Handshake fails with real SNI but succeeds without SNI (suspicious)"
        error = with_sni["error"]
    else:
        status = STATUS_ERROR
        summary = f"TLS handshake failed ({with_sni['outcome']})"
        error = with_sni["error"]

    return ProbeResult(
        name="tls",
        status=status,
        summary=summary,
        details=details,
        duration_ms=round((time.monotonic() - start) * 1000, 1),
        error=error,
    )
