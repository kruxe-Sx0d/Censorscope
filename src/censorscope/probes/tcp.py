"""TCP probe: test raw connectivity to ports 80 and 443."""

from __future__ import annotations

import errno
import socket
import time

from censorscope.models import STATUS_ERROR, STATUS_SUCCESS, STATUS_WARNING, ProbeResult

DEFAULT_PORTS = (80, 443)


def _test_port(target: str, port: int, timeout: float) -> dict:
    start = time.monotonic()
    entry: dict = {"outcome": None, "duration_ms": 0.0, "error": None}
    try:
        with socket.create_connection((target, port), timeout=timeout):
            entry["outcome"] = "connected"
    except socket.gaierror as exc:
        entry["outcome"] = "dns_error"
        entry["error"] = str(exc)
    except ConnectionRefusedError:
        entry["outcome"] = "refused"
        entry["error"] = "connection refused"
    except TimeoutError:
        entry["outcome"] = "timeout"
        entry["error"] = "connection timed out"
    except OSError as exc:
        entry["outcome"] = (
            "unreachable" if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH) else "error"
        )
        entry["error"] = str(exc)
    entry["duration_ms"] = round((time.monotonic() - start) * 1000, 1)
    return entry


def _resolve(target: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
        return sorted({info[4][0] for info in infos})
    except OSError:
        return []


def run(
    target: str,
    timeout: float = 5.0,
    ports: tuple[int, ...] = DEFAULT_PORTS,
    addresses: list[str] | None = None,
) -> ProbeResult:
    """Attempt TCP connections to each port and record the outcomes.

    `addresses` lets the orchestrator reuse DNS probe answers; None means
    resolve here, and an empty list means DNS found nothing to connect to.
    """
    start = time.monotonic()
    if addresses is None:
        addresses = _resolve(target)
    if not addresses:
        return ProbeResult(
            name="tcp",
            status=STATUS_ERROR,
            summary="No DNS addresses available; connection not attempted",
            details={"ports": {}},
            duration_ms=round((time.monotonic() - start) * 1000, 1),
            error="no addresses",
        )

    results = {str(port): _test_port(addresses[0], port, timeout) for port in ports}
    connected = [port for port, entry in results.items() if entry["outcome"] == "connected"]

    if len(connected) == len(results):
        status = STATUS_SUCCESS
        summary = f"Connected on port(s) {', '.join(connected)}"
        error = None
    elif connected:
        status = STATUS_WARNING
        failed = ", ".join(
            f"{port} ({entry['outcome']})"
            for port, entry in results.items()
            if entry["outcome"] != "connected"
        )
        summary = f"Port {', '.join(connected)} reachable; {failed}"
        error = None
    else:
        status = STATUS_ERROR
        summary = "No TCP connection could be established"
        error = "; ".join(f"port {port}: {entry['error']}" for port, entry in results.items())

    return ProbeResult(
        name="tcp",
        status=status,
        summary=summary,
        details={"ports": results},
        duration_ms=round((time.monotonic() - start) * 1000, 1),
        error=error,
    )
