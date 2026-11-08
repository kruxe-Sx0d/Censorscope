"""TCP probe: test raw connectivity to ports 80 and 443."""

from __future__ import annotations

import errno
import socket
import time

from censorscope.models import STATUS_ERROR, STATUS_SUCCESS, STATUS_WARNING, ProbeResult
from censorscope.probes.dns import resolve_system

DEFAULT_PORTS = (80, 443)


def _test_port(addresses: list[str], port: int, timeout: float) -> dict:
    """Try every address until one connects; record each attempt."""
    start = time.monotonic()
    entry: dict = {
        "outcome": None,
        "address": None,
        "attempts": [],
        "duration_ms": 0.0,
        "error": None,
    }
    for address in addresses:
        attempt: dict = {"address": address, "outcome": None, "duration_ms": 0.0, "error": None}
        attempt_start = time.monotonic()
        try:
            with socket.create_connection((address, port), timeout=timeout):
                attempt["outcome"] = "connected"
        except socket.gaierror as exc:
            attempt["outcome"] = "dns_error"
            attempt["error"] = str(exc)
        except ConnectionRefusedError:
            attempt["outcome"] = "refused"
            attempt["error"] = "connection refused"
        except TimeoutError:
            attempt["outcome"] = "timeout"
            attempt["error"] = "connection timed out"
        except OSError as exc:
            attempt["outcome"] = (
                "unreachable" if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH) else "error"
            )
            attempt["error"] = str(exc)
        attempt["duration_ms"] = round((time.monotonic() - attempt_start) * 1000, 1)
        entry["attempts"].append(attempt)
        if attempt["outcome"] == "connected":
            entry["outcome"] = "connected"
            entry["address"] = address
            break
    else:
        entry["outcome"] = entry["attempts"][-1]["outcome"]
        entry["error"] = entry["attempts"][-1]["error"]
    entry["duration_ms"] = round((time.monotonic() - start) * 1000, 1)
    return entry


def run(
    target: str,
    timeout: float = 5.0,
    ports: tuple[int, ...] = DEFAULT_PORTS,
    addresses: list[str] | None = None,
) -> ProbeResult:
    """Attempt TCP connections to each port and record the outcomes.

    Every resolved IPv4 address is tried per port (each attempt gets its own
    timeout); the port counts as connected if any address accepts. `addresses`
    lets the orchestrator reuse DNS probe answers; None means resolve here,
    and an empty list means DNS found nothing to connect to.
    """
    start = time.monotonic()
    if addresses is None:
        addresses = resolve_system(target, timeout)["addresses"]
    if not addresses:
        return ProbeResult(
            name="tcp",
            status=STATUS_ERROR,
            summary="No DNS addresses available; connection not attempted",
            details={"ports": {}},
            duration_ms=round((time.monotonic() - start) * 1000, 1),
            error="no addresses",
        )

    results = {str(port): _test_port(addresses, port, timeout) for port in ports}
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
