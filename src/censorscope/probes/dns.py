"""DNS probe: compare system resolver answers with public resolvers."""

from __future__ import annotations

import ipaddress
import socket
import threading
import time

import dns.exception
import dns.resolver

from censorscope.models import STATUS_ERROR, STATUS_SUCCESS, STATUS_WARNING, ProbeResult

PUBLIC_RESOLVERS = {"google": "8.8.8.8", "cloudflare": "1.1.1.1"}


def non_public_reasons(address: str) -> list[str]:
    """Return why an address is not a normal public unicast address (empty if it is)."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return ["invalid"]
    reasons = []
    for flag in ("is_private", "is_loopback", "is_link_local", "is_reserved", "is_multicast",
                 "is_unspecified"):
        if getattr(ip, flag):
            reasons.append(flag.removeprefix("is_"))
    if not reasons and not ip.is_global:
        reasons.append("non-global")
    return reasons


def resolve_system(target: str, timeout: float) -> dict:
    """Resolve via the OS resolver (getaddrinfo), bounded by `timeout`.

    getaddrinfo has no timeout parameter and cannot be cancelled, so it runs
    in a daemon thread. On timeout the thread is abandoned; it exits with the
    process. This keeps exact system semantics (hosts file, nsswitch) while
    bounding the wait.
    """
    start = time.monotonic()
    entry: dict = {"addresses": [], "duration_ms": 0.0, "error": None}
    outcome: dict = {}

    def worker() -> None:
        try:
            infos = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
            outcome["addresses"] = sorted({info[4][0] for info in infos})
        except OSError as exc:
            outcome["error"] = f"system resolver: {exc}"

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        entry["error"] = f"system resolver: timed out after {timeout:g}s"
    else:
        entry["addresses"] = outcome.get("addresses", [])
        entry["error"] = outcome.get("error")
    entry["duration_ms"] = round((time.monotonic() - start) * 1000, 1)
    return entry


def _resolve_public(target: str, server: str, timeout: float) -> dict:
    start = time.monotonic()
    entry: dict = {"addresses": [], "duration_ms": 0.0, "error": None, "nxdomain": False}
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answer = resolver.resolve(target, "A")
        entry["addresses"] = sorted(rdata.address for rdata in answer)
    except dns.resolver.NXDOMAIN:
        entry["nxdomain"] = True
        entry["error"] = f"{server}: NXDOMAIN (domain does not exist)"
    except dns.resolver.NoAnswer:
        entry["error"] = f"{server}: no A record in answer"
    except dns.exception.Timeout:
        entry["error"] = f"{server}: query timed out"
    except (dns.exception.DNSException, OSError) as exc:
        entry["error"] = f"{server}: {exc}"
    entry["duration_ms"] = round((time.monotonic() - start) * 1000, 1)
    return entry


def run(target: str, timeout: float = 5.0) -> ProbeResult:
    """Resolve the domain via the system resolver and two public resolvers."""
    start = time.monotonic()
    system = resolve_system(target, timeout)
    resolvers = {"system": system}
    for name, server in PUBLIC_RESOLVERS.items():
        resolvers[name] = _resolve_public(target, server, timeout)

    answered = {
        name: set(entry["addresses"])
        for name, entry in resolvers.items()
        if entry["addresses"]
    }
    answers_differ = len({frozenset(s) for s in answered.values()}) > 1

    non_public: dict[str, list[str]] = {}
    for entry in resolvers.values():
        for address in entry["addresses"]:
            reasons = non_public_reasons(address)
            if reasons:
                non_public[address] = reasons

    nxdomain = any(entry.get("nxdomain") for entry in resolvers.values())
    all_failed = all(entry["error"] for entry in resolvers.values())
    any_failed = any(entry["error"] for entry in resolvers.values())
    system_failed_public_ok = bool(system["error"]) and any(
        resolvers[name]["addresses"] for name in PUBLIC_RESOLVERS
    )

    details = {
        "resolvers": resolvers,
        "answers_differ": answers_differ,
        "non_public_addresses": non_public,
        "nxdomain": nxdomain,
        "system_failed_public_ok": system_failed_public_ok,
    }

    if all_failed:
        status = STATUS_ERROR
        summary = "All DNS resolvers failed" + (" (NXDOMAIN)" if nxdomain else "")
        error = "; ".join(entry["error"] for entry in resolvers.values())
    elif non_public:
        status = STATUS_WARNING
        summary = f"Non-public addresses returned: {', '.join(sorted(non_public))}"
        error = None
    elif answers_differ:
        status = STATUS_WARNING
        summary = "DNS answers differ between resolvers"
        error = None
    elif nxdomain or any_failed:
        status = STATUS_WARNING
        summary = "Partial DNS failure" + (" (NXDOMAIN from some resolvers)" if nxdomain else "")
        error = "; ".join(entry["error"] for entry in resolvers.values() if entry["error"])
    else:
        status = STATUS_SUCCESS
        ips = ", ".join(sorted(answered.get("system", set())))
        summary = f"Consistent public addresses: {ips}" if ips else "Resolved consistently"
        error = None

    return ProbeResult(
        name="dns",
        status=status,
        summary=summary,
        details=details,
        duration_ms=round((time.monotonic() - start) * 1000, 1),
        error=error,
    )
