"""Validation and normalization of user-supplied domain names."""

from __future__ import annotations

import ipaddress
import re

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def validate_domain(target: str) -> str:
    """Return the normalized (lowercase, ASCII/punycode) domain.

    Raises ValueError with a user-readable message for anything that is not
    a bare domain name.
    """
    if not isinstance(target, str):
        raise ValueError("target must be a string")

    domain = target.strip().lower().rstrip(".")
    if not domain:
        raise ValueError("target must not be empty")

    if any(ch in domain for ch in (":", "/", "@", "?", "#", " ")) or "://" in domain:
        raise ValueError("target must be a bare domain name (no scheme, port, path, or userinfo)")

    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("target must be a domain name, not an IP address")

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid internationalized domain name: {exc}") from exc

    if len(domain) > 253:
        raise ValueError("domain name is too long (max 253 characters)")

    labels = domain.split(".")
    if len(labels) < 2:
        raise ValueError("target must be a fully qualified domain name (e.g. example.com)")

    for label in labels:
        if not _LABEL_RE.match(label):
            raise ValueError(f"invalid domain label: {label!r}")

    return domain
