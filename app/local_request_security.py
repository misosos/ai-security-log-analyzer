"""Shared, loopback-only request boundary for local features."""

from ipaddress import ip_address
import re

from fastapi import Request


_HOST = re.compile(r"^(?:127\.0\.0\.1|\[::1\])(?::[0-9]{1,5})?$")
_FORWARDING = (
    "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-real-ip", "via",
)


def classify_local_request(request: Request) -> str | None:
    """Return a fixed rejection reason, never a request-controlled value."""
    if request.client is None:
        return "LOOPBACK_REQUIRED"
    try:
        address = ip_address(request.client.host)
    except ValueError:
        return "LOOPBACK_REQUIRED"
    if not address.is_loopback or getattr(address, "ipv4_mapped", None) is not None:
        return "LOOPBACK_REQUIRED"
    if any(name in request.headers for name in _FORWARDING):
        return "FORWARDED_REQUEST_REJECTED"
    hosts = request.headers.getlist("host")
    if len(hosts) != 1 or _HOST.fullmatch(hosts[0]) is None:
        return "INVALID_HOST"
    origins = request.headers.getlist("origin")
    if len(origins) > 1 or (origins and origins[0] != f"{request.url.scheme}://{hosts[0]}"):
        return "ORIGIN_REJECTED"
    if request.headers.get("sec-fetch-site") == "cross-site":
        return "ORIGIN_REJECTED"
    return None
