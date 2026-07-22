"""CSRF via standard headers only (DESIGN §9): Origin (RFC 6454) first,
W3C Fetch Metadata (Sec-Fetch-Site) as the fallback signal. No token
embedding — SameSite=Lax cookies are the first line of defense and this
check is the second.
"""

from __future__ import annotations

from hayate import Request

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def is_allowed(request: Request, trusted_origins: frozenset[str]) -> bool:
    if request.method in _SAFE_METHODS:
        return True

    origin = request.headers.get("origin")
    if origin is not None and origin != "null":
        return origin == request.url.origin or origin in trusted_origins

    # No Origin header: browsers send Sec-Fetch-Site; non-browser clients
    # (curl, server-to-server) send neither and cannot carry ambient cookies
    # in a CSRF-relevant way, so they pass.
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None:
        return fetch_site in ("same-origin", "none")
    return True
