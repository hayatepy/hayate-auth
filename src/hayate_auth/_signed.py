"""HMAC-signed opaque values (stdlib only; no self-built primitives).

Used for the OAuth state cookie: the value round-trips through the client,
so it carries a signature instead of a database row — which also survives
Workers isolate recycling (research/kdf.md, production finding 5).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any


def _mac(secret: str, payload: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def sign_payload(secret: str, data: dict[str, Any]) -> str:
    payload = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"{body}.{_mac(secret, payload)}"


def unsign_payload(secret: str, signed: str) -> dict[str, Any] | None:
    body, _, mac = signed.partition(".")
    if not body or not mac:
        return None
    try:
        payload = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (ValueError, TypeError):
        return None
    if not hmac.compare_digest(_mac(secret, payload), mac):
        return None
    try:
        data = json.loads(payload)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None
