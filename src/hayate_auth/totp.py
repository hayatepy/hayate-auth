"""TOTP (RFC 6238) two-factor, stdlib only (DESIGN §2: hmac + base32).

No self-built crypto: HOTP/TOTP are HMAC-SHA1 over a time counter
(RFC 4226 / RFC 6238), and Base32 is stdlib. The provisioning URI
(otpauth://) is the de-facto authenticator-app format.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import sys
import time
from urllib.parse import quote

DIGITS = 6
PERIOD = 30


def generate_secret(length: int = 20) -> str:
    """A fresh Base32 secret (RFC 4226 recommends >= 128 bits; 160 here)."""
    return base64.b32encode(secrets.token_bytes(length)).decode("ascii").rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    padded = secret + "=" * (-len(secret) % 8)
    if sys.platform == "emscripten":
        print("hayate-auth TOTP trace: base32", flush=True)
    key = base64.b32decode(padded, casefold=True)
    if sys.platform == "emscripten":
        print("hayate-auth TOTP trace: counter", flush=True)
    packed_counter = struct.pack(">Q", counter)
    # Use the callable form like the rest of the package. Pyodide/workerd can
    # terminate its isolate while resolving the OpenSSL algorithm-name string,
    # even though the same RFC 6238 SHA-1 implementation works via hashlib.
    if sys.platform == "emscripten":
        print("hayate-auth TOTP trace: hmac", flush=True)
    digest = hmac.new(key, packed_counter, hashlib.sha1).digest()
    if sys.platform == "emscripten":
        print("hayate-auth TOTP trace: truncate", flush=True)
    offset = digest[-1] & 0x0F
    code = (int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF) % (10**DIGITS)
    return str(code).zfill(DIGITS)


def code_at(secret: str, moment: float) -> str:
    return _hotp(secret, int(moment // PERIOD))


def matching_step(
    secret: str, code: str, *, at: float | None = None, window: int = 1
) -> int | None:
    """Return the highest matching time step inside the accepted clock window.

    Every candidate is compared before returning. The concrete step lets the
    persistence layer atomically reject replay and state rollback; a boolean
    alone cannot enforce single use across processes or Worker isolates.
    """
    if not code or not code.isdigit():
        return None
    now = at if at is not None else time.time()
    counter = int(now // PERIOD)
    matched: int | None = None
    for step in range(-window, window + 1):
        candidate = counter + step
        candidate_code = _hotp(secret, candidate)
        if sys.platform == "emscripten":
            print("hayate-auth TOTP trace: compare", flush=True)
        if hmac.compare_digest(candidate_code, code):
            matched = candidate
    return matched


def verify(secret: str, code: str, *, at: float | None = None, window: int = 1) -> bool:
    """Constant-time check across +/- ``window`` steps (clock-skew tolerance)."""
    return matching_step(secret, code, at=at, window=window) is not None


def provisioning_uri(secret: str, *, account_name: str, issuer: str) -> str:
    """otpauth:// URI for authenticator apps / QR codes.

    The label is ``issuer:account`` with the colon kept literal (the de-facto
    Key URI format); each side is percent-encoded on its own."""
    label = f"{quote(issuer)}:{quote(account_name)}"
    params = f"secret={secret}&issuer={quote(issuer)}&digits={DIGITS}&period={PERIOD}"
    return f"otpauth://totp/{label}?{params}"
