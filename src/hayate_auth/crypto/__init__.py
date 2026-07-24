"""Password KDF backends (DESIGN §8, decided by the 2026-07-22 spike).

Default everywhere is scrypt with OWASP parameters; environments whose
Pyodide predates the OpenSSL-backed hashlib fall back to PBKDF2-HMAC-SHA256.
Stored hashes carry a PHC-style algorithm identifier, so verification
dispatches on the stored string and runtimes can be mixed freely
(measured cross-runtime known-answer match in docs/research/kdf.md).

The iron rule: no self-built crypto primitives. Everything below calls
``hashlib`` or WebCrypto.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import sys
from collections.abc import Callable
from importlib import import_module
from typing import Protocol

__all__ = [
    "CryptoBackend",
    "Pbkdf2Backend",
    "ScryptBackend",
    "UnsupportedHashError",
    "default_backend",
]


class UnsupportedHashError(Exception):
    """The stored hash uses an algorithm this runtime cannot verify."""


class CryptoBackend(Protocol):
    async def hash_password(self, password: str) -> str: ...

    async def verify_password(self, password: str, stored: str) -> bool: ...


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4))


async def _off_loop[T](fn: Callable[[], T]) -> T:
    """Run a CPU-heavy KDF without blocking the event loop.

    Pyodide has no threads, but there each request owns its isolate, so
    calling inline is acceptable (DESIGN §8).
    """
    if sys.platform == "emscripten":
        return fn()
    return await asyncio.to_thread(fn)


def _have_scrypt() -> bool:
    return hasattr(hashlib, "scrypt")


def _have_pbkdf2() -> bool:
    return hasattr(hashlib, "pbkdf2_hmac")


class ScryptBackend:
    """scrypt (RFC 7914), OWASP parameters: N=2^17, r=8, p=1, 64 MiB."""

    def __init__(self, *, log_n: int = 17, r: int = 8, p: int = 1, dklen: int = 32) -> None:
        self.log_n = log_n
        self.r = r
        self.p = p
        self.dklen = dklen

    def _derive(self, password: str, salt: bytes, *, log_n: int, r: int, p: int) -> bytes:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=1 << log_n,
            r=r,
            p=p,
            dklen=self.dklen,
            maxmem=2 * 128 * r * (1 << log_n),
        )

    async def hash_password(self, password: str) -> str:
        salt = os.urandom(16)
        derived = await _off_loop(
            lambda: self._derive(password, salt, log_n=self.log_n, r=self.r, p=self.p)
        )
        return (
            f"$scrypt$ln={self.log_n},r={self.r},p={self.p}"
            f"${_b64encode(salt)}${_b64encode(derived)}"
        )

    async def verify_password(self, password: str, stored: str) -> bool:
        return await verify_phc(password, stored)


class Pbkdf2Backend:
    """PBKDF2-HMAC-SHA256 (RFC 8018), OWASP 600k iterations.

    Uses ``hashlib.pbkdf2_hmac`` when present (it is, on current Pyodide);
    otherwise derives through WebCrypto ``deriveBits`` on Workers.
    """

    def __init__(self, *, iterations: int = 600_000, dklen: int = 32) -> None:
        self.iterations = iterations
        self.dklen = dklen

    async def _derive(self, password: str, salt: bytes, iterations: int, dklen: int) -> bytes:
        if _have_pbkdf2():
            return await _off_loop(
                lambda: hashlib.pbkdf2_hmac(
                    "sha256", password.encode("utf-8"), salt, iterations, dklen=dklen
                )
            )
        return await _webcrypto_pbkdf2(password.encode("utf-8"), salt, iterations, dklen)

    async def hash_password(self, password: str) -> str:
        salt = os.urandom(16)
        derived = await self._derive(password, salt, self.iterations, self.dklen)
        return f"$pbkdf2-sha256$i={self.iterations}${_b64encode(salt)}${_b64encode(derived)}"

    async def verify_password(self, password: str, stored: str) -> bool:
        return await verify_phc(password, stored)


async def _webcrypto_pbkdf2(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    js = import_module("js")
    to_js = import_module("pyodide.ffi").to_js

    key = await js.crypto.subtle.importKey(
        "raw", to_js(password), "PBKDF2", False, to_js(["deriveBits"])
    )
    algo = to_js(
        {"name": "PBKDF2", "hash": "SHA-256", "salt": salt, "iterations": iterations},
        dict_converter=js.Object.fromEntries,
    )
    bits = await js.crypto.subtle.deriveBits(algo, key, dklen * 8)
    return bytes(js.Uint8Array.new(bits).to_py())


async def verify_phc(password: str, stored: str) -> bool:
    """Verify against any hash this package ever wrote, whichever backend
    wrote it. Raises UnsupportedHashError when the algorithm cannot run here."""
    parts = stored.split("$")
    if len(parts) != 5 or parts[0] != "":
        return False
    _, algorithm, params, salt_b64, hash_b64 = parts
    salt = _b64decode(salt_b64)
    expected = _b64decode(hash_b64)

    if algorithm == "scrypt":
        if not _have_scrypt():
            raise UnsupportedHashError("stored hash is scrypt but hashlib.scrypt is unavailable")
        values = dict(item.split("=") for item in params.split(","))
        log_n, r, p = int(values["ln"]), int(values["r"]), int(values["p"])
        derived = await _off_loop(
            lambda: hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt,
                n=1 << log_n,
                r=r,
                p=p,
                dklen=len(expected),
                maxmem=2 * 128 * r * (1 << log_n),
            )
        )
    elif algorithm == "pbkdf2-sha256":
        values = dict(item.split("=") for item in params.split(","))
        iterations = int(values["i"])
        backend = Pbkdf2Backend(iterations=iterations, dklen=len(expected))
        derived = await backend._derive(password, salt, iterations, len(expected))
    else:
        raise UnsupportedHashError(f"unknown password hash algorithm {algorithm!r}")

    return hmac.compare_digest(derived, expected)


def default_backend() -> CryptoBackend:
    """Best standard KDF the running interpreter offers (DESIGN §8)."""
    if _have_scrypt():
        return ScryptBackend()
    return Pbkdf2Backend()
