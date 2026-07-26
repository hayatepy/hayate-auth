"""RFC 9449 Demonstrating Proof of Possession (DPoP).

The protocol parsing and policy live here; signature operations are delegated
to ``cryptography`` on regular Python and WebCrypto on Python Workers.  No
cryptographic primitive is implemented by hayate-auth.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib import import_module
from typing import Any, Protocol
from urllib.parse import urlsplit

from hayate import Request

from . import session as sessions
from ._uuid7 import new_id
from .adapter import Adapter, Where

ES256 = "ES256"
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_PRIVATE_JWK_MEMBERS = frozenset(
    {
        "d",
        "p",
        "q",
        "dp",
        "dq",
        "qi",
        "oth",
        "k",
    }
)


class DPoPValidationError(ValueError):
    """A proof is absent, malformed, invalid, expired, or replayed."""

    def __init__(self, description: str, *, error: str = "invalid_dpop_proof") -> None:
        super().__init__(description)
        self.error = error
        self.description = description


class DPoPSignatureVerifier(Protocol):
    async def verify(
        self,
        *,
        algorithm: str,
        jwk: dict[str, Any],
        signing_input: bytes,
        signature: bytes,
    ) -> bool: ...


class DPoPReplayStore(Protocol):
    async def record(self, *, jkt: str, jti: str, expires_at: datetime) -> bool:
        """Atomically store a proof identifier; return false if it already exists."""
        ...


@dataclass(frozen=True)
class DPoPConfig:
    """DPoP policy shared by authorization and resource servers.

    ``require_bound_tokens`` opts the whole authorization server into
    DPoP-only issuance.  Leaving it false preserves current MCP Bearer-client
    interoperability while still honoring an RFC 9449 DPoP request.
    """

    signature_verifier: DPoPSignatureVerifier | None = None
    replay_store: DPoPReplayStore | None = None
    algorithms: tuple[str, ...] = (ES256,)
    max_age: timedelta = timedelta(minutes=5)
    clock_skew: timedelta = timedelta(seconds=30)
    require_bound_tokens: bool = False

    def __post_init__(self) -> None:
        if not self.algorithms or any(algorithm != ES256 for algorithm in self.algorithms):
            raise ValueError("the cross-runtime DPoP profile currently supports only ES256")
        if len(set(self.algorithms)) != len(self.algorithms):
            raise ValueError("DPoP algorithms must be unique")
        if self.max_age <= timedelta(0):
            raise ValueError("DPoP max_age must be greater than zero")
        if self.clock_skew < timedelta(0):
            raise ValueError("DPoP clock_skew must not be negative")


@dataclass(frozen=True)
class DPoPProof:
    jkt: str
    jti: str
    iat: int
    jwk: dict[str, Any]


TokenVerifier = Callable[[str], Awaitable[dict[str, Any] | None]]


@dataclass(frozen=True)
class DPoPRequestVerifier:
    """Request-aware verifier for a DPoP-bound protected resource."""

    verify_token: TokenVerifier
    config: DPoPConfig
    replay_store: DPoPReplayStore

    async def __call__(self, request: Request) -> dict[str, Any] | None:
        raw = getattr(request, "raw", request)
        authorization = [
            value for name, value in raw.headers.raw() if name.lower() == "authorization"
        ]
        if len(authorization) != 1:
            return None
        scheme, separator, token = authorization[0].partition(" ")
        token = token.strip()
        if (
            not separator
            or scheme.lower() != "dpop"
            or not token
            or any(character.isspace() for character in token)
        ):
            return None
        claims = await self.verify_token(token)
        if claims is None:
            return None
        expected_jkt = claims.get("dpop_jkt")
        if not isinstance(expected_jkt, str):
            return None
        try:
            await validate_dpop_request(
                raw,
                config=self.config,
                replay_store=self.replay_store,
                access_token=token,
                expected_jkt=expected_jkt,
            )
        except DPoPValidationError:
            return None
        return claims


class InMemoryDPoPReplayStore:
    """Single-process feasibility store.

    Production ASGI replicas and Workers isolates must use a shared store such
    as :class:`AdapterDPoPReplayStore`.
    """

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], datetime] = {}
        self._lock = asyncio.Lock()

    async def record(self, *, jkt: str, jti: str, expires_at: datetime) -> bool:
        now = datetime.now(UTC)
        async with self._lock:
            self._entries = {key: expiry for key, expiry in self._entries.items() if expiry > now}
            key = (jkt, jti)
            if key in self._entries:
                return False
            self._entries[key] = expires_at
            return True


class AdapterDPoPReplayStore:
    """Shared replay store backed by any hayate-auth Adapter.

    A namespaced row in the existing ``verification`` model stores a SHA-256
    jti digest. Its ``UNIQUE (identifier, value_hash)`` database constraint is
    the concurrency boundary. If an insert fails, a confirming lookup
    distinguishes a concurrent replay from an unavailable store; unavailable
    storage fails closed.
    """

    def __init__(
        self,
        adapter: Adapter,
        *,
        cleanup_interval: timedelta = timedelta(minutes=1),
    ) -> None:
        if cleanup_interval <= timedelta(0):
            raise ValueError("cleanup_interval must be greater than zero")
        self.adapter = adapter
        self.cleanup_interval = cleanup_interval
        self._next_cleanup = 0.0
        self._cleanup_lock = asyncio.Lock()

    async def record(self, *, jkt: str, jti: str, expires_at: datetime) -> bool:
        now = sessions.isoformat(sessions.now())
        monotonic_now = time.monotonic()
        if monotonic_now >= self._next_cleanup:
            async with self._cleanup_lock:
                if monotonic_now >= self._next_cleanup:
                    await self.adapter.delete("verification", [Where("expires_at", now, "lt")])
                    self._next_cleanup = monotonic_now + self.cleanup_interval.total_seconds()
        identifier = f"dpop:{jkt}"
        jti_hash = hashlib.sha256(jti.encode("utf-8")).hexdigest()
        data = {
            "id": new_id(),
            "identifier": identifier,
            "value_hash": jti_hash,
            "expires_at": sessions.isoformat(expires_at),
            "created_at": now,
        }
        try:
            await self.adapter.create("verification", data)
        except Exception:
            duplicate = await self.adapter.find_one(
                "verification",
                [Where("identifier", identifier), Where("value_hash", jti_hash)],
            )
            if duplicate is not None:
                return False
            raise
        return True


class CryptographyDPoPSignatureVerifier:
    """ES256 verification through the optional ``cryptography`` package."""

    async def verify(
        self,
        *,
        algorithm: str,
        jwk: dict[str, Any],
        signing_input: bytes,
        signature: bytes,
    ) -> bool:
        if algorithm != ES256 or len(signature) != 64:
            return False

        def verify_sync() -> bool:
            try:
                hashes = import_module("cryptography.hazmat.primitives.hashes")
                ec = import_module("cryptography.hazmat.primitives.asymmetric.ec")
                utils = import_module("cryptography.hazmat.primitives.asymmetric.utils")
                invalid_signature = import_module("cryptography.exceptions").InvalidSignature
            except ImportError:
                return False
            try:
                public_key = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(_decode_coordinate(jwk["x"])),
                    int.from_bytes(_decode_coordinate(jwk["y"])),
                    ec.SECP256R1(),
                ).public_key()
                der_signature = utils.encode_dss_signature(
                    int.from_bytes(signature[:32]),
                    int.from_bytes(signature[32:]),
                )
                public_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
            except (ValueError, invalid_signature):
                return False
            return True

        if sys.platform == "emscripten":
            return verify_sync()
        return await asyncio.to_thread(verify_sync)


class WebCryptoDPoPSignatureVerifier:
    """ES256 verification through Workers' standards-based WebCrypto."""

    async def verify(
        self,
        *,
        algorithm: str,
        jwk: dict[str, Any],
        signing_input: bytes,
        signature: bytes,
    ) -> bool:
        if algorithm != ES256 or len(signature) != 64:
            return False
        try:
            js = import_module("js")
            to_js = import_module("pyodide.ffi").to_js
            public_jwk = {
                "kty": "EC",
                "crv": "P-256",
                "x": jwk["x"],
                "y": jwk["y"],
                "ext": True,
                "key_ops": ["verify"],
            }
            key = await js.crypto.subtle.importKey(
                "jwk",
                to_js(public_jwk, dict_converter=js.Object.fromEntries),
                to_js(
                    {"name": "ECDSA", "namedCurve": "P-256"},
                    dict_converter=js.Object.fromEntries,
                ),
                False,
                to_js(["verify"]),
            )
            valid = await js.crypto.subtle.verify(
                to_js({"name": "ECDSA", "hash": "SHA-256"}, dict_converter=js.Object.fromEntries),
                key,
                to_js(signature),
                to_js(signing_input),
            )
        except Exception:
            return False
        return bool(valid)


def default_dpop_signature_verifier() -> DPoPSignatureVerifier:
    if sys.platform == "emscripten":
        return WebCryptoDPoPSignatureVerifier()
    try:
        import_module("cryptography")
    except ImportError as error:
        raise RuntimeError(
            "DPoP on CPython requires the 'dpop' extra: pip install 'hayate-auth[dpop]'"
        ) from error
    return CryptographyDPoPSignatureVerifier()


def validate_jkt(value: str) -> str:
    """Validate an RFC 7638 SHA-256 JWK thumbprint representation."""
    try:
        decoded = _b64url_decode(value)
    except ValueError:
        decoded = b""
    if len(decoded) != 32 or len(value) != 43:
        raise ValueError("dpop_jkt must be a base64url-encoded SHA-256 JWK thumbprint")
    return value


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint for the supported P-256 public JWK."""
    _validate_public_jwk(jwk)
    canonical = json.dumps(
        {"crv": "P-256", "kty": "EC", "x": jwk["x"], "y": jwk["y"]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _b64url_encode(hashlib.sha256(canonical).digest())


def access_token_hash(access_token: str) -> str:
    try:
        raw = access_token.encode("ascii")
    except UnicodeEncodeError as error:
        raise DPoPValidationError("access token must contain only ASCII characters") from error
    return _b64url_encode(hashlib.sha256(raw).digest())


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: Any) -> bytes:
    if not isinstance(value, str) or not value or _B64URL.fullmatch(value) is None:
        raise ValueError("value is not unpadded base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("value is not valid base64url") from error
    if _b64url_encode(decoded) != value:
        raise ValueError("value is not canonical base64url")
    return decoded


def _decode_coordinate(value: Any) -> bytes:
    raw = _b64url_decode(value)
    if len(raw) != 32:
        raise ValueError("P-256 coordinates must contain exactly 32 bytes")
    return raw


def _validate_public_jwk(jwk: Any) -> dict[str, Any]:
    if not isinstance(jwk, dict):
        raise ValueError("jwk must be a JSON object")
    if _PRIVATE_JWK_MEMBERS & jwk.keys():
        raise ValueError("jwk must not contain private key material")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("jwk must be an EC P-256 public key")
    _decode_coordinate(jwk.get("x"))
    _decode_coordinate(jwk.get("y"))
    return jwk


def _json_object(value: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON member {key!r}")
            result[key] = item
        return result

    try:
        document = json.loads(value, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise DPoPValidationError("DPoP proof contains invalid JSON") from error
    if not isinstance(document, dict):
        raise DPoPValidationError("DPoP proof JWT parts must be JSON objects")
    return document


def _normalize_percent_encoding(path: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(path):
        if index + 2 < len(path) and path[index] == "%":
            digits = path[index + 1 : index + 3]
            try:
                character = chr(int(digits, 16))
            except ValueError:
                output.append(path[index])
                index += 1
                continue
            output.append(character if character in _UNRESERVED else f"%{digits.upper()}")
            index += 3
            continue
        output.append(path[index])
        index += 1
    return "".join(output)


def normalize_htu(value: str) -> str:
    """RFC 9449 htu form with RFC 3986 syntax/scheme normalization."""
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as error:
        raise DPoPValidationError("htu is not an absolute HTTP(S) URI") from error
    if (
        parts.scheme.lower() not in ("https", "http")
        or not parts.hostname
        or parts.username
        or parts.password
    ):
        raise DPoPValidationError("htu is not an absolute HTTP(S) URI")
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default_port = (parts.scheme.lower() == "https" and port == 443) or (
        parts.scheme.lower() == "http" and port == 80
    )
    authority = host if port is None or default_port else f"{host}:{port}"
    path = _normalize_percent_encoding(parts.path or "/")
    return f"{parts.scheme.lower()}://{authority}{path}"


def _proof_header(request: Request) -> str | None:
    values = [value for name, value in request.headers.raw() if name.lower() == "dpop"]
    if len(values) > 1:
        raise DPoPValidationError("request must not contain more than one DPoP header")
    return values[0] if values else None


async def validate_dpop_proof(
    proof: str,
    *,
    method: str,
    url: str,
    config: DPoPConfig,
    replay_store: DPoPReplayStore,
    access_token: str | None = None,
    expected_jkt: str | None = None,
    now: float | None = None,
) -> DPoPProof:
    """Validate one RFC 9449 proof and atomically consume its ``jti``."""
    if not isinstance(proof, str) or not proof or len(proof) > 8192:
        raise DPoPValidationError("DPoP proof is absent or exceeds 8192 characters")
    parts = proof.split(".")
    if len(parts) != 3:
        raise DPoPValidationError("DPoP proof must be a compact JWS")
    try:
        header_raw, payload_raw, signature = (
            _b64url_decode(parts[0]),
            _b64url_decode(parts[1]),
            _b64url_decode(parts[2]),
        )
    except ValueError as error:
        raise DPoPValidationError("DPoP proof must use unpadded base64url") from error
    header = _json_object(header_raw)
    payload = _json_object(payload_raw)
    if header.get("typ") != "dpop+jwt":
        raise DPoPValidationError("DPoP proof typ must be 'dpop+jwt'")
    algorithm = header.get("alg")
    if algorithm not in config.algorithms:
        raise DPoPValidationError("DPoP proof uses an unsupported signing algorithm")
    try:
        jwk = _validate_public_jwk(header.get("jwk"))
        jkt = jwk_thumbprint(jwk)
    except ValueError as error:
        raise DPoPValidationError(str(error)) from error
    verifier = config.signature_verifier or default_dpop_signature_verifier()
    try:
        signature_valid = await verifier.verify(
            algorithm=algorithm,
            jwk=jwk,
            signing_input=f"{parts[0]}.{parts[1]}".encode("ascii"),
            signature=signature,
        )
    except Exception as error:
        raise DPoPValidationError("DPoP signature verification is unavailable") from error
    if not signature_valid:
        raise DPoPValidationError("DPoP proof signature is invalid")

    jti = payload.get("jti")
    htm = payload.get("htm")
    htu = payload.get("htu")
    iat = payload.get("iat")
    if not isinstance(jti, str) or not jti or len(jti) > 256:
        raise DPoPValidationError("DPoP proof jti must be a non-empty string")
    if not isinstance(htm, str) or htm != method:
        raise DPoPValidationError("DPoP proof htm does not match the request method")
    if not isinstance(htu, str) or normalize_htu(htu) != normalize_htu(url):
        raise DPoPValidationError("DPoP proof htu does not match the request URI")
    if not isinstance(iat, int) or isinstance(iat, bool):
        raise DPoPValidationError("DPoP proof iat must be an integer")
    current = time.time() if now is None else now
    max_age = config.max_age.total_seconds()
    clock_skew = config.clock_skew.total_seconds()
    if iat < current - max_age or iat > current + clock_skew:
        raise DPoPValidationError("DPoP proof iat is outside the accepted time window")

    if access_token is not None:
        ath = payload.get("ath")
        if not isinstance(ath, str) or not hmac.compare_digest(
            ath, access_token_hash(access_token)
        ):
            raise DPoPValidationError("DPoP proof ath does not match the access token")
        if expected_jkt is None or not hmac.compare_digest(jkt, expected_jkt):
            raise DPoPValidationError("DPoP proof key does not match the token binding")
    elif expected_jkt is not None and not hmac.compare_digest(jkt, expected_jkt):
        raise DPoPValidationError("DPoP proof key does not match the authorization binding")

    expires_at = datetime.fromtimestamp(iat + max_age + clock_skew, UTC)
    try:
        recorded = await replay_store.record(jkt=jkt, jti=jti, expires_at=expires_at)
    except Exception as error:
        raise DPoPValidationError("DPoP replay storage is unavailable") from error
    if not recorded:
        raise DPoPValidationError("DPoP proof was already used")
    return DPoPProof(jkt=jkt, jti=jti, iat=iat, jwk=jwk)


async def validate_dpop_request(
    request: Request,
    *,
    config: DPoPConfig,
    replay_store: DPoPReplayStore,
    access_token: str | None = None,
    expected_jkt: str | None = None,
    required: bool = True,
) -> DPoPProof | None:
    proof = _proof_header(request)
    if proof is None:
        if required:
            raise DPoPValidationError("DPoP proof is required")
        return None
    return await validate_dpop_proof(
        proof,
        method=request.method,
        url=request.url.href,
        config=config,
        replay_store=replay_store,
        access_token=access_token,
        expected_jkt=expected_jkt,
    )
