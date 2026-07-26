"""RFC 9449 proof validation and replay-safety regressions."""

import asyncio
import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from hayate import Request

from hayate_auth import (
    AdapterDPoPReplayStore,
    DPoPConfig,
    DPoPRequestVerifier,
    DPoPValidationError,
    InMemoryDPoPReplayStore,
)
from hayate_auth.dpop import access_token_hash, jwk_thumbprint, validate_dpop_proof


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


@pytest.fixture
def dpop_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(numbers.x.to_bytes(32)),
        "y": b64url(numbers.y.to_bytes(32)),
    }
    return private_key, public_jwk


def make_proof(
    dpop_key,
    *,
    method: str = "POST",
    url: str = "https://mcp.example/mcp",
    jti: str = "proof-id-with-96-bits-of-entropy",
    iat: int | None = None,
    access_token: str | None = None,
    header_overrides: dict | None = None,
    payload_overrides: dict | None = None,
) -> str:
    private_key, public_jwk = dpop_key
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk}
    payload = {
        "jti": jti,
        "htm": method,
        "htu": url,
        "iat": int(time.time()) if iat is None else iat,
    }
    if access_token is not None:
        payload["ath"] = access_token_hash(access_token)
    header.update(header_overrides or {})
    payload.update(payload_overrides or {})
    encoded_header = b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    signature = r.to_bytes(32) + s.to_bytes(32)
    return f"{encoded_header}.{encoded_payload}.{b64url(signature)}"


async def test_valid_resource_proof_is_key_and_access_token_bound(dpop_key):
    token = "hat_access-token"
    proof = make_proof(
        dpop_key,
        method="POST",
        url="https://MCP.EXAMPLE:443/mcp?ignored=yes",
        access_token=token,
    )
    result = await validate_dpop_proof(
        proof,
        method="POST",
        url="https://mcp.example/mcp?different=query",
        config=DPoPConfig(),
        replay_store=InMemoryDPoPReplayStore(),
        access_token=token,
        expected_jkt=jwk_thumbprint(dpop_key[1]),
    )
    assert result.jkt == jwk_thumbprint(dpop_key[1])


async def test_proof_replay_is_rejected_even_under_concurrency(adapter, dpop_key):
    proof = make_proof(dpop_key)
    config = DPoPConfig()
    store = AdapterDPoPReplayStore(adapter)

    async def validate():
        return await validate_dpop_proof(
            proof,
            method="POST",
            url="https://mcp.example/mcp",
            config=config,
            replay_store=store,
        )

    outcomes = await asyncio.gather(validate(), validate(), return_exceptions=True)
    assert sum(not isinstance(value, Exception) for value in outcomes) == 1
    rejected = next(value for value in outcomes if isinstance(value, Exception))
    assert isinstance(rejected, DPoPValidationError)
    assert "already used" in str(rejected)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"method": "GET"}, "htm"),
        ({"url": "https://mcp.example/other"}, "htu"),
        ({"access_token": "hat_other"}, "ath"),
        ({"expected_jkt": b64url(hashlib.sha256(b"other").digest())}, "key"),
    ],
)
async def test_resource_binding_mismatches_fail_closed(dpop_key, change, message):
    token = "hat_access-token"
    proof = make_proof(dpop_key, access_token=token)
    arguments = {
        "method": "POST",
        "url": "https://mcp.example/mcp",
        "config": DPoPConfig(),
        "replay_store": InMemoryDPoPReplayStore(),
        "access_token": token,
        "expected_jkt": jwk_thumbprint(dpop_key[1]),
        **change,
    }
    with pytest.raises(DPoPValidationError, match=message):
        await validate_dpop_proof(proof, **arguments)


async def test_private_jwk_expired_iat_and_duplicate_headers_are_rejected(dpop_key):
    private_jwk = {**dpop_key[1], "d": b64url(b"\x01" * 32)}
    proof = make_proof(
        dpop_key,
        iat=int(time.time()) - 601,
        header_overrides={"jwk": private_jwk},
    )
    with pytest.raises(DPoPValidationError, match="private"):
        await validate_dpop_proof(
            proof,
            method="POST",
            url="https://mcp.example/mcp",
            config=DPoPConfig(),
            replay_store=InMemoryDPoPReplayStore(),
        )

    expired = make_proof(dpop_key, iat=int(time.time()) - 601, jti="expired-proof")
    with pytest.raises(DPoPValidationError, match="time window"):
        await validate_dpop_proof(
            expired,
            method="POST",
            url="https://mcp.example/mcp",
            config=DPoPConfig(),
            replay_store=InMemoryDPoPReplayStore(),
        )

    duplicated = Request(
        "https://mcp.example/mcp",
        method="POST",
        headers=[("DPoP", "first"), ("dpop", "second")],
    )
    verifier = DPoPRequestVerifier(
        verify_token=lambda _token: _claims(dpop_key),
        config=DPoPConfig(),
        replay_store=InMemoryDPoPReplayStore(),
    )
    assert await verifier(duplicated) is None


async def _claims(dpop_key):
    return {"subject": "user-1", "scopes": ["mcp"], "dpop_jkt": jwk_thumbprint(dpop_key[1])}


async def test_request_verifier_requires_dpop_scheme_proof_and_bound_token(dpop_key):
    token = "hat_access-token"
    proof = make_proof(dpop_key, access_token=token)
    verifier = DPoPRequestVerifier(
        verify_token=lambda _token: _claims(dpop_key),
        config=DPoPConfig(),
        replay_store=InMemoryDPoPReplayStore(),
    )
    request = Request(
        "https://mcp.example/mcp",
        method="POST",
        headers={"authorization": f"DPoP {token}", "dpop": proof},
    )
    claims = await verifier(request)
    assert claims is not None
    assert claims["subject"] == "user-1"

    bearer = Request(
        "https://mcp.example/mcp",
        method="POST",
        headers={"authorization": f"Bearer {token}", "dpop": proof},
    )
    assert await verifier(bearer) is None
