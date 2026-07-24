"""Small standards-shaped WebAuthn authenticator used by the test suite.

It implements the two browser ceremony responses exercised by hayate-auth:
none-attestation registration and ES256 authentication.  Keeping this
fixture local avoids pinning production cryptography to the abandoned
``soft-webauthn`` dependency.
"""

from __future__ import annotations

import json
import os
from base64 import urlsafe_b64encode
from hashlib import sha256
from struct import pack
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def _base64url(value: bytes) -> str:
    return urlsafe_b64encode(value).decode("ascii").rstrip("=")


class VirtualWebAuthnDevice:
    """One-credential ES256 authenticator with a monotonically increasing counter."""

    def __init__(self) -> None:
        self.credential_id: bytes | None = None
        self.private_key: ec.EllipticCurvePrivateKey | None = None
        self.rp_id: str | None = None
        self.user_handle: bytes | None = None
        self.sign_count = 0

    def create(self, options: dict[str, Any], origin: str) -> dict[str, Any]:
        public_key = options["publicKey"]
        if {"alg": -7, "type": "public-key"} not in public_key["pubKeyCredParams"]:
            raise ValueError("ES256 was not offered")
        if public_key.get("attestation") not in (None, "none"):
            raise ValueError("only none attestation is supported")

        self.credential_id = os.urandom(32)
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.rp_id = public_key["rp"]["id"]
        self.user_handle = public_key["user"]["id"]

        client_data = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": _base64url(public_key["challenge"]),
                "origin": origin,
            },
            separators=(",", ":"),
        ).encode()
        numbers = self.private_key.public_key().public_numbers()
        cose_key = cbor2.dumps(
            {
                1: 2,  # kty: EC2
                3: -7,  # alg: ES256
                -1: 1,  # crv: P-256
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )
        authenticator_data = (
            sha256(self.rp_id.encode("ascii")).digest()
            + b"\x41"  # user present + attested credential data
            + pack(">I", self.sign_count)
            + bytes(16)  # zero AAGUID for a test authenticator
            + pack(">H", len(self.credential_id))
            + self.credential_id
            + cose_key
        )
        return {
            "id": urlsafe_b64encode(self.credential_id),
            "rawId": self.credential_id,
            "response": {
                "clientDataJSON": client_data,
                "attestationObject": cbor2.dumps(
                    {"authData": authenticator_data, "fmt": "none", "attStmt": {}}
                ),
            },
            "type": "public-key",
        }

    def get(self, options: dict[str, Any], origin: str) -> dict[str, Any]:
        public_key = options["publicKey"]
        if self.rp_id is None or self.rp_id != public_key["rpId"]:
            raise ValueError("requested rpId does not match the credential")
        if self.private_key is None or self.credential_id is None:
            raise ValueError("the device has no credential")

        self.sign_count += 1
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": _base64url(public_key["challenge"]),
                "origin": origin,
            },
            separators=(",", ":"),
        ).encode()
        authenticator_data = (
            sha256(self.rp_id.encode("ascii")).digest()
            + b"\x01"  # user present
            + pack(">I", self.sign_count)
        )
        signature = self.private_key.sign(
            authenticator_data + sha256(client_data).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        return {
            "id": urlsafe_b64encode(self.credential_id),
            "rawId": self.credential_id,
            "response": {
                "authenticatorData": authenticator_data,
                "clientDataJSON": client_data,
                "signature": signature,
                "userHandle": self.user_handle,
            },
            "type": "public-key",
        }
