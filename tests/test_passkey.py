"""Passkeys (DESIGN §20.3): real WebAuthn ceremonies via soft-webauthn.

soft-webauthn plays the authenticator (navigator.credentials.create/get),
so py_webauthn's actual verification path runs — origin binding, challenge
matching, and sign-counter regression are exercised for real, not mocked.
"""

import pytest
from hayate import Request
from soft_webauthn import SoftWebauthnDevice
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from conftest import cookie_pair, request_json
from hayate_auth import Auth, PasskeyConfig, ScryptBackend

BASE = "/api/auth"
ORIGIN = "http://localhost"


@pytest.fixture
def auth_pk(adapter):
    return Auth(
        secret="test-secret",
        adapter=adapter,
        crypto=ScryptBackend(log_n=12),
        passkey=PasskeyConfig(rp_id="localhost", rp_name="Test", origin=ORIGIN),
    )


def to_device_options(options: dict) -> dict:
    """py_webauthn JSON options -> the browser-shaped dict soft-webauthn eats."""
    public_key = dict(options)
    public_key["challenge"] = base64url_to_bytes(public_key["challenge"])
    if "user" in public_key:
        public_key["user"] = {
            **public_key["user"],
            "id": base64url_to_bytes(public_key["user"]["id"]),
        }
    return {"publicKey": public_key}


def to_json_credential(credential: dict) -> dict:
    """soft-webauthn bytes fields -> the base64url JSON shape py_webauthn parses."""
    response = {
        key: bytes_to_base64url(value)
        for key, value in credential["response"].items()
        if value is not None
    }
    return {
        # soft-webauthn leaves id as padded bytes; normalize to the unpadded
        # base64url string a browser would send.
        "id": bytes_to_base64url(credential["rawId"]),
        "rawId": bytes_to_base64url(credential["rawId"]),
        "type": credential["type"],
        "response": response,
    }


async def signed_in_cookie(auth, email="pk@example.com") -> str:
    res = await auth.fetch(
        request_json(f"{BASE}/sign-up/email", {"email": email, "password": "long enough"})
    )
    assert res.status == 200
    return cookie_pair(res)


async def register_passkey(auth, cookie, device=None, *, origin=ORIGIN):
    device = device or SoftWebauthnDevice()
    options_res = await auth.fetch(
        request_json(f"{BASE}/passkey/generate-register-options", {}, cookie=cookie)
    )
    assert options_res.status == 200, await options_res.text()
    challenge_cookie = cookie_pair(options_res)
    options = await options_res.json()

    attestation = device.create(to_device_options(options), origin)
    verify_res = await auth.fetch(
        request_json(
            f"{BASE}/passkey/verify-registration",
            {"response": to_json_credential(attestation), "name": "test key"},
            cookie=f"{cookie}; {challenge_cookie}",
        )
    )
    return device, verify_res


async def authenticate(auth, device, *, email=None, origin=ORIGIN):
    body = {"email": email} if email else {}
    options_res = await auth.fetch(
        request_json(f"{BASE}/passkey/generate-authenticate-options", body)
    )
    assert options_res.status == 200
    challenge_cookie = cookie_pair(options_res)
    options = await options_res.json()

    assertion = device.get(to_device_options(options), origin)
    return await auth.fetch(
        request_json(
            f"{BASE}/passkey/verify-authentication",
            {"response": to_json_credential(assertion)},
            cookie=challenge_cookie,
        )
    )


async def test_register_and_list(auth_pk):
    cookie = await signed_in_cookie(auth_pk)
    _device, res = await register_passkey(auth_pk, cookie)
    assert res.status == 201, await res.text()
    body = await res.json()
    assert body["passkey"]["name"] == "test key"

    listing = await auth_pk.fetch(
        request_json(f"{BASE}/passkey/list-user-passkeys", None, method="GET", cookie=cookie)
    )
    keys = (await listing.json())["passkeys"]
    assert len(keys) == 1


async def test_passkey_sign_in_issues_a_session(auth_pk):
    cookie = await signed_in_cookie(auth_pk)
    device, res = await register_passkey(auth_pk, cookie)
    assert res.status == 201

    signin = await authenticate(auth_pk, device, email="pk@example.com")
    assert signin.status == 200, await signin.text()
    session_cookie = cookie_pair(signin)
    session = await auth_pk.fetch(
        Request(f"http://localhost{BASE}/get-session", headers={"cookie": session_cookie})
    )
    assert (await session.json())["user"]["email"] == "pk@example.com"


async def test_wrong_origin_is_rejected(auth_pk):
    cookie = await signed_in_cookie(auth_pk)
    device, res = await register_passkey(auth_pk, cookie)
    assert res.status == 201
    hijack = await authenticate(auth_pk, device, origin="https://evil.example")
    assert hijack.status == 401


async def test_sign_counter_rollback_is_rejected(auth_pk):
    """A cloned authenticator replays an old counter: sign-in must fail."""
    from hayate_auth.adapter import Where

    cookie = await signed_in_cookie(auth_pk)
    device, res = await register_passkey(auth_pk, cookie)
    assert res.status == 201

    first = await authenticate(auth_pk, device, email="pk@example.com")
    assert first.status == 200

    # Pretend the server has seen a much later counter (the real device
    # moved on); this device's next assertion is now a rollback.
    row = (await auth_pk.adapter.find_many("passkey", []))[0]
    await auth_pk.adapter.update("passkey", [Where("id", row["id"])], {"counter": 1000})
    rollback = await authenticate(auth_pk, device, email="pk@example.com")
    assert rollback.status == 401


async def test_registration_needs_session_and_challenge(auth_pk):
    anonymous = await auth_pk.fetch(request_json(f"{BASE}/passkey/generate-register-options", {}))
    assert anonymous.status == 401

    cookie = await signed_in_cookie(auth_pk)
    no_challenge = await auth_pk.fetch(
        request_json(
            f"{BASE}/passkey/verify-registration",
            {"response": {"id": "x", "rawId": "x", "type": "public-key", "response": {}}},
            cookie=cookie,
        )
    )
    assert no_challenge.status == 400


async def test_replayed_attestation_cannot_register_twice(auth_pk):
    """A stolen registration response replayed while the challenge cookie is
    still fresh must hit the duplicate-credential guard, not create a row."""
    cookie = await signed_in_cookie(auth_pk)
    device = SoftWebauthnDevice()
    options_res = await auth_pk.fetch(
        request_json(f"{BASE}/passkey/generate-register-options", {}, cookie=cookie)
    )
    challenge_cookie = cookie_pair(options_res)
    options = await options_res.json()
    attestation = to_json_credential(device.create(to_device_options(options), ORIGIN))

    first = await auth_pk.fetch(
        request_json(
            f"{BASE}/passkey/verify-registration",
            {"response": attestation},
            cookie=f"{cookie}; {challenge_cookie}",
        )
    )
    assert first.status == 201

    replay = await auth_pk.fetch(
        request_json(
            f"{BASE}/passkey/verify-registration",
            {"response": attestation},
            cookie=f"{cookie}; {challenge_cookie}",
        )
    )
    assert replay.status == 422
    rows = await auth_pk.adapter.find_many("passkey", [])
    assert len(rows) == 1


async def test_delete_is_owner_scoped(auth_pk):
    cookie = await signed_in_cookie(auth_pk)
    _device, res = await register_passkey(auth_pk, cookie)
    body = await res.json()
    passkey_id = body["passkey"]["id"]

    other = await signed_in_cookie(auth_pk, email="other@example.com")
    steal = await auth_pk.fetch(
        request_json(f"{BASE}/passkey/delete-passkey", {"id": passkey_id}, cookie=other)
    )
    assert steal.status == 404

    own = await auth_pk.fetch(
        request_json(f"{BASE}/passkey/delete-passkey", {"id": passkey_id}, cookie=cookie)
    )
    assert own.status == 200


async def test_unknown_email_still_gets_options(auth_pk):
    res = await auth_pk.fetch(
        request_json(f"{BASE}/passkey/generate-authenticate-options", {"email": "ghost@x.co"})
    )
    assert res.status == 200
    assert "challenge" in (await res.json())


async def test_routes_404_without_config(auth):
    res = await auth.fetch(request_json(f"{BASE}/passkey/generate-register-options", {}))
    assert res.status == 404
