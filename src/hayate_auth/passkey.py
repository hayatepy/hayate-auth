"""Passkeys — W3C WebAuthn Level 3 via the ``[passkey]`` extra (DESIGN §20.3).

Ceremony verification is delegated to py_webauthn (``webauthn``): COSE,
CBOR, and signature checking are exactly the "never hand-roll crypto"
territory of §8. This is the core's first optional dependency, guarded at
request time — without it the passkey routes answer 501 with the install
hint; without a ``PasskeyConfig`` they answer 404 (same pattern as AS mode).

Challenges travel in an HMAC-signed, short-lived cookie (the OAuth state /
consent machinery): stateless and bound to the browser that asked.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from hayate import Request, Response, problem

from . import session as sessions
from ._signed import sign_payload, unsign_payload
from ._uuid7 import new_id
from .adapter import Where
from .routes import _issue_session, _json_response, _read_json_object

if TYPE_CHECKING:
    from .auth import Auth

CHALLENGE_COOKIE_BASE = "hayate_auth.passkey"
CHALLENGE_TTL_SECONDS = 300


@dataclass(frozen=True)
class PasskeyConfig:
    """Relying-party identity: ``rp_id`` is the effective domain,
    ``origin`` the exact scheme://host[:port] the browser reports."""

    rp_id: str
    rp_name: str
    origin: str


def _gate(auth: Auth) -> Any | Response:
    """The [passkey] extra + config gate; returns the webauthn module."""
    if auth.passkey is None:
        return problem(404, title="Not Found")
    try:
        import webauthn
    except ImportError:
        return problem(
            501, title="Passkeys need the optional dependency: pip install hayate-auth[passkey]"
        )
    return webauthn


def _cookie_name(secure: bool) -> str:
    return f"__Host-{CHALLENGE_COOKIE_BASE}" if secure else CHALLENGE_COOKIE_BASE


def _challenge_cookie(auth: Auth, request: Request, payload: dict[str, Any]) -> str:
    from hayate.cookies import serialize_set_cookie

    secure = sessions.is_secure_request(request)
    return serialize_set_cookie(
        _cookie_name(secure),
        sign_payload(auth.secret, {**payload, "expires": int(time.time()) + CHALLENGE_TTL_SECONDS}),
        max_age=CHALLENGE_TTL_SECONDS,
        path="/",
        secure=secure,
        http_only=True,
        same_site="lax",
    )


def _read_challenge(auth: Auth, request: Request, purpose: str) -> dict[str, Any] | None:
    from hayate.cookies import parse_cookies

    cookies = parse_cookies(request.headers.get("cookie") or "")
    raw = cookies.get(_cookie_name(True)) or cookies.get(CHALLENGE_COOKIE_BASE)
    stored = unsign_payload(auth.secret, raw) if raw else None
    if (
        stored is None
        or stored.get("purpose") != purpose
        or stored.get("expires", 0) < int(time.time())
    ):
        return None
    return stored


def _clear_cookie(request: Request) -> str:
    from hayate.cookies import serialize_set_cookie

    secure = sessions.is_secure_request(request)
    return serialize_set_cookie(
        _cookie_name(secure),
        "",
        max_age=0,
        path="/",
        secure=secure,
        http_only=True,
        same_site="lax",
    )


def _public_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "credential_id": row["credential_id"],
        "device_type": row["device_type"],
        "backed_up": bool(row["backed_up"]),
        "created_at": row["created_at"],
    }


async def register_options(auth: Auth, request: Request) -> Response:
    wa = _gate(auth)
    if isinstance(wa, Response):
        return wa
    resolved = await auth.get_session(request)
    if resolved is None:
        return problem(401, title="Authentication required")
    user = resolved[0]

    from webauthn.helpers import bytes_to_base64url
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor

    existing = await auth.adapter.find_many("passkey", [Where("user_id", user["id"])])
    options = wa.generate_registration_options(
        rp_id=auth.passkey.rp_id,
        rp_name=auth.passkey.rp_name,
        user_id=user["id"].encode("ascii"),
        user_name=user["email"],
        user_display_name=user.get("name") or user["email"],
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=wa.base64url_to_bytes(row["credential_id"]))
            for row in existing
        ],
    )
    cookie = _challenge_cookie(
        auth,
        request,
        {
            "purpose": "register",
            "user_id": user["id"],
            "challenge": bytes_to_base64url(options.challenge),
        },
    )
    return _json_response(json.loads(wa.options_to_json(options)), cookies=[cookie])


async def verify_registration(auth: Auth, request: Request) -> Response:
    wa = _gate(auth)
    if isinstance(wa, Response):
        return wa
    resolved = await auth.get_session(request)
    if resolved is None:
        return problem(401, title="Authentication required")
    user = resolved[0]
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data
    stored = _read_challenge(auth, request, "register")
    if stored is None or stored.get("user_id") != user["id"]:
        return problem(400, title="No passkey registration is in progress")
    name = data.get("name")
    if name is not None and not isinstance(name, str):
        return problem(400, title="Name must be a string")

    from webauthn.helpers import bytes_to_base64url
    from webauthn.helpers.exceptions import InvalidRegistrationResponse

    try:
        verification = wa.verify_registration_response(
            credential=data.get("response"),
            expected_challenge=wa.base64url_to_bytes(stored["challenge"]),
            expected_origin=auth.passkey.origin,
            expected_rp_id=auth.passkey.rp_id,
        )
    except InvalidRegistrationResponse as exc:
        return problem(400, title=f"Passkey registration failed: {exc}")

    credential_id = bytes_to_base64url(verification.credential_id)
    if await auth.adapter.find_one("passkey", [Where("credential_id", credential_id)]):
        return problem(422, title="This passkey is already registered")

    row = {
        "id": new_id(),
        "user_id": user["id"],
        "name": name,
        "credential_id": credential_id,
        "public_key": bytes_to_base64url(verification.credential_public_key),
        "counter": verification.sign_count,
        "device_type": verification.credential_device_type.value,
        "backed_up": 1 if verification.credential_backed_up else 0,
        "transports": None,
        "created_at": sessions.isoformat(sessions.now()),
    }
    await auth.adapter.create("passkey", row)
    return _json_response(
        {"passkey": _public_row(row)}, status=201, cookies=[_clear_cookie(request)]
    )


async def authenticate_options(auth: Auth, request: Request) -> Response:
    wa = _gate(auth)
    if isinstance(wa, Response):
        return wa
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data

    from webauthn.helpers import bytes_to_base64url
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor

    allow: list[Any] = []
    email = data.get("email")
    if isinstance(email, str) and email:
        from .password import normalize_email

        user_row = await auth.adapter.find_one("user", [Where("email", normalize_email(email))])
        if user_row is not None:
            rows = await auth.adapter.find_many("passkey", [Where("user_id", user_row["id"])])
            allow = [
                PublicKeyCredentialDescriptor(id=wa.base64url_to_bytes(row["credential_id"]))
                for row in rows
            ]
        # An unknown email still gets ordinary-looking options (enumeration
        # defense §9): an empty allow list means discoverable credentials.

    options = wa.generate_authentication_options(
        rp_id=auth.passkey.rp_id, allow_credentials=allow or None
    )
    cookie = _challenge_cookie(
        auth,
        request,
        {"purpose": "authenticate", "challenge": bytes_to_base64url(options.challenge)},
    )
    return _json_response(json.loads(wa.options_to_json(options)), cookies=[cookie])


async def verify_authentication(auth: Auth, request: Request) -> Response:
    wa = _gate(auth)
    if isinstance(wa, Response):
        return wa
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data
    stored = _read_challenge(auth, request, "authenticate")
    if stored is None:
        return problem(400, title="No passkey sign-in is in progress")

    credential = data.get("response")
    if not isinstance(credential, dict) or not isinstance(credential.get("id"), str):
        return problem(400, title="response must be a WebAuthn credential")
    row = await auth.adapter.find_one("passkey", [Where("credential_id", credential["id"])])
    if row is None:
        return problem(401, title="Unknown passkey")

    from webauthn.helpers.exceptions import InvalidAuthenticationResponse

    try:
        verification = wa.verify_authentication_response(
            credential=credential,
            expected_challenge=wa.base64url_to_bytes(stored["challenge"]),
            expected_origin=auth.passkey.origin,
            expected_rp_id=auth.passkey.rp_id,
            credential_public_key=wa.base64url_to_bytes(row["public_key"]),
            credential_current_sign_count=row["counter"],
        )
    except InvalidAuthenticationResponse as exc:
        return problem(401, title=f"Passkey sign-in failed: {exc}")

    await auth.adapter.update(
        "passkey", [Where("id", row["id"])], {"counter": verification.new_sign_count}
    )
    user_row = await auth.adapter.find_one("user", [Where("id", row["user_id"])])
    if user_row is None:
        return problem(500, title="Passkey exists without a user")
    response = await _issue_session(auth, request, user_row)
    response.headers.append("set-cookie", _clear_cookie(request))
    return response


async def list_user_passkeys(auth: Auth, request: Request) -> Response:
    wa = _gate(auth)
    if isinstance(wa, Response):
        return wa
    resolved = await auth.get_session(request)
    if resolved is None:
        return problem(401, title="Authentication required")
    rows = await auth.adapter.find_many(
        "passkey", [Where("user_id", resolved[0]["id"])], sort=("created_at", "desc")
    )
    return _json_response({"passkeys": [_public_row(row) for row in rows]})


async def delete_passkey(auth: Auth, request: Request) -> Response:
    wa = _gate(auth)
    if isinstance(wa, Response):
        return wa
    resolved = await auth.get_session(request)
    if resolved is None:
        return problem(401, title="Authentication required")
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data
    passkey_id = data.get("id")
    if not isinstance(passkey_id, str):
        return problem(400, title="id is required")
    removed = await auth.adapter.delete(
        "passkey", [Where("id", passkey_id), Where("user_id", resolved[0]["id"])]
    )
    if not removed:
        return problem(404, title="Passkey not found")
    return _json_response({"success": True})
