"""TOTP two-factor endpoints and the two-step sign-in (DESIGN §7, v0.4).

Enrollment is authenticated (a live session enables/verifies/disables the
secret). Sign-in becomes two-step when 2FA is on: the password check returns
a short-lived HMAC-signed challenge cookie instead of a session, and a
second call with a valid TOTP code exchanges it for the session — so a
stolen password alone never yields a session.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from hayate import Request, Response, problem

from . import session as sessions
from . import totp
from ._uuid7 import new_id
from .adapter import Where
from .routes import _issue_session, _json_response, _read_json_object

if TYPE_CHECKING:
    from .auth import Auth

CHALLENGE_COOKIE_BASE = "hayate_auth.2fa"
CHALLENGE_TTL_SECONDS = 300


def _challenge_cookie_name(secure: bool) -> str:
    return f"__Host-{CHALLENGE_COOKIE_BASE}" if secure else CHALLENGE_COOKIE_BASE


async def _require_user(auth: Auth, request: Request) -> dict[str, Any] | Response:
    resolved = await auth.get_session(request)
    if resolved is None:
        return problem(401, title="Authentication required")
    return resolved[0]


async def enable(auth: Auth, request: Request) -> Response:
    """Start enrollment: mint a secret, store it disabled, return the URI."""
    user = await _require_user(auth, request)
    if isinstance(user, Response):
        return user

    existing = await auth.adapter.find_one("two_factor", [Where("user_id", user["id"])])
    if existing is not None and existing["enabled"]:
        return problem(409, title="Two-factor is already enabled")

    secret = totp.generate_secret()
    stamp = sessions.isoformat(sessions.now())
    if existing is None:
        await auth.adapter.create(
            "two_factor",
            {
                "id": new_id(),
                "user_id": user["id"],
                "secret": secret,
                "enabled": 0,
                "created_at": stamp,
                "updated_at": stamp,
            },
        )
    else:
        await auth.adapter.update(
            "two_factor", [Where("user_id", user["id"])], {"secret": secret, "updated_at": stamp}
        )

    return _json_response(
        {
            "secret": secret,
            "uri": totp.provisioning_uri(
                secret, account_name=user["email"], issuer=auth.totp_issuer
            ),
        }
    )


async def verify_enrollment(auth: Auth, request: Request) -> Response:
    """Confirm enrollment with a code; flips the row to enabled."""
    user = await _require_user(auth, request)
    if isinstance(user, Response):
        return user
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data

    row = await auth.adapter.find_one("two_factor", [Where("user_id", user["id"])])
    if row is None:
        return problem(400, title="Two-factor enrollment has not been started")
    if not totp.verify(row["secret"], str(data.get("code", ""))):
        return problem(400, title="Invalid code")

    await auth.adapter.update(
        "two_factor",
        [Where("user_id", user["id"])],
        {"enabled": 1, "updated_at": sessions.isoformat(sessions.now())},
    )
    return _json_response({"success": True})


async def disable(auth: Auth, request: Request) -> Response:
    user = await _require_user(auth, request)
    if isinstance(user, Response):
        return user
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data

    row = await auth.adapter.find_one("two_factor", [Where("user_id", user["id"])])
    if row is None or not row["enabled"]:
        return problem(400, title="Two-factor is not enabled")
    if not totp.verify(row["secret"], str(data.get("code", ""))):
        return problem(400, title="Invalid code")

    await auth.adapter.delete("two_factor", [Where("user_id", user["id"])])
    return _json_response({"success": True})


async def enabled_row(auth: Auth, user_id: str) -> dict[str, Any] | None:
    row = await auth.adapter.find_one("two_factor", [Where("user_id", user_id)])
    return row if row is not None and row["enabled"] else None


def issue_challenge(auth: Auth, request: Request, user_id: str) -> Response:
    """Password ok but 2FA required: hand back a signed challenge, no session."""
    from hayate.cookies import serialize_set_cookie

    from ._signed import sign_payload

    secure = sessions.is_secure_request(request)
    cookie = serialize_set_cookie(
        _challenge_cookie_name(secure),
        sign_payload(
            auth.secret,
            {"user_id": user_id, "expires": int(time.time()) + CHALLENGE_TTL_SECONDS},
        ),
        max_age=CHALLENGE_TTL_SECONDS,
        path="/",
        secure=secure,
        http_only=True,
        same_site="lax",
    )
    return _json_response({"two_factor_required": True}, cookies=[cookie])


async def sign_in(auth: Auth, request: Request) -> Response:
    """Second step: exchange a valid TOTP code + challenge for a session."""
    from hayate.cookies import parse_cookies

    from ._signed import unsign_payload

    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data
    code = str(data.get("code", ""))

    secure = sessions.is_secure_request(request)
    cookies = parse_cookies(request.headers.get("cookie") or "")
    raw = cookies.get(_challenge_cookie_name(secure)) or cookies.get(CHALLENGE_COOKIE_BASE)
    stored = unsign_payload(auth.secret, raw) if raw else None
    if stored is None or stored.get("expires", 0) < int(time.time()):
        return problem(400, title="Invalid or expired two-factor challenge")

    row = await enabled_row(auth, stored["user_id"])
    if row is None or not totp.verify(row["secret"], code):
        return problem(401, title="Invalid code")

    user_row = await auth.adapter.find_one("user", [Where("id", stored["user_id"])])
    if user_row is None:
        return problem(401, title="Invalid code")
    return await _issue_session(auth, request, user_row)


def public_state(row: dict[str, Any] | None) -> dict[str, Any]:
    return {"enabled": bool(row and row["enabled"])}
