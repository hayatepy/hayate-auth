"""The v0.1 endpoint set (DESIGN §7): email sign-up/sign-in, session
introspection, sign-out. Paths mirror better-auth's API surface.

Every handler is ``(auth, request) -> Response`` over the protocols only —
no framework object in sight, which is what keeps ``Auth.fetch`` a pure
function.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from hayate import Headers, Request, Response, problem

from . import session as sessions
from ._uuid7 import new_id
from .adapter import Where
from .password import email_error, normalize_email, password_error

if TYPE_CHECKING:
    from .auth import Auth

_GENERIC_SIGNIN_FAILURE = "Invalid email or password"


def _json_response(data: Any, status: int = 200, cookies: list[str] | None = None) -> Response:
    headers = Headers({"content-type": "application/json"})
    for cookie in cookies or ():
        headers.append("set-cookie", cookie)
    return Response(json.dumps(data, separators=(",", ":")), status=status, headers=headers)


async def _read_json_object(request: Request) -> dict[str, Any] | Response:
    try:
        data = await request.json()
    except Exception:
        return problem(400, title="Request body must be JSON")
    if not isinstance(data, dict):
        return problem(400, title="Request body must be a JSON object")
    return data


def public_user(row: dict[str, Any]) -> dict[str, Any]:
    user = dict(row)
    user["email_verified"] = bool(user.get("email_verified"))
    return user


async def _issue_session(auth: Auth, request: Request, user_row: dict[str, Any]) -> Response:
    token, _ = await sessions.create_session(
        auth.adapter,
        user_row["id"],
        ttl=auth.session_ttl,
        user_agent=request.headers.get("user-agent"),
    )
    cookie = sessions.session_cookie(
        token,
        secure=sessions.is_secure_request(request),
        max_age=int(auth.session_ttl.total_seconds()),
    )
    return _json_response({"user": public_user(user_row)}, cookies=[cookie])


async def sign_up_email(auth: Auth, request: Request) -> Response:
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data

    if (error := email_error(data.get("email"))) is not None:
        return problem(400, title=error)
    if (error := password_error(data.get("password"))) is not None:
        return problem(400, title=error)
    name = data.get("name")
    if name is not None and not isinstance(name, str):
        return problem(400, title="Name must be a string")

    email = normalize_email(data["email"])
    if await auth.adapter.find_one("user", [Where("email", email)]) is not None:
        return problem(422, title="User already exists")

    stamp = sessions.isoformat(sessions.now())
    user_row = {
        "id": new_id(),
        "email": email,
        "email_verified": 0,
        "name": name,
        "image": None,
        "created_at": stamp,
        "updated_at": stamp,
    }
    await auth.adapter.create("user", user_row)
    await auth.adapter.create(
        "account",
        {
            "id": new_id(),
            "user_id": user_row["id"],
            "provider_id": "credential",
            "account_id": user_row["id"],
            "password_hash": await auth.crypto.hash_password(data["password"]),
            "access_token": None,
            "refresh_token": None,
            "expires_at": None,
            "created_at": stamp,
            "updated_at": stamp,
        },
    )
    if auth.send_verification_email is not None:
        from .verification import create_verification

        token = await create_verification(
            auth.adapter, f"verify:{user_row['id']}", ttl=auth.verification_ttl
        )
        await auth.send_verification_email(public_user(user_row), token)
    return await _issue_session(auth, request, user_row)


async def sign_in_email(auth: Auth, request: Request) -> Response:
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data
    email = data.get("email")
    password = data.get("password")
    if not isinstance(email, str) or not isinstance(password, str):
        return problem(400, title="Email and password are required")

    user_row = await auth.adapter.find_one("user", [Where("email", normalize_email(email))])
    account = None
    if user_row is not None:
        account = await auth.adapter.find_one(
            "account",
            [Where("user_id", user_row["id"]), Where("provider_id", "credential")],
        )

    stored = account["password_hash"] if account else None
    if user_row is None or stored is None:
        # Equalize timing against user enumeration (DESIGN §9): burn the
        # same KDF work a real verification would.
        await auth.crypto.verify_password(password, await auth._dummy_hash())
        return problem(401, title=_GENERIC_SIGNIN_FAILURE)

    if not await auth.crypto.verify_password(password, stored):
        return problem(401, title=_GENERIC_SIGNIN_FAILURE)

    return await _issue_session(auth, request, user_row)


async def sign_out(auth: Auth, request: Request) -> Response:
    await sessions.revoke_session(auth.adapter, request)
    cookie = sessions.clear_cookie(secure=sessions.is_secure_request(request))
    return _json_response({"success": True}, cookies=[cookie])


async def forget_password(auth: Auth, request: Request) -> Response:
    """Start a reset. The response never reveals whether the email exists."""
    from .verification import create_verification

    if auth.send_reset_password is None:
        return problem(501, title="Password reset is not configured")
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data
    email = data.get("email")
    if not isinstance(email, str):
        return problem(400, title="Email is required")

    user_row = await auth.adapter.find_one("user", [Where("email", normalize_email(email))])
    if user_row is not None:
        token = await create_verification(
            auth.adapter, f"reset:{user_row['id']}", ttl=auth.verification_ttl
        )
        await auth.send_reset_password(public_user(user_row), token)
    return _json_response({"success": True})


async def reset_password(auth: Auth, request: Request) -> Response:
    from .verification import consume_verification

    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data
    token = data.get("token")
    if not isinstance(token, str) or not token:
        return problem(400, title="Token is required")
    if (error := password_error(data.get("password"))) is not None:
        return problem(400, title=error)

    row = await consume_verification(auth.adapter, token, prefix="reset:")
    if row is None:
        return problem(400, title="Invalid or expired token")
    user_id = row["identifier"].removeprefix("reset:")

    await auth.adapter.update(
        "account",
        [Where("user_id", user_id), Where("provider_id", "credential")],
        {
            "password_hash": await auth.crypto.hash_password(data["password"]),
            "updated_at": sessions.isoformat(sessions.now()),
        },
    )
    # A reset invalidates every existing session for the user (ASVS V7).
    await auth.adapter.delete("session", [Where("user_id", user_id)])
    return _json_response({"success": True})


async def verify_email(auth: Auth, request: Request) -> Response:
    from .verification import consume_verification

    token = request.url.search_params.get("token")
    if not token:
        return problem(400, title="Token is required")
    row = await consume_verification(auth.adapter, token, prefix="verify:")
    if row is None:
        return problem(400, title="Invalid or expired token")
    user_id = row["identifier"].removeprefix("verify:")
    await auth.adapter.update(
        "user",
        [Where("id", user_id)],
        {"email_verified": 1, "updated_at": sessions.isoformat(sessions.now())},
    )
    return _json_response({"success": True})


async def get_session(auth: Auth, request: Request) -> Response:
    resolved = await auth.get_session(request)
    if resolved is None:
        return _json_response({"session": None, "user": None})
    user, record = resolved
    return _json_response({"session": record, "user": user})


ROUTES = {
    ("POST", "/sign-up/email"): sign_up_email,
    ("POST", "/sign-in/email"): sign_in_email,
    ("POST", "/sign-out"): sign_out,
    ("GET", "/get-session"): get_session,
    ("POST", "/forget-password"): forget_password,
    ("POST", "/reset-password"): reset_password,
    ("GET", "/verify-email"): verify_email,
}
