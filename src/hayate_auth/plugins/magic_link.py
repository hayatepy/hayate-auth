"""Magic-link sign-in as an AuthPlugin (DESIGN §20.1).

The link carries a one-shot hashed token (the §2 "explicit non-standard
part", same verification machinery as reset/verify emails). Requesting a
link always answers ``{"success": true}`` — user enumeration gets nothing.
Landing on the link signs the user in (creating the account on first use:
reaching the inbox is the email-ownership proof, so ``email_verified=1``).
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from hayate import Request, Response, problem

from .. import session as sessions
from .._uuid7 import new_id
from ..adapter import Where
from ..oauth import _redirect_allowed
from ..password import email_error, normalize_email
from ..plugin import AuthPlugin
from ..routes import _json_response, _read_json_object
from ..verification import consume_verification, create_verification

if TYPE_CHECKING:
    from ..auth import Auth

PREFIX = "magic:"


def magic_link(*, send: Any, ttl: timedelta = timedelta(minutes=5)) -> AuthPlugin:
    """Build the plugin. ``send`` is the app-owned async callback
    ``(email, token) -> None`` — the app renders the link and delivers the
    mail, the core only mints and checks tokens (DESIGN §10)."""

    async def request_link(auth: Auth, request: Request) -> Response:
        data = await _read_json_object(request)
        if isinstance(data, Response):
            return data
        if (error := email_error(data.get("email"))) is not None:
            return problem(400, title=error)
        callback_url = data.get("callback_url", "/")
        if not isinstance(callback_url, str) or not _redirect_allowed(auth, request, callback_url):
            return problem(400, title="callback_url is not a trusted origin")
        name = data.get("name")
        if name is not None and not isinstance(name, str):
            return problem(400, title="Name must be a string")

        email = normalize_email(data["email"])
        # The identifier doubles as the token's payload: prefix + JSON.
        identifier = PREFIX + json.dumps(
            {"email": email, "callback_url": callback_url, "name": name},
            separators=(",", ":"),
            sort_keys=True,
        )
        token = await create_verification(auth.adapter, identifier, ttl=ttl)
        await send(email, token)
        return _json_response({"success": True})

    async def verify(auth: Auth, request: Request) -> Response:
        token = request.url.search_params.get("token")
        if not token:
            return problem(400, title="Token is required")
        row = await consume_verification(auth.adapter, token, prefix=PREFIX)
        if row is None:
            return problem(400, title="Invalid or expired token")
        payload = json.loads(row["identifier"].removeprefix(PREFIX))
        email = payload["email"]

        stamp = sessions.isoformat(sessions.now())
        user_row = await auth.adapter.find_one("user", [Where("email", email)])
        if user_row is None:
            user_row = {
                "id": new_id(),
                "email": email,
                "email_verified": 1,
                "name": payload.get("name"),
                "image": None,
                "created_at": stamp,
                "updated_at": stamp,
            }
            await auth.adapter.create("user", user_row)
        elif not user_row["email_verified"]:
            await auth.adapter.update(
                "user", [Where("id", user_row["id"])], {"email_verified": 1, "updated_at": stamp}
            )

        session_token, _ = await sessions.create_session(
            auth.adapter,
            user_row["id"],
            ttl=auth.session_ttl,
            user_agent=request.headers.get("user-agent"),
        )
        cookie = sessions.session_cookie(
            session_token,
            secure=sessions.is_secure_request(request),
            max_age=int(auth.session_ttl.total_seconds()),
        )
        return Response(
            None,
            status=302,
            headers=[
                ("location", payload["callback_url"]),
                ("set-cookie", cookie),
                ("cache-control", "no-store"),
            ],
        )

    return AuthPlugin(
        id="magic-link",
        routes={
            ("POST", "/sign-in/magic-link"): request_link,
            ("GET", "/magic-link/verify"): verify,
        },
    )
