"""OAuth 2.1 authorization-code + PKCE (DESIGN §7 v0.2, standards §2).

Normative: OAuth 2.1 draft (PKCE REQUIRED, S256), RFC 7636, RFC 9700.
OIDC id_tokens are accepted without local signature verification per
OIDC Core §3.1.3.7 — the token arrives over TLS directly from the Token
Endpoint we chose, so TLS server authentication stands in for JWS
(DESIGN §17-2; JWKS verification stays a future ``[oidc]`` extra).

State + PKCE verifier travel in an HMAC-signed, short-lived, HttpOnly
cookie instead of a database row: stateless, replay-bound to the browser
that started the flow, and immune to Workers isolate recycling.

HTTP goes through hayate-fetch's backend protocol, so tests inject a fake
and never touch the network.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

from hayate import Request, Response, problem

from . import session as sessions
from ._uuid7 import new_id
from .adapter import Where
from .password import normalize_email
from .routes import _json_response, public_user

if TYPE_CHECKING:
    from .auth import Auth

STATE_COOKIE_BASE = "hayate_auth.oauth"
STATE_TTL_SECONDS = 600


@dataclass(frozen=True)
class OAuthProvider:
    id: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    scopes: str
    userinfo_url: str | None = None
    uses_id_token: bool = False


def google(*, client_id: str, client_secret: str) -> OAuthProvider:
    return OAuthProvider(
        id="google",
        client_id=client_id,
        client_secret=client_secret,
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        scopes="openid email profile",
        uses_id_token=True,
    )


def github(*, client_id: str, client_secret: str) -> OAuthProvider:
    return OAuthProvider(
        id="github",
        client_id=client_id,
        client_secret=client_secret,
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        scopes="read:user user:email",
        userinfo_url="https://api.github.com/user",
    )


def _state_cookie_name(secure: bool) -> str:
    return f"__Host-{STATE_COOKIE_BASE}" if secure else STATE_COOKIE_BASE


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


async def sign_in_social(auth: Auth, request: Request) -> Response:
    """POST /sign-in/social {provider, callback_url?} -> {url} + state cookie."""
    from hayate.cookies import serialize_set_cookie

    from ._signed import sign_payload
    from .routes import _read_json_object

    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data
    provider = auth.providers.get(data.get("provider"))
    if provider is None:
        return problem(400, title="Unknown provider")

    callback_url = data.get("callback_url", "/")
    if not isinstance(callback_url, str) or not _redirect_allowed(auth, request, callback_url):
        return problem(400, title="callback_url is not a trusted origin")

    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    redirect_uri = f"{request.url.origin}{auth.base_path}/callback/{provider.id}"
    authorize = (
        provider.authorize_url
        + "?"
        + urlencode(
            {
                "response_type": "code",
                "client_id": provider.client_id,
                "redirect_uri": redirect_uri,
                "scope": provider.scopes,
                "state": state,
                "code_challenge": _code_challenge(verifier),
                "code_challenge_method": "S256",
            }
        )
    )

    secure = sessions.is_secure_request(request)
    cookie = serialize_set_cookie(
        _state_cookie_name(secure),
        sign_payload(
            auth.secret,
            {
                "state": state,
                "verifier": verifier,
                "provider": provider.id,
                "callback_url": callback_url,
                "redirect_uri": redirect_uri,
                "expires": int(time.time()) + STATE_TTL_SECONDS,
            },
        ),
        max_age=STATE_TTL_SECONDS,
        path="/",
        secure=secure,
        http_only=True,
        same_site="lax",
    )
    return _json_response({"url": authorize}, cookies=[cookie])


async def oauth_callback(auth: Auth, request: Request, provider_id: str) -> Response:
    """GET /callback/:provider — verify state, exchange the code, sign in."""
    from hayate.cookies import parse_cookies, serialize_set_cookie

    from ._signed import unsign_payload

    provider = auth.providers.get(provider_id)
    if provider is None:
        return problem(404, title="Unknown provider")

    header = request.headers.get("cookie") or ""
    cookies = parse_cookies(header)
    secure = sessions.is_secure_request(request)
    raw_state = cookies.get(_state_cookie_name(secure)) or cookies.get(STATE_COOKIE_BASE)
    stored = unsign_payload(auth.secret, raw_state) if raw_state else None
    if (
        stored is None
        or stored.get("provider") != provider_id
        or stored.get("expires", 0) < int(time.time())
        or not secrets.compare_digest(
            str(stored.get("state", "")), request.url.search_params.get("state") or ""
        )
    ):
        return problem(400, title="Invalid or expired OAuth state")

    code = request.url.search_params.get("code")
    if not code:
        return problem(400, title="Missing authorization code")

    identity = await _exchange(auth, provider, code, stored)
    if identity is None:
        return problem(502, title="Token exchange with the provider failed")

    user_row = await _resolve_user(auth, provider, identity)
    if isinstance(user_row, Response):
        return user_row

    token, _ = await sessions.create_session(
        auth.adapter,
        user_row["id"],
        ttl=auth.session_ttl,
        user_agent=request.headers.get("user-agent"),
    )
    session_cookie = sessions.session_cookie(
        token, secure=secure, max_age=int(auth.session_ttl.total_seconds())
    )
    clear_state = serialize_set_cookie(
        _state_cookie_name(secure),
        "",
        max_age=0,
        path="/",
        secure=secure,
        http_only=True,
        same_site="lax",
    )
    headers = [
        ("location", stored["callback_url"]),
        ("set-cookie", session_cookie),
        ("set-cookie", clear_state),
    ]
    return Response(None, status=302, headers=headers)


async def _exchange(
    auth: Auth, provider: OAuthProvider, code: str, stored: dict[str, Any]
) -> dict[str, Any] | None:
    """Code -> tokens -> a normalized identity dict, or None on failure."""
    fetch = import_module("hayate_fetch").fetch

    token_response = await fetch(
        provider.token_url,
        method="POST",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        },
        body=urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": stored["redirect_uri"],
                "client_id": provider.client_id,
                "client_secret": provider.client_secret,
                "code_verifier": stored["verifier"],
            }
        ),
        backend=auth.http_backend,
    )
    if token_response.status != 200:
        return None
    tokens = await token_response.json()

    if provider.uses_id_token:
        claims = _decode_jwt_claims(tokens.get("id_token", ""))
        if claims is None or not claims.get("sub"):
            return None
        return {
            "subject": str(claims["sub"]),
            "email": claims.get("email"),
            "email_verified": bool(claims.get("email_verified")),
            "name": claims.get("name"),
            "image": claims.get("picture"),
            "access_token": tokens.get("access_token"),
            "refresh_token": tokens.get("refresh_token"),
        }

    userinfo_response = await fetch(
        provider.userinfo_url,
        headers={
            "authorization": f"Bearer {tokens.get('access_token', '')}",
            "accept": "application/json",
            "user-agent": "hayate-auth",
        },
        backend=auth.http_backend,
    )
    if userinfo_response.status != 200:
        return None
    info = await userinfo_response.json()
    if not info.get("id"):
        return None
    return {
        "subject": str(info["id"]),
        "email": info.get("email"),
        # GitHub's /user email is unverified data; without the extra
        # /user/emails call we treat it as unverified (no auto-linking).
        "email_verified": False,
        "name": info.get("name") or info.get("login"),
        "image": info.get("avatar_url"),
        "access_token": tokens.get("access_token"),
        "refresh_token": tokens.get("refresh_token"),
    }


async def _resolve_user(
    auth: Auth, provider: OAuthProvider, identity: dict[str, Any]
) -> dict[str, Any] | Response:
    """Find or create the user for a provider identity.

    Auto-linking to an existing user happens only when the provider asserts
    the email as verified (account-takeover defense, DESIGN §9)."""
    account = await auth.adapter.find_one(
        "account",
        [Where("provider_id", provider.id), Where("account_id", identity["subject"])],
    )
    if account is not None:
        user_row = await auth.adapter.find_one("user", [Where("id", account["user_id"])])
        if user_row is None:
            return problem(500, title="Account exists without a user")
        return user_row

    email = normalize_email(identity["email"]) if identity.get("email") else None
    user_row = None
    if email is not None:
        existing = await auth.adapter.find_one("user", [Where("email", email)])
        if existing is not None:
            if not identity["email_verified"]:
                return problem(422, title="An account with this email already exists")
            user_row = existing

    stamp = sessions.isoformat(sessions.now())
    if user_row is None:
        user_row = {
            "id": new_id(),
            "email": email or f"{provider.id}:{identity['subject']}@users.noreply.invalid",
            "email_verified": 1 if identity["email_verified"] else 0,
            "name": identity.get("name"),
            "image": identity.get("image"),
            "created_at": stamp,
            "updated_at": stamp,
        }
        await auth.adapter.create("user", user_row)

    await auth.adapter.create(
        "account",
        {
            "id": new_id(),
            "user_id": user_row["id"],
            "provider_id": provider.id,
            "account_id": identity["subject"],
            "password_hash": None,
            "access_token": identity.get("access_token"),
            "refresh_token": identity.get("refresh_token"),
            "expires_at": None,
            "created_at": stamp,
            "updated_at": stamp,
        },
    )
    return user_row


def _decode_jwt_claims(token: str) -> dict[str, Any] | None:
    """Claims of a JWT accepted over TLS (OIDC Core §3.1.3.7; no JWS check)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        claims = json.loads(payload)
    except (ValueError, TypeError):
        return None
    return claims if isinstance(claims, dict) else None


def _redirect_allowed(auth: Auth, request: Request, callback_url: str) -> bool:
    """Open-redirect defense (§9): relative paths or trusted origins only."""
    if callback_url.startswith("/") and not callback_url.startswith("//"):
        return True
    origin = request.url.origin
    return callback_url.startswith(origin + "/") or any(
        callback_url == trusted or callback_url.startswith(trusted + "/")
        for trusted in auth.trusted_origins
    )


def public_identity(user_row: dict[str, Any]) -> dict[str, Any]:
    return public_user(user_row)
