"""AS mode: an OAuth 2.1 Authorization Server (DESIGN §19, v0.6).

Normative: OAuth 2.1 draft / RFC 6749, RFC 7636 (PKCE, S256 only), RFC 8414
(AS metadata), RFC 7591 (Dynamic Client Registration), RFC 8707 (Resource
Indicators), RFC 9700 (Security BCP), RFC 8252 §7.3 (loopback redirects).

This is the token-issuing half of the "MCP server + its AS in one app"
story: hayate-mcp's ``Authorization(verify_token=...)`` takes
``auth.oauth_token_verifier(resource=...)`` and the pair is complete.

Every credential this module mints (authorization codes, access and refresh
tokens, client secrets) is a ``secrets.token_urlsafe`` value stored only as
its SHA-256 — the same discipline as sessions and API keys. Access tokens
are opaque: the resource server lives in the same process, so introspection
and JWKS stay out (DESIGN §19.5).

Consent and login pages are the app's job (better-auth's shape): the
authorize endpoint 302s to ``login_url`` / ``consent_url`` and carries the
in-flight request in an HMAC-signed cookie; ``POST /oauth2/consent`` answers
with the final redirect target as JSON.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlencode, urlsplit

from hayate import Headers, Request, Response, problem

from . import session as sessions
from ._signed import sign_payload, unsign_payload
from ._uuid7 import new_id
from .adapter import Where
from .routes import _json_response, _read_json_object

if TYPE_CHECKING:
    from .auth import Auth

WELL_KNOWN_PATH = "/.well-known/oauth-authorization-server"
ACCESS_PREFIX = "hat_"  # hayate access token
REFRESH_PREFIX = "har_"  # hayate refresh token
AS_COOKIE_BASE = "hayate_auth.authorize"
AS_COOKIE_TTL_SECONDS = 600
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
AUTH_METHODS = ("none", "client_secret_basic", "client_secret_post")
GRANT_TYPES = frozenset({"authorization_code", "refresh_token"})
FORBIDDEN_SCHEMES = frozenset({"javascript", "data", "file", "vbscript"})


@dataclass(frozen=True)
class AuthorizationServer:
    """AS-mode configuration, passed as ``Auth(authorization_server=...)``.

    ``issuer`` must be an origin with no path (documented subset, DESIGN
    §19.3): the RFC 8414 well-known document then lives at exactly
    ``{issuer}/.well-known/oauth-authorization-server``.

    ``login_url`` / ``consent_url`` are app pages: authorize redirects there
    with ``?redirect=<authorize url>`` (login) or the client/scope details
    (consent). Relative paths are resolved against the issuer.
    """

    issuer: str
    login_url: str
    consent_url: str
    scopes_supported: tuple[str, ...] = ()
    access_token_ttl: timedelta = timedelta(hours=1)
    refresh_token_ttl: timedelta = timedelta(days=30)
    code_ttl: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        parts = urlsplit(self.issuer)
        if parts.scheme not in ("https", "http") or not parts.netloc:
            raise ValueError("issuer must be an absolute http(s) origin")
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise ValueError("issuer must be an origin without path, query, or fragment")
        object.__setattr__(self, "issuer", f"{parts.scheme}://{parts.netloc}")


# -- small shared pieces ---------------------------------------------------------------


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _oauth_error(
    status: int, error: str, description: str | None = None, *, basic: bool = False
) -> Response:
    """An RFC 6749 §5.2 error body (not Problem Details: token/register
    clients parse the standard ``{"error": ...}`` shape)."""
    body: dict[str, Any] = {"error": error}
    if description is not None:
        body["error_description"] = description
    headers = Headers({"content-type": "application/json", "cache-control": "no-store"})
    if basic:
        headers.set("www-authenticate", 'Basic realm="oauth2/token"')
    return Response(json.dumps(body, separators=(",", ":")), status=status, headers=headers)


def _with_params(uri: str, **params: str | None) -> str:
    present = {key: value for key, value in params.items() if value is not None}
    separator = "&" if urlsplit(uri).query else "?"
    return uri + separator + urlencode(present)


def _redirect(target: str) -> Response:
    return Response(None, status=302, headers=[("location", target), ("cache-control", "no-store")])


def _error_redirect(
    redirect_uri: str, state: str | None, error: str, description: str | None = None
) -> Response:
    """Deliver an authorize-endpoint error to the *validated* redirect_uri
    (RFC 6749 §4.1.2.1). Never used before client_id + redirect_uri check."""
    return _redirect(
        _with_params(redirect_uri, error=error, error_description=description, state=state)
    )


def _matches_registered(uri: str, registered: list[str]) -> bool:
    """Exact match, except loopback redirects may vary the port (RFC 8252 §7.3)."""
    if uri in registered:
        return True
    parsed = urlsplit(uri)
    if parsed.scheme != "http" or parsed.hostname not in LOOPBACK_HOSTS:
        return False
    for candidate in registered:
        reg = urlsplit(candidate)
        if (
            reg.scheme == "http"
            and reg.hostname == parsed.hostname
            and reg.path == parsed.path
            and reg.query == parsed.query
        ):
            return True
    return False


def _acceptable_redirect_uri(uri: str) -> bool:
    parsed = urlsplit(uri)
    if not parsed.scheme or parsed.fragment:
        return False
    if parsed.scheme == "https":
        return True
    if parsed.scheme == "http":
        return parsed.hostname in LOOPBACK_HOSTS
    # Private-use schemes for native apps (RFC 8252 §7.1); block script schemes.
    return parsed.scheme not in FORBIDDEN_SCHEMES


def _as_cookie_name(secure: bool) -> str:
    return f"__Host-{AS_COOKIE_BASE}" if secure else AS_COOKIE_BASE


def _read_as_cookie(auth: Auth, request: Request) -> dict[str, Any] | None:
    from hayate.cookies import parse_cookies

    cookies = parse_cookies(request.headers.get("cookie") or "")
    raw = cookies.get(_as_cookie_name(True)) or cookies.get(AS_COOKIE_BASE)
    stored = unsign_payload(auth.secret, raw) if raw else None
    if stored is None or stored.get("expires", 0) < int(time.time()):
        return None
    return stored


def _clear_as_cookie(secure: bool) -> str:
    from hayate.cookies import serialize_set_cookie

    return serialize_set_cookie(
        _as_cookie_name(secure),
        "",
        max_age=0,
        path="/",
        secure=secure,
        http_only=True,
        same_site="lax",
    )


def _resolve_page(config: AuthorizationServer, page_url: str) -> str:
    return page_url if urlsplit(page_url).scheme else config.issuer + page_url


# -- RFC 8414 metadata -----------------------------------------------------------------


def metadata_document(auth: Auth) -> dict[str, Any]:
    config = auth.authorization_server
    assert config is not None
    base = config.issuer + auth.base_path
    doc: dict[str, Any] = {
        "issuer": config.issuer,
        "authorization_endpoint": f"{base}/oauth2/authorize",
        "token_endpoint": f"{base}/oauth2/token",
        "registration_endpoint": f"{base}/oauth2/register",
        "response_types_supported": ["code"],
        "grant_types_supported": sorted(GRANT_TYPES),
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": list(AUTH_METHODS),
    }
    if config.scopes_supported:
        doc["scopes_supported"] = list(config.scopes_supported)
    return doc


def well_known(auth: Auth) -> Response:
    return _json_response(metadata_document(auth))


# -- GET /oauth2/authorize -------------------------------------------------------------


async def authorize(auth: Auth, request: Request) -> Response:
    config = auth.authorization_server
    if config is None:
        return problem(404, title="Not Found")
    params = request.url.search_params

    client_id = params.get("client_id")
    client = (
        await auth.adapter.find_one("oauth_client", [Where("client_id", client_id)])
        if client_id
        else None
    )
    if client is None:
        # No validated redirect target exists: answer directly (RFC 6749 §4.1.2.1).
        return problem(400, title="Unknown client_id")
    redirect_uri = params.get("redirect_uri")
    registered = json.loads(client["redirect_uris"])
    if not redirect_uri or not _matches_registered(redirect_uri, registered):
        return problem(400, title="redirect_uri does not match a registered value")

    state = params.get("state")
    if params.get("response_type") != "code":
        return _error_redirect(redirect_uri, state, "unsupported_response_type")
    code_challenge = params.get("code_challenge")
    if not code_challenge:
        return _error_redirect(
            redirect_uri, state, "invalid_request", "code_challenge is required (PKCE)"
        )
    if (params.get("code_challenge_method") or "plain") != "S256":
        return _error_redirect(
            redirect_uri, state, "invalid_request", "code_challenge_method must be S256"
        )
    resources = params.get_all("resource")
    if len(resources) > 1:
        return _error_redirect(
            redirect_uri, state, "invalid_target", "only a single resource is supported"
        )
    resource = resources[0] if resources else None
    scope = params.get("scope") or ""
    if config.scopes_supported and any(
        item not in config.scopes_supported for item in scope.split()
    ):
        return _error_redirect(redirect_uri, state, "invalid_scope")

    resolved = await auth.get_session(request)
    if resolved is None:
        login = _resolve_page(config, config.login_url)
        return _redirect(_with_params(login, redirect=request.url.href))
    user = resolved[0]

    consent_row = await auth.adapter.find_one(
        "oauth_consent", [Where("user_id", user["id"]), Where("client_id", client["client_id"])]
    )
    if consent_row is not None and set(scope.split()) <= set((consent_row["scope"] or "").split()):
        return await _code_redirect(
            auth,
            user_id=user["id"],
            client_id=client["client_id"],
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            resource=resource,
        )

    from hayate.cookies import serialize_set_cookie

    secure = sessions.is_secure_request(request)
    pending = sign_payload(
        auth.secret,
        {
            "client_id": client["client_id"],
            "user_id": user["id"],
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "resource": resource,
            "expires": int(time.time()) + AS_COOKIE_TTL_SECONDS,
        },
    )
    cookie = serialize_set_cookie(
        _as_cookie_name(secure),
        pending,
        max_age=AS_COOKIE_TTL_SECONDS,
        path="/",
        secure=secure,
        http_only=True,
        same_site="lax",
    )
    consent = _with_params(
        _resolve_page(config, config.consent_url),
        client_id=client["client_id"],
        client_name=client["name"],
        scope=scope or None,
    )
    return Response(
        None,
        status=302,
        headers=[("location", consent), ("set-cookie", cookie), ("cache-control", "no-store")],
    )


async def _code_redirect(
    auth: Auth,
    *,
    user_id: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str | None,
    code_challenge: str,
    resource: str | None,
    cookies: list[str] | None = None,
) -> Response:
    code = await _mint_code(
        auth,
        user_id=user_id,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        code_challenge=code_challenge,
        resource=resource,
    )
    target = _with_params(redirect_uri, code=code, state=state)
    headers: list[tuple[str, str]] = [("location", target), ("cache-control", "no-store")]
    for cookie in cookies or ():
        headers.append(("set-cookie", cookie))
    return Response(None, status=302, headers=headers)


async def _mint_code(
    auth: Auth,
    *,
    user_id: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    code_challenge: str,
    resource: str | None,
) -> str:
    config = auth.authorization_server
    assert config is not None
    code = secrets.token_urlsafe(32)
    stamp = sessions.now()
    await auth.adapter.create(
        "oauth_code",
        {
            "id": new_id(),
            "code_hash": _hash(code),
            "client_id": client_id,
            "user_id": user_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "resource": resource,
            "used": 0,
            "family_id": None,
            "expires_at": sessions.isoformat(stamp + config.code_ttl),
            "created_at": sessions.isoformat(stamp),
        },
    )
    return code


# -- POST /oauth2/consent --------------------------------------------------------------


async def consent(auth: Auth, request: Request) -> Response:
    config = auth.authorization_server
    if config is None:
        return problem(404, title="Not Found")
    resolved = await auth.get_session(request)
    if resolved is None:
        return problem(401, title="Authentication required")
    user = resolved[0]
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data

    pending = _read_as_cookie(auth, request)
    if pending is None or pending.get("user_id") != user["id"]:
        return problem(400, title="No authorization request is in progress")
    secure = sessions.is_secure_request(request)
    clear = _clear_as_cookie(secure)

    if data.get("accept") is not True:
        denied = _with_params(
            pending["redirect_uri"], error="access_denied", state=pending.get("state")
        )
        return _json_response({"redirect_uri": denied}, cookies=[clear])

    scope = pending.get("scope") or ""
    stamp = sessions.isoformat(sessions.now())
    existing = await auth.adapter.find_one(
        "oauth_consent",
        [Where("user_id", user["id"]), Where("client_id", pending["client_id"])],
    )
    if existing is None:
        await auth.adapter.create(
            "oauth_consent",
            {
                "id": new_id(),
                "user_id": user["id"],
                "client_id": pending["client_id"],
                "scope": scope,
                "created_at": stamp,
                "updated_at": stamp,
            },
        )
    else:
        merged = set((existing["scope"] or "").split()) | set(scope.split())
        await auth.adapter.update(
            "oauth_consent",
            [Where("id", existing["id"])],
            {"scope": " ".join(sorted(merged)), "updated_at": stamp},
        )

    code = await _mint_code(
        auth,
        user_id=user["id"],
        client_id=pending["client_id"],
        redirect_uri=pending["redirect_uri"],
        scope=scope,
        code_challenge=pending["code_challenge"],
        resource=pending.get("resource"),
    )
    granted = _with_params(pending["redirect_uri"], code=code, state=pending.get("state"))
    return _json_response({"redirect_uri": granted}, cookies=[clear])


# -- POST /oauth2/token ----------------------------------------------------------------


async def token(auth: Auth, request: Request) -> Response:
    if auth.authorization_server is None:
        return problem(404, title="Not Found")
    try:
        form = await request.form_data()
    except Exception:
        return _oauth_error(
            400, "invalid_request", "body must be application/x-www-form-urlencoded"
        )

    client = await _authenticate_client(auth, request, form)
    if isinstance(client, Response):
        return client

    grant_type = form.get("grant_type")
    if grant_type == "authorization_code":
        return await _token_authorization_code(auth, form, client)
    if grant_type == "refresh_token":
        return await _token_refresh(auth, form, client)
    return _oauth_error(400, "unsupported_grant_type")


async def _authenticate_client(
    auth: Auth, request: Request, form: Any
) -> dict[str, Any] | Response:
    header = request.headers.get("authorization")
    if header is not None and header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(header[6:].strip()).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return _oauth_error(401, "invalid_client", basic=True)
        encoded_id, _, encoded_secret = decoded.partition(":")
        return await _check_client(
            auth, unquote(encoded_id), unquote(encoded_secret), "client_secret_basic"
        )
    client_id = form.get("client_id")
    if not isinstance(client_id, str) or not client_id:
        return _oauth_error(400, "invalid_request", "client_id is required")
    secret = form.get("client_secret")
    if isinstance(secret, str) and secret:
        return await _check_client(auth, client_id, secret, "client_secret_post")
    return await _check_client(auth, client_id, None, "none")


async def _check_client(
    auth: Auth, client_id: str, secret: str | None, method: str
) -> dict[str, Any] | Response:
    basic = method == "client_secret_basic"
    client = await auth.adapter.find_one("oauth_client", [Where("client_id", client_id)])
    if client is None or client["token_endpoint_auth_method"] != method:
        return _oauth_error(401, "invalid_client", basic=basic)
    if method == "none":
        return client
    stored = client["client_secret_hash"]
    if secret is None or stored is None or not hmac.compare_digest(stored, _hash(secret)):
        return _oauth_error(401, "invalid_client", basic=basic)
    return client


async def _token_authorization_code(auth: Auth, form: Any, client: dict[str, Any]) -> Response:
    code = form.get("code")
    verifier = form.get("code_verifier")
    if not isinstance(code, str) or not code or not isinstance(verifier, str) or not verifier:
        return _oauth_error(400, "invalid_request", "code and code_verifier are required")

    row = await auth.adapter.find_one("oauth_code", [Where("code_hash", _hash(code))])
    if row is None:
        return _oauth_error(400, "invalid_grant")
    if row["used"]:
        # Replay of a spent code is evidence of theft: revoke everything it
        # issued before rejecting (RFC 9700 §4.2 / RFC 6749 §4.1.2).
        if row["family_id"]:
            await auth.adapter.update(
                "oauth_token", [Where("family_id", row["family_id"])], {"revoked": 1}
            )
        return _oauth_error(400, "invalid_grant")
    if row["expires_at"] <= sessions.isoformat(sessions.now()):
        await auth.adapter.delete("oauth_code", [Where("id", row["id"])])
        return _oauth_error(400, "invalid_grant")
    if row["client_id"] != client["client_id"]:
        return _oauth_error(400, "invalid_grant")
    if row["redirect_uri"] != form.get("redirect_uri"):
        return _oauth_error(400, "invalid_grant")
    if not hmac.compare_digest(_s256(verifier), row["code_challenge"]):
        return _oauth_error(400, "invalid_grant", "PKCE verification failed")

    resources = form.get_all("resource")
    if len(resources) > 1:
        return _oauth_error(400, "invalid_target", "only a single resource is supported")
    if resources and resources[0] != row["resource"]:
        return _oauth_error(400, "invalid_target")

    family = new_id()
    await auth.adapter.update(
        "oauth_code", [Where("id", row["id"])], {"used": 1, "family_id": family}
    )
    return await _mint_tokens(
        auth,
        client=client,
        family_id=family,
        user_id=row["user_id"],
        scope=row["scope"],
        resource=row["resource"],
    )


async def _token_refresh(auth: Auth, form: Any, client: dict[str, Any]) -> Response:
    presented = form.get("refresh_token")
    if not isinstance(presented, str) or not presented:
        return _oauth_error(400, "invalid_request", "refresh_token is required")

    row = await auth.adapter.find_one(
        "oauth_token", [Where("refresh_token_hash", _hash(presented))]
    )
    if row is None:
        return _oauth_error(400, "invalid_grant")
    if row["revoked"]:
        # A rotated-out refresh token came back: assume theft, kill the family
        # (RFC 9700 §4.14).
        await auth.adapter.update(
            "oauth_token", [Where("family_id", row["family_id"])], {"revoked": 1}
        )
        return _oauth_error(400, "invalid_grant")
    if row["client_id"] != client["client_id"]:
        return _oauth_error(400, "invalid_grant")
    if row["refresh_expires_at"] is not None and row["refresh_expires_at"] <= sessions.isoformat(
        sessions.now()
    ):
        return _oauth_error(400, "invalid_grant")

    scope = form.get("scope")
    if isinstance(scope, str) and scope:
        if not set(scope.split()) <= set((row["scope"] or "").split()):
            return _oauth_error(400, "invalid_scope")
    else:
        scope = row["scope"]

    await auth.adapter.update("oauth_token", [Where("id", row["id"])], {"revoked": 1})
    return await _mint_tokens(
        auth,
        client=client,
        family_id=row["family_id"],
        user_id=row["user_id"],
        scope=scope,
        resource=row["resource"],
    )


async def _mint_tokens(
    auth: Auth,
    *,
    client: dict[str, Any],
    family_id: str,
    user_id: str,
    scope: str | None,
    resource: str | None,
) -> Response:
    config = auth.authorization_server
    assert config is not None
    access = ACCESS_PREFIX + secrets.token_urlsafe(32)
    with_refresh = "refresh_token" in json.loads(client["grant_types"])
    refresh = REFRESH_PREFIX + secrets.token_urlsafe(32) if with_refresh else None
    stamp = sessions.now()
    await auth.adapter.create(
        "oauth_token",
        {
            "id": new_id(),
            "access_token_hash": _hash(access),
            "refresh_token_hash": _hash(refresh) if refresh else None,
            "family_id": family_id,
            "client_id": client["client_id"],
            "user_id": user_id,
            "scope": scope,
            "resource": resource,
            "access_expires_at": sessions.isoformat(stamp + config.access_token_ttl),
            "refresh_expires_at": (
                sessions.isoformat(stamp + config.refresh_token_ttl) if refresh else None
            ),
            "revoked": 0,
            "created_at": sessions.isoformat(stamp),
        },
    )
    body: dict[str, Any] = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": int(config.access_token_ttl.total_seconds()),
    }
    if scope:
        body["scope"] = scope
    if refresh:
        body["refresh_token"] = refresh
    headers = Headers({"content-type": "application/json", "cache-control": "no-store"})
    return Response(json.dumps(body, separators=(",", ":")), status=200, headers=headers)


# -- POST /oauth2/register (RFC 7591) --------------------------------------------------


async def register_client(auth: Auth, request: Request) -> Response:
    if auth.authorization_server is None:
        return problem(404, title="Not Found")
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data

    uris = data.get("redirect_uris")
    if (
        not isinstance(uris, list)
        or not uris
        or not all(isinstance(uri, str) and uri for uri in uris)
    ):
        return _oauth_error(
            400, "invalid_redirect_uri", "redirect_uris must be a non-empty array of strings"
        )
    for uri in uris:
        if not _acceptable_redirect_uri(uri):
            return _oauth_error(
                400,
                "invalid_redirect_uri",
                f"{uri!r} is not acceptable (https, loopback http, or a private-use scheme)",
            )

    method = data.get("token_endpoint_auth_method", "client_secret_basic")
    if method not in AUTH_METHODS:
        return _oauth_error(
            400, "invalid_client_metadata", "unsupported token_endpoint_auth_method"
        )
    grant_types = data.get("grant_types", ["authorization_code"])
    if (
        not isinstance(grant_types, list)
        or not set(grant_types) <= GRANT_TYPES
        or "authorization_code" not in grant_types
    ):
        return _oauth_error(400, "invalid_client_metadata", "unsupported grant_types")
    response_types = data.get("response_types", ["code"])
    if response_types != ["code"]:
        return _oauth_error(
            400, "invalid_client_metadata", "only response_type 'code' is supported"
        )
    name = data.get("client_name")
    if name is not None and not isinstance(name, str):
        return _oauth_error(400, "invalid_client_metadata", "client_name must be a string")
    scope = data.get("scope")
    if scope is not None and not isinstance(scope, str):
        return _oauth_error(400, "invalid_client_metadata", "scope must be a string")

    client_id = secrets.token_urlsafe(24)
    client_secret = None if method == "none" else secrets.token_urlsafe(32)
    stamp = sessions.now()
    await auth.adapter.create(
        "oauth_client",
        {
            "id": new_id(),
            "client_id": client_id,
            "client_secret_hash": _hash(client_secret) if client_secret else None,
            "name": name,
            "redirect_uris": json.dumps(uris),
            "token_endpoint_auth_method": method,
            "grant_types": json.dumps(grant_types),
            "scope": scope,
            "created_at": sessions.isoformat(stamp),
            "updated_at": sessions.isoformat(stamp),
        },
    )

    body: dict[str, Any] = {
        "client_id": client_id,
        "client_id_issued_at": int(stamp.timestamp()),
        "redirect_uris": uris,
        "token_endpoint_auth_method": method,
        "grant_types": grant_types,
        "response_types": ["code"],
    }
    if client_secret is not None:
        # The secret appears here and never again (hash-only at rest).
        body["client_secret"] = client_secret
        body["client_secret_expires_at"] = 0
    if name is not None:
        body["client_name"] = name
    if scope is not None:
        body["scope"] = scope
    return _json_response(body, status=201)


# -- verification (the hayate-mcp splice point) ------------------------------------------


async def verify_token(
    auth: Auth, token_value: str, *, resource: str | None = None
) -> dict[str, Any] | None:
    """Claims for a live access token, or None. With ``resource`` set, a
    token minted for a different RFC 8707 resource is rejected."""
    if not token_value.startswith(ACCESS_PREFIX):
        return None
    row = await auth.adapter.find_one(
        "oauth_token", [Where("access_token_hash", _hash(token_value))]
    )
    if row is None or row["revoked"]:
        return None
    if row["access_expires_at"] <= sessions.isoformat(sessions.now()):
        return None
    if resource is not None and row["resource"] != resource:
        return None
    return {
        "user_id": row["user_id"],
        "client_id": row["client_id"],
        "scopes": (row["scope"] or "").split(),
        "token_id": row["id"],
        "resource": row["resource"],
    }
