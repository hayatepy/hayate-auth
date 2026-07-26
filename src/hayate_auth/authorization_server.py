"""AS mode: an OAuth 2.1 Authorization Server (DESIGN §19, v0.6).

Normative: OAuth 2.1 draft / RFC 6749, RFC 7636 (PKCE, S256 only), RFC 7009
(revocation), RFC 7662 (introspection), RFC 8414 (AS metadata), RFC 7591
(Dynamic Client Registration), RFC 8707 (Resource Indicators), RFC 9700
(Security BCP), RFC 8252 §7.3 (loopback redirects).

This is the token-issuing half of the "MCP server + its AS in one app"
story: hayate-mcp's ``Authorization(verify_token=...)`` takes
``auth.oauth_token_verifier(resource=...)`` and the pair is complete.

Every credential this module mints (authorization codes, access and refresh
tokens, client secrets) is a ``secrets.token_urlsafe`` value stored only as
its SHA-256 — the same discipline as sessions and API keys. Access tokens
are opaque. A co-located resource server verifies them directly; a separated
resource server uses authenticated RFC 7662 introspection.

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
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote_plus, urlencode, urlsplit

from hayate import Headers, Request, Response, problem

from . import session as sessions
from ._signed import sign_payload, unsign_payload
from ._uuid7 import new_id
from .adapter import Where
from .cimd import (
    ClientIdMetadataDocuments,
    InvalidClientMetadata,
    is_metadata_client_id,
    resolve_metadata_client,
)
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
TOKEN_ACTIVE = 0
TOKEN_ROTATING = 1
TOKEN_COMPROMISED = 2
TOKEN_ROTATED = 3
TOKEN_REVOKED = 4


@dataclass(frozen=True)
class OAuthResourceServer:
    """Confidential resource-server credentials for RFC 7662 introspection.

    Credentials are deployment configuration, not OAuth client credentials:
    the resource server may introspect every access token whose RFC 8707
    resource matches ``resource``. Use an independently generated secret.
    """

    client_id: str
    client_secret: str
    resource: str

    def __post_init__(self) -> None:
        if not self.client_id:
            raise ValueError("resource-server client_id must be non-empty")
        if len(self.client_secret) < 32:
            raise ValueError("resource-server client_secret must contain at least 32 characters")
        object.__setattr__(
            self,
            "resource",
            _validate_resource(self.resource, name="resource-server resource"),
        )


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
    resource: str | None = None
    resource_servers: tuple[OAuthResourceServer, ...] = ()
    client_id_metadata_documents: ClientIdMetadataDocuments | None = None
    access_token_ttl: timedelta = timedelta(hours=1)
    refresh_token_ttl: timedelta = timedelta(days=30)
    code_ttl: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        parts = urlsplit(self.issuer)
        try:
            _issuer_port = parts.port
        except ValueError:
            raise ValueError("issuer contains an invalid port") from None
        if parts.scheme not in ("https", "http") or not parts.netloc:
            raise ValueError("issuer must be an absolute http(s) origin")
        if (
            parts.path not in ("", "/")
            or parts.query
            or parts.fragment
            or parts.username
            or parts.password
        ):
            raise ValueError("issuer must be an origin without path, query, or fragment")
        if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS:
            raise ValueError("issuer must use https except on loopback hosts")
        object.__setattr__(self, "issuer", f"{parts.scheme.lower()}://{parts.netloc.lower()}")
        if self.resource is not None:
            object.__setattr__(self, "resource", _validate_resource(self.resource))
        resource_server_ids = [server.client_id for server in self.resource_servers]
        if len(resource_server_ids) != len(set(resource_server_ids)):
            raise ValueError("resource-server client_id values must be unique")
        if self.resource is not None and any(
            not _resource_matches(server.resource, self.resource)
            for server in self.resource_servers
        ):
            raise ValueError("resource-server resource must match the configured resource")


# -- small shared pieces ---------------------------------------------------------------


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _oauth_error(
    status: int,
    error: str,
    description: str | None = None,
    *,
    basic: bool = False,
    basic_realm: str = "oauth2/token",
) -> Response:
    """An RFC 6749 §5.2 error body (not Problem Details: token/register
    clients parse the standard ``{"error": ...}`` shape)."""
    body: dict[str, Any] = {"error": error}
    if description is not None:
        body["error_description"] = description
    headers = Headers(
        {
            "content-type": "application/json",
            "cache-control": "no-store",
            "pragma": "no-cache",
        }
    )
    if basic:
        headers.set("www-authenticate", f'Basic realm="{basic_realm}"')
    return Response(json.dumps(body, separators=(",", ":")), status=status, headers=headers)


def _oauth_json_response(data: Any, *, status: int = 200) -> Response:
    return Response(
        json.dumps(data, separators=(",", ":")),
        status=status,
        headers=Headers(
            {
                "content-type": "application/json",
                "cache-control": "no-store",
                "pragma": "no-cache",
            }
        ),
    )


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


def _canonical_resource(value: str) -> str:
    parts = urlsplit(value)
    return parts._replace(
        scheme=parts.scheme.lower(),
        netloc=parts.netloc.lower(),
    ).geturl()


def _validate_resource(value: str, *, name: str = "resource") -> str:
    resource = urlsplit(value)
    try:
        _resource_port = resource.port
    except ValueError:
        raise ValueError(f"{name} contains an invalid port") from None
    if (
        resource.scheme not in ("https", "http")
        or not resource.netloc
        or resource.fragment
        or resource.username
        or resource.password
    ):
        raise ValueError(f"{name} must be an absolute HTTP(S) URI without a fragment")
    if resource.scheme == "http" and resource.hostname not in LOOPBACK_HOSTS:
        raise ValueError(f"{name} must use https except on loopback hosts")
    return _canonical_resource(value)


def _resource_matches(presented: str, expected: str) -> bool:
    try:
        return _canonical_resource(presented) == _canonical_resource(expected)
    except ValueError:
        return False


def _acceptable_redirect_uri(uri: str) -> bool:
    parsed = urlsplit(uri)
    try:
        _port = parsed.port
    except ValueError:
        return False
    if not parsed.scheme or parsed.fragment or parsed.username or parsed.password:
        return False
    if parsed.scheme == "https":
        return bool(parsed.netloc and parsed.hostname)
    if parsed.scheme == "http":
        return bool(parsed.netloc) and parsed.hostname in LOOPBACK_HOSTS
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
        "revocation_endpoint": f"{base}/oauth2/revoke",
        "revocation_endpoint_auth_methods_supported": list(AUTH_METHODS),
    }
    if config.resource_servers:
        doc["introspection_endpoint"] = f"{base}/oauth2/introspect"
        doc["introspection_endpoint_auth_methods_supported"] = ["client_secret_basic"]
    if config.scopes_supported:
        doc["scopes_supported"] = list(config.scopes_supported)
    if config.client_id_metadata_documents is not None:
        doc["client_id_metadata_document_supported"] = True
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
    if (
        client_id
        and config.client_id_metadata_documents is not None
        and is_metadata_client_id(client_id)
    ):
        try:
            client = await resolve_metadata_client(auth, client_id, client)
        except InvalidClientMetadata as error:
            return problem(400, title="Invalid client_id", detail=str(error))
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
    if config.resource is not None and (
        resource is None or not _resource_matches(resource, config.resource)
    ):
        return _error_redirect(
            redirect_uri,
            state,
            "invalid_target",
            "resource must identify this MCP server",
        )
    if resource is not None:
        resource = _canonical_resource(resource)
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
    if (
        consent_row is not None
        and not consent_row["revoked"]
        and set(scope.split()) <= set((consent_row["scope"] or "").split())
    ):
        return await _code_redirect(
            auth,
            user_id=user["id"],
            client_id=client["client_id"],
            grant_id=consent_row["grant_id"],
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
    grant_id: str,
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
        grant_id=grant_id,
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
    grant_id: str,
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
            "grant_id": grant_id,
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
        grant_id = new_id()
        await auth.adapter.create(
            "oauth_consent",
            {
                "id": new_id(),
                "user_id": user["id"],
                "client_id": pending["client_id"],
                "grant_id": grant_id,
                "scope": scope,
                "revoked": 0,
                "created_at": stamp,
                "updated_at": stamp,
            },
        )
    elif existing["revoked"]:
        grant_id = new_id()
        await auth.adapter.update(
            "oauth_consent",
            [Where("id", existing["id"])],
            {
                "grant_id": grant_id,
                "scope": scope,
                "revoked": 0,
                "updated_at": stamp,
            },
        )
    else:
        grant_id = existing["grant_id"]
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
        grant_id=grant_id,
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
    if (request.headers.get("content-type") or "").partition(";")[0].strip().lower() != (
        "application/x-www-form-urlencoded"
    ):
        return _oauth_error(
            400, "invalid_request", "body must be application/x-www-form-urlencoded"
        )
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
    if header is not None:
        if not header.lower().startswith("basic "):
            return _oauth_error(401, "invalid_client", basic=True)
        try:
            decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return _oauth_error(401, "invalid_client", basic=True)
        encoded_id, separator, encoded_secret = decoded.partition(":")
        if not separator:
            return _oauth_error(401, "invalid_client", basic=True)
        return await _check_client(
            auth, unquote_plus(encoded_id), unquote_plus(encoded_secret), "client_secret_basic"
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
            # ``used = 2`` is a durable compromise marker.  A successful
            # exchange finalizes 1 -> 3 before disclosing its token.  Trying
            # both guarded source states closes the race where the winner
            # finalizes after this replay read the row.
            marked = await auth.adapter.update_many(
                "oauth_code",
                [Where("id", row["id"]), Where("used", 1)],
                {"used": 2},
            )
            if marked == 0:
                await auth.adapter.update_many(
                    "oauth_code",
                    [Where("id", row["id"]), Where("used", 3)],
                    {"used": 2},
                )
            await auth.adapter.update_many(
                "oauth_token",
                [
                    Where("family_id", row["family_id"]),
                    Where("revoked", TOKEN_ACTIVE),
                ],
                {"revoked": TOKEN_ROTATING},
            )
        return _oauth_error(400, "invalid_grant")
    if row["expires_at"] <= sessions.isoformat(sessions.now()):
        await auth.adapter.delete("oauth_code", [Where("id", row["id"])])
        return _oauth_error(400, "invalid_grant")
    if row["client_id"] != client["client_id"]:
        return _oauth_error(400, "invalid_grant")
    grant_id = row["grant_id"]
    if not isinstance(grant_id, str) or not await _grant_active(
        auth,
        user_id=row["user_id"],
        client_id=row["client_id"],
        grant_id=grant_id,
    ):
        return _oauth_error(400, "invalid_grant")
    if row["redirect_uri"] != form.get("redirect_uri"):
        return _oauth_error(400, "invalid_grant")
    try:
        verified_challenge = _s256(verifier)
    except UnicodeEncodeError:
        return _oauth_error(400, "invalid_grant", "PKCE verification failed")
    if not hmac.compare_digest(verified_challenge, row["code_challenge"]):
        return _oauth_error(400, "invalid_grant", "PKCE verification failed")

    resources = form.get_all("resource")
    if len(resources) > 1:
        return _oauth_error(400, "invalid_target", "only a single resource is supported")
    config = auth.authorization_server
    assert config is not None
    if config.resource is not None and not resources:
        return _oauth_error(400, "invalid_target", "resource is required")
    if resources and (
        row["resource"] is None or not _resource_matches(resources[0], row["resource"])
    ):
        return _oauth_error(400, "invalid_target")

    family = new_id()
    claimed = await auth.adapter.update_many(
        "oauth_code",
        [Where("id", row["id"]), Where("used", 0)],
        {"used": 1, "family_id": family},
    )
    if claimed != 1:
        # Another request won the guarded transition. Do not mint a second
        # token family, and do not revoke the winner as if this were a later
        # replay: simultaneous retries are not evidence of theft.
        return _oauth_error(400, "invalid_grant")
    return await _mint_tokens(
        auth,
        client=client,
        family_id=family,
        user_id=row["user_id"],
        grant_id=grant_id,
        scope=row["scope"],
        resource=row["resource"],
        authorization_code_id=row["id"],
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
        # Preserve one ``revoked = 2`` row as a durable family-compromise
        # marker.  A concurrent rotation checks it after inserting its
        # replacement, so a replay cannot slip through the create gap.
        marked = await auth.adapter.update_many(
            "oauth_token",
            [Where("id", row["id"]), Where("revoked", TOKEN_ROTATING)],
            {"revoked": TOKEN_COMPROMISED},
        )
        if marked == 0:
            await auth.adapter.update_many(
                "oauth_token",
                [Where("id", row["id"]), Where("revoked", TOKEN_ROTATED)],
                {"revoked": TOKEN_COMPROMISED},
            )
        await auth.adapter.update_many(
            "oauth_token",
            [
                Where("family_id", row["family_id"]),
                Where("revoked", TOKEN_ACTIVE),
            ],
            {"revoked": TOKEN_ROTATING},
        )
        return _oauth_error(400, "invalid_grant")
    if row["client_id"] != client["client_id"]:
        return _oauth_error(400, "invalid_grant")
    grant_id = row["grant_id"]
    if not isinstance(grant_id, str) or not await _grant_active(
        auth,
        user_id=row["user_id"],
        client_id=row["client_id"],
        grant_id=grant_id,
    ):
        return _oauth_error(400, "invalid_grant")
    if row["refresh_expires_at"] is not None and row["refresh_expires_at"] <= sessions.isoformat(
        sessions.now()
    ):
        return _oauth_error(400, "invalid_grant")

    resources = form.get_all("resource")
    if len(resources) > 1:
        return _oauth_error(400, "invalid_target", "only a single resource is supported")
    config = auth.authorization_server
    assert config is not None
    if config.resource is not None and not resources:
        return _oauth_error(400, "invalid_target", "resource is required")
    if resources and (
        row["resource"] is None or not _resource_matches(resources[0], row["resource"])
    ):
        return _oauth_error(400, "invalid_target")

    scope = form.get("scope")
    if isinstance(scope, str) and scope:
        if not set(scope.split()) <= set((row["scope"] or "").split()):
            return _oauth_error(400, "invalid_scope")
    else:
        scope = row["scope"]

    claimed = await auth.adapter.update_many(
        "oauth_token",
        [Where("id", row["id"]), Where("revoked", TOKEN_ACTIVE)],
        {"revoked": TOKEN_ROTATING},
    )
    if claimed != 1:
        return _oauth_error(400, "invalid_grant")
    return await _mint_tokens(
        auth,
        client=client,
        family_id=row["family_id"],
        user_id=row["user_id"],
        grant_id=grant_id,
        scope=scope,
        resource=row["resource"],
        rotated_token_id=row["id"],
    )


async def _mint_tokens(
    auth: Auth,
    *,
    client: dict[str, Any],
    family_id: str,
    user_id: str,
    grant_id: str,
    scope: str | None,
    resource: str | None,
    authorization_code_id: str | None = None,
    rotated_token_id: str | None = None,
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
            "grant_id": grant_id,
            "scope": scope,
            "resource": resource,
            "access_expires_at": sessions.isoformat(stamp + config.access_token_ttl),
            "refresh_expires_at": (
                sessions.isoformat(stamp + config.refresh_token_ttl) if refresh else None
            ),
            "revoked": TOKEN_ACTIVE,
            "created_at": sessions.isoformat(stamp),
        },
    )
    finalized = 0
    if authorization_code_id is not None:
        finalized = await auth.adapter.update_many(
            "oauth_code",
            [Where("id", authorization_code_id), Where("used", 1)],
            {"used": 3},
        )
    elif rotated_token_id is not None:
        finalized = await auth.adapter.update_many(
            "oauth_token",
            [Where("id", rotated_token_id), Where("revoked", TOKEN_ROTATING)],
            {"revoked": TOKEN_ROTATED},
        )
    if (
        finalized != 1
        or await _family_invalidated(auth, family_id)
        or not await _grant_active(
            auth,
            user_id=user_id,
            client_id=client["client_id"],
            grant_id=grant_id,
        )
    ):
        # A replay may have been detected while the token row did not exist.
        # The guarded finalization also prevents a replay that read the
        # in-progress state from acting on stale data without being noticed.
        # Never disclose credentials from a compromised family.
        await auth.adapter.update_many(
            "oauth_token",
            [Where("family_id", family_id), Where("revoked", TOKEN_ACTIVE)],
            {"revoked": TOKEN_ROTATING},
        )
        return _oauth_error(400, "invalid_grant")
    body: dict[str, Any] = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": int(config.access_token_ttl.total_seconds()),
    }
    if scope:
        body["scope"] = scope
    if refresh:
        body["refresh_token"] = refresh
    headers = Headers(
        {
            "content-type": "application/json",
            "cache-control": "no-store",
            "pragma": "no-cache",
        }
    )
    return Response(json.dumps(body, separators=(",", ":")), status=200, headers=headers)


async def _family_invalidated(auth: Auth, family_id: str) -> bool:
    """Return whether replay detection or explicit revocation burned a family."""
    code_replay = await auth.adapter.find_one(
        "oauth_code",
        [Where("family_id", family_id), Where("used", 2)],
    )
    if code_replay is not None:
        return True
    refresh_replay = await auth.adapter.find_one(
        "oauth_token",
        [
            Where("family_id", family_id),
            Where("revoked", (TOKEN_COMPROMISED, TOKEN_REVOKED), "in"),
        ],
    )
    return refresh_replay is not None


async def _grant_active(auth: Auth, *, user_id: str, client_id: str, grant_id: str) -> bool:
    consent = await auth.adapter.find_one(
        "oauth_consent",
        [
            Where("user_id", user_id),
            Where("client_id", client_id),
            Where("grant_id", grant_id),
            Where("revoked", 0),
        ],
    )
    return consent is not None


# -- RFC 7009 revocation / RFC 7662 introspection --------------------------------------


async def _find_token_row(
    auth: Auth, presented: str, hint: Any = None
) -> tuple[dict[str, Any], str] | None:
    fields = ["access_token_hash", "refresh_token_hash"]
    if hint == "refresh_token" or presented.startswith(REFRESH_PREFIX):
        fields.reverse()
    digest = _hash(presented)
    for field in fields:
        row = await auth.adapter.find_one("oauth_token", [Where(field, digest)])
        if row is not None:
            kind = "access_token" if field == "access_token_hash" else "refresh_token"
            return row, kind
    return None


async def revoke_token(auth: Auth, request: Request) -> Response:
    """RFC 7009: idempotently invalidate a token and its complete family."""
    if auth.authorization_server is None:
        return problem(404, title="Not Found")
    if (request.headers.get("content-type") or "").partition(";")[0].strip().lower() != (
        "application/x-www-form-urlencoded"
    ):
        return _oauth_error(
            400, "invalid_request", "body must be application/x-www-form-urlencoded"
        )
    try:
        form = await request.form_data()
    except Exception:
        return _oauth_error(
            400, "invalid_request", "body must be application/x-www-form-urlencoded"
        )
    client = await _authenticate_client(auth, request, form)
    if isinstance(client, Response):
        return client
    presented_values = form.get_all("token")
    if (
        len(presented_values) != 1
        or not isinstance(presented_values[0], str)
        or not presented_values[0]
    ):
        return _oauth_error(400, "invalid_request", "token is required")
    presented = presented_values[0]

    found = await _find_token_row(auth, presented, form.get("token_type_hint"))
    if found is not None:
        row, _kind = found
        # A valid client can only revoke its own grant. The same 200 response
        # is returned for unknown and foreign tokens, preventing enumeration.
        if row["client_id"] == client["client_id"]:
            await auth.adapter.update_many(
                "oauth_token",
                [Where("id", row["id"])],
                {"revoked": TOKEN_REVOKED},
            )
            await auth.adapter.update_many(
                "oauth_token",
                [Where("family_id", row["family_id"]), Where("revoked", TOKEN_ACTIVE)],
                {"revoked": TOKEN_REVOKED},
            )
    return Response(
        None,
        status=200,
        headers=Headers({"cache-control": "no-store", "pragma": "no-cache"}),
    )


def _basic_credentials(request: Request, *, realm: str) -> tuple[str, str] | Response:
    header = request.headers.get("authorization")
    if header is None or not header.lower().startswith("basic "):
        return _oauth_error(
            401,
            "invalid_client",
            basic=True,
            basic_realm=realm,
        )
    try:
        decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return _oauth_error(
            401,
            "invalid_client",
            basic=True,
            basic_realm=realm,
        )
    encoded_id, separator, encoded_secret = decoded.partition(":")
    if not separator:
        return _oauth_error(
            401,
            "invalid_client",
            basic=True,
            basic_realm=realm,
        )
    return unquote_plus(encoded_id), unquote_plus(encoded_secret)


def _authenticate_resource_server(
    config: AuthorizationServer, request: Request
) -> OAuthResourceServer | Response:
    credentials = _basic_credentials(request, realm="oauth2/introspect")
    if isinstance(credentials, Response):
        return credentials
    client_id, secret = credentials
    resource_server = next(
        (candidate for candidate in config.resource_servers if candidate.client_id == client_id),
        None,
    )
    if resource_server is None or not hmac.compare_digest(secret, resource_server.client_secret):
        return _oauth_error(
            401,
            "invalid_client",
            basic=True,
            basic_realm="oauth2/introspect",
        )
    return resource_server


async def introspect_token(auth: Auth, request: Request) -> Response:
    """RFC 7662 for confidential, resource-bound resource servers."""
    config = auth.authorization_server
    if config is None or not config.resource_servers:
        return problem(404, title="Not Found")
    if (request.headers.get("content-type") or "").partition(";")[0].strip().lower() != (
        "application/x-www-form-urlencoded"
    ):
        return _oauth_error(
            400, "invalid_request", "body must be application/x-www-form-urlencoded"
        )
    try:
        form = await request.form_data()
    except Exception:
        return _oauth_error(
            400, "invalid_request", "body must be application/x-www-form-urlencoded"
        )
    resource_server = _authenticate_resource_server(config, request)
    if isinstance(resource_server, Response):
        return resource_server
    presented_values = form.get_all("token")
    if (
        len(presented_values) != 1
        or not isinstance(presented_values[0], str)
        or not presented_values[0]
    ):
        return _oauth_error(400, "invalid_request", "token is required")
    presented = presented_values[0]

    found = await _find_token_row(auth, presented, form.get("token_type_hint"))
    if found is None:
        return _oauth_json_response({"active": False})
    row, kind = found
    if (
        row["revoked"] != TOKEN_ACTIVE
        or row["resource"] is None
        or not _resource_matches(row["resource"], resource_server.resource)
    ):
        return _oauth_json_response({"active": False})

    expires_at = row["access_expires_at"] if kind == "access_token" else row["refresh_expires_at"]
    if expires_at is None or expires_at <= sessions.isoformat(sessions.now()):
        return _oauth_json_response({"active": False})

    try:
        expiration = int(datetime.fromisoformat(expires_at).timestamp())
        issued = int(datetime.fromisoformat(row["created_at"]).timestamp())
    except (TypeError, ValueError):
        return _oauth_json_response({"active": False})
    body: dict[str, Any] = {
        "active": True,
        "client_id": row["client_id"],
        "sub": row["user_id"],
        "aud": row["resource"],
        "iss": config.issuer,
        "exp": expiration,
        "iat": issued,
        "jti": row["id"],
    }
    if row["scope"]:
        body["scope"] = row["scope"]
    if kind == "access_token":
        body["token_type"] = "Bearer"
    return _oauth_json_response(body)


# -- End-user consent management -------------------------------------------------------


async def list_consents(auth: Auth, request: Request) -> Response:
    if auth.authorization_server is None:
        return problem(404, title="Not Found")
    resolved = await auth.get_session(request)
    if resolved is None:
        return problem(401, title="Authentication required")
    user = resolved[0]
    rows = await auth.adapter.find_many(
        "oauth_consent",
        [Where("user_id", user["id"]), Where("revoked", 0)],
        sort=("updated_at", "desc"),
    )
    public: list[dict[str, Any]] = []
    for row in rows:
        client = await auth.adapter.find_one("oauth_client", [Where("client_id", row["client_id"])])
        public.append(
            {
                "client_id": row["client_id"],
                "client_name": client["name"] if client is not None else None,
                "scope": row["scope"] or "",
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )
    return _oauth_json_response({"consents": public})


async def revoke_consent(auth: Auth, request: Request) -> Response:
    """Revoke one user's complete grant to a client, including race winners."""
    if auth.authorization_server is None:
        return problem(404, title="Not Found")
    resolved = await auth.get_session(request)
    if resolved is None:
        return problem(401, title="Authentication required")
    user = resolved[0]
    data = await _read_json_object(request)
    if isinstance(data, Response):
        return data
    client_id = data.get("client_id")
    if not isinstance(client_id, str) or not client_id:
        return problem(400, title="client_id is required")

    stamp = sessions.isoformat(sessions.now())
    consent = await auth.adapter.find_one(
        "oauth_consent",
        [Where("user_id", user["id"]), Where("client_id", client_id)],
    )
    if consent is not None:
        # Change grant_id first. Any in-flight mint bound to the prior value
        # fails its final grant check even if its token row did not exist yet.
        await auth.adapter.update_many(
            "oauth_consent",
            [Where("id", consent["id"])],
            {"grant_id": new_id(), "revoked": 1, "updated_at": stamp},
        )
        await auth.adapter.update_many(
            "oauth_code",
            [
                Where("user_id", user["id"]),
                Where("client_id", client_id),
                Where("used", (0, 1, 3), "in"),
            ],
            {"used": 2},
        )
        await auth.adapter.update_many(
            "oauth_token",
            [
                Where("user_id", user["id"]),
                Where("client_id", client_id),
                Where(
                    "revoked",
                    (TOKEN_ACTIVE, TOKEN_ROTATING, TOKEN_ROTATED, TOKEN_REVOKED),
                    "in",
                ),
            ],
            {"revoked": TOKEN_REVOKED},
        )
    return _oauth_json_response({"success": True})


# -- POST /oauth2/register (RFC 7591) --------------------------------------------------


async def register_client(auth: Auth, request: Request) -> Response:
    if auth.authorization_server is None:
        return problem(404, title="Not Found")
    if (request.headers.get("content-type") or "").partition(";")[0].strip().lower() != (
        "application/json"
    ):
        return _oauth_error(400, "invalid_request", "body must use application/json")
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
        if auth.authorization_server.resource is not None:
            redirect = urlsplit(uri)
            if redirect.scheme != "https" and not (
                redirect.scheme == "http" and redirect.hostname in LOOPBACK_HOSTS
            ):
                return _oauth_error(
                    400,
                    "invalid_redirect_uri",
                    "MCP clients must use https or a loopback http redirect URI",
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
    if resource is not None and (
        row["resource"] is None or not _resource_matches(row["resource"], resource)
    ):
        return None
    from .principal import principal_from_claims

    return principal_from_claims(
        {
            "user_id": row["user_id"],
            "client_id": row["client_id"],
            "scopes": (row["scope"] or "").split(),
            "token_id": row["id"],
            "resource": row["resource"],
        },
        credential_type="oauth",
    )
