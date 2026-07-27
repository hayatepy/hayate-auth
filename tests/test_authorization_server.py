"""AS mode (DESIGN §19): metadata, DCR, authorize/consent, token grants.

The attack regressions pin every §19.4 decision: PKCE S256, exact redirect
matching (+ loopback ports), single-use codes with family revocation,
refresh rotation with reuse detection, and RFC 8707 resource binding.
"""

import asyncio
import base64
import hashlib
import json
from datetime import timedelta
from urllib.parse import parse_qs, quote_plus, urlencode, urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from hayate import Request, Response

from conftest import cookie_pair, request_json
from hayate_auth import (
    Auth,
    AuthorizationServer,
    ClientIdMetadataDocuments,
    DPoPConfig,
    OAuthResourceServer,
    ScryptBackend,
    Where,
)
from hayate_auth.dpop import jwk_thumbprint
from test_dpop import b64url, make_proof

BASE = "/api/auth"


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def make_auth(adapter, **overrides):
    config = {
        "issuer": "http://localhost",
        "login_url": "/login",
        "consent_url": "/consent",
        **overrides,
    }
    return Auth(
        secret="test-secret",
        adapter=adapter,
        crypto=ScryptBackend(log_n=12),
        authorization_server=AuthorizationServer(**config),
    )


@pytest.fixture
def auth_as(adapter):
    return make_auth(adapter)


def request_form(path: str, data: dict, *, headers: dict | None = None) -> Request:
    merged = {"content-type": "application/x-www-form-urlencoded", **(headers or {})}
    return Request(f"http://localhost{path}", method="POST", headers=merged, body=urlencode(data))


async def signed_in_cookie(auth, email="user@example.com") -> str:
    res = await auth.fetch(
        request_json(f"{BASE}/sign-up/email", {"email": email, "password": "long enough"})
    )
    assert res.status == 200
    return cookie_pair(res)


async def register(auth, **overrides) -> dict:
    payload = {
        "redirect_uris": ["https://client.example/cb"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "client_name": "Test Client",
        **overrides,
    }
    res = await auth.fetch(request_json(f"{BASE}/oauth2/register", payload))
    assert res.status == 201, await res.text()
    return await res.json()


def authorize_request(
    client,
    *,
    verifier,
    cookie=None,
    state="st4te",
    scope=None,
    resource=None,
    redirect_uri=None,
    **extra,
) -> Request:
    params = {
        "response_type": "code",
        "client_id": client["client_id"],
        "redirect_uri": redirect_uri or client["redirect_uris"][0],
        "state": state,
        "code_challenge": s256(verifier),
        "code_challenge_method": "S256",
    }
    if scope is not None:
        params["scope"] = scope
    if resource is not None:
        params["resource"] = resource
    params.update(extra)
    headers = {"cookie": cookie} if cookie else {}
    return Request(f"http://localhost{BASE}/oauth2/authorize?{urlencode(params)}", headers=headers)


def location_params(location: str) -> dict:
    return {key: values[0] for key, values in parse_qs(urlsplit(location).query).items()}


async def obtain_code(
    auth, cookie, client, *, verifier, scope=None, resource=None, dpop_jkt=None
) -> str:
    extra = {"dpop_jkt": dpop_jkt} if dpop_jkt is not None else {}
    res = await auth.fetch(
        authorize_request(
            client,
            verifier=verifier,
            cookie=cookie,
            scope=scope,
            resource=resource,
            **extra,
        )
    )
    assert res.status == 302
    location = res.headers.get("location")
    if "/consent" in location:
        pending = cookie_pair(res)
        consent = await auth.fetch(
            request_json(f"{BASE}/oauth2/consent", {"accept": True}, cookie=f"{cookie}; {pending}")
        )
        assert consent.status == 200, await consent.text()
        location = (await consent.json())["redirect_uri"]
    params = location_params(location)
    assert params["state"] == "st4te"
    return params["code"]


async def exchange(
    auth, client, code, *, verifier, redirect_uri=None, resource=None, secret=None, headers=None
):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": redirect_uri or client["redirect_uris"][0],
    }
    if headers is None or "authorization" not in headers:
        data["client_id"] = client["client_id"]
    if resource is not None:
        data["resource"] = resource
    if secret is not None:
        data["client_secret"] = secret
    return await auth.fetch(request_form(f"{BASE}/oauth2/token", data, headers=headers))


async def full_grant(auth, *, scope=None, resource=None) -> tuple[dict, dict, str]:
    """DCR -> authorize -> consent -> token; returns (tokens, client, cookie)."""
    cookie = await signed_in_cookie(auth)
    client = await register(auth)
    verifier = "a-plenty-long-code-verifier-string-42"
    code = await obtain_code(
        auth, cookie, client, verifier=verifier, scope=scope, resource=resource
    )
    res = await exchange(auth, client, code, verifier=verifier, resource=resource)
    assert res.status == 200, await res.text()
    return await res.json(), client, cookie


# -- RFC 8414 metadata -----------------------------------------------------------------


async def test_well_known_metadata(auth_as):
    res = await auth_as.fetch(Request("http://localhost/.well-known/oauth-authorization-server"))
    assert res.status == 200
    doc = await res.json()
    assert doc["issuer"] == "http://localhost"
    assert doc["authorization_endpoint"] == f"http://localhost{BASE}/oauth2/authorize"
    assert doc["token_endpoint"] == f"http://localhost{BASE}/oauth2/token"
    assert doc["registration_endpoint"] == f"http://localhost{BASE}/oauth2/register"
    assert doc["revocation_endpoint"] == f"http://localhost{BASE}/oauth2/revoke"
    assert doc["revocation_endpoint_auth_methods_supported"] == [
        "none",
        "client_secret_basic",
        "client_secret_post",
    ]
    assert "introspection_endpoint" not in doc
    introspection = await auth_as.fetch(
        request_form(f"{BASE}/oauth2/introspect", {"token": "unknown"})
    )
    assert introspection.status == 404
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert doc["response_types_supported"] == ["code"]


async def test_client_id_metadata_document_flow_and_discovery(adapter):
    client_id = "https://client.example/metadata.json"
    redirect_uri = "http://127.0.0.1:43210/callback"
    fetched: list[str] = []
    metadata = {
        "client_id": client_id,
        "client_name": "MCP Test Client",
        "redirect_uris": [redirect_uri],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": "mcp",
    }

    async def fetch_document(url: str) -> Response:
        fetched.append(url)
        return Response(
            json.dumps(metadata),
            headers={"content-type": "application/json"},
        )

    resource = "https://mcp.example.com/mcp"
    auth = make_auth(
        adapter,
        resource=resource,
        scopes_supported=("mcp",),
        client_id_metadata_documents=ClientIdMetadataDocuments(fetch_document),
    )
    discovery_response = await auth.fetch(
        Request("http://localhost/.well-known/oauth-authorization-server")
    )
    discovery = await discovery_response.json()
    assert discovery["client_id_metadata_document_supported"] is True

    cookie = await signed_in_cookie(auth)
    client = {"client_id": client_id, "redirect_uris": [redirect_uri]}
    verifier = "cimd-code-verifier-with-sufficient-length-42"
    code = await obtain_code(
        auth,
        cookie,
        client,
        verifier=verifier,
        scope="mcp",
        resource=resource,
    )
    tokens = await exchange(
        auth,
        client,
        code,
        verifier=verifier,
        resource=resource,
    )
    assert tokens.status == 200, await tokens.text()
    assert await auth.verify_oauth_token((await tokens.json())["access_token"], resource=resource)
    assert fetched == [client_id]

    stored = await adapter.find_one("oauth_client", [Where("client_id", client_id)])
    assert stored is not None
    assert stored["client_secret_hash"] is None
    assert stored["name"] == "MCP Test Client"


@pytest.mark.parametrize(
    ("client_id", "metadata"),
    [
        (
            "https://client.example/metadata.json",
            {
                "client_id": "https://wrong.example/metadata.json",
                "client_name": "Mismatch",
                "redirect_uris": ["https://wrong.example/callback"],
            },
        ),
        (
            "https://client.example/metadata.json",
            {
                "client_id": "https://client.example/metadata.json",
                "client_name": "Secret client",
                "redirect_uris": ["https://client.example/callback"],
                "client_secret": "must-not-be-accepted",
            },
        ),
        (
            "https://client.example/metadata.json",
            {
                "client_id": "https://client.example/metadata.json",
                "client_name": "Cross-origin redirect",
                "redirect_uris": ["https://attacker.example/callback"],
            },
        ),
    ],
)
async def test_invalid_client_id_metadata_documents_are_rejected(adapter, client_id, metadata):
    async def fetch_document(url: str) -> Response:
        return Response(json.dumps(metadata), headers={"content-type": "application/json"})

    auth = make_auth(
        adapter,
        client_id_metadata_documents=ClientIdMetadataDocuments(fetch_document),
    )
    request = authorize_request(
        {"client_id": client_id, "redirect_uris": ["https://client.example/callback"]},
        verifier="cimd-code-verifier-with-sufficient-length-42",
    )
    response = await auth.fetch(request)
    assert response.status == 400
    assert await adapter.find_one("oauth_client", [Where("client_id", client_id)]) is None


async def test_client_id_metadata_url_policy_runs_before_fetch(adapter):
    fetched = False

    async def fetch_document(url: str) -> Response:
        nonlocal fetched
        fetched = True
        return Response("{}", headers={"content-type": "application/json"})

    auth = make_auth(
        adapter,
        client_id_metadata_documents=ClientIdMetadataDocuments(
            fetch_document,
            allow_url=lambda url: False,
        ),
    )
    client_id = "https://client.example/metadata.json"
    response = await auth.fetch(
        authorize_request(
            {"client_id": client_id, "redirect_uris": ["https://client.example/callback"]},
            verifier="cimd-code-verifier-with-sufficient-length-42",
        )
    )
    assert response.status == 400
    assert fetched is False


async def test_client_id_metadata_document_size_and_content_type_are_bounded(adapter):
    client_id = "https://client.example/metadata.json"

    async def fetch_document(url: str) -> Response:
        return Response(
            b"{}",
            headers={"content-type": "text/html", "content-length": "9999"},
        )

    auth = make_auth(
        adapter,
        client_id_metadata_documents=ClientIdMetadataDocuments(
            fetch_document,
            max_document_bytes=8,
        ),
    )
    response = await auth.fetch(
        authorize_request(
            {"client_id": client_id, "redirect_uris": ["https://client.example/callback"]},
            verifier="cimd-code-verifier-with-sufficient-length-42",
        )
    )
    assert response.status == 400


def test_openapi_oauth2_scheme_matches_authorization_server(auth_as):
    scheme = auth_as.openapi_security_schemes()["OAuth2"]
    flow = scheme["flows"]["authorizationCode"]
    assert flow["authorizationUrl"] == "http://localhost/api/auth/oauth2/authorize"
    assert flow["tokenUrl"] == "http://localhost/api/auth/oauth2/token"


async def test_well_known_absent_without_as_mode(auth):
    res = await auth.fetch(Request("http://localhost/.well-known/oauth-authorization-server"))
    assert res.status == 404


async def test_as_endpoints_404_without_as_mode(auth):
    res = await auth.fetch(request_json(f"{BASE}/oauth2/register", {"redirect_uris": ["x"]}))
    assert res.status == 404


def test_issuer_must_be_an_origin():
    with pytest.raises(ValueError):
        AuthorizationServer(issuer="http://localhost/api", login_url="/l", consent_url="/c")
    with pytest.raises(ValueError):
        AuthorizationServer(issuer="localhost", login_url="/l", consent_url="/c")
    with pytest.raises(ValueError):
        AuthorizationServer(issuer="http://auth.example.com", login_url="/l", consent_url="/c")
    with pytest.raises(ValueError):
        AuthorizationServer(
            issuer="https://user:password@auth.example.com",
            login_url="/l",
            consent_url="/c",
        )
    with pytest.raises(ValueError):
        AuthorizationServer(
            issuer="https://auth.example.com",
            login_url="/l",
            consent_url="/c",
            resource="http://mcp.example.com/mcp",
        )
    with pytest.raises(ValueError):
        AuthorizationServer(
            issuer="https://auth.example.com",
            login_url="/l",
            consent_url="/c",
            resource="https://user@mcp.example.com/mcp",
        )
    with pytest.raises(ValueError):
        OAuthResourceServer("resource-server", "short", "https://mcp.example/mcp")
    resource_server = OAuthResourceServer(
        "resource-server",
        "s" * 32,
        "https://mcp.example/mcp",
    )
    with pytest.raises(ValueError):
        AuthorizationServer(
            issuer="https://auth.example.com",
            login_url="/l",
            consent_url="/c",
            resource_servers=(resource_server, resource_server),
        )
    with pytest.raises(ValueError):
        AuthorizationServer(
            issuer="https://auth.example.com",
            login_url="/l",
            consent_url="/c",
            resource="https://mcp.example/a",
            resource_servers=(resource_server,),
        )


# -- RFC 7591 dynamic client registration ------------------------------------------------


async def test_register_public_client(auth_as):
    client = await register(auth_as)
    assert client["client_id"]
    assert "client_secret" not in client
    assert client["token_endpoint_auth_method"] == "none"
    assert client["grant_types"] == ["authorization_code", "refresh_token"]


async def test_register_confidential_client_returns_secret_once(auth_as):
    client = await register(auth_as, token_endpoint_auth_method="client_secret_basic")
    assert client["client_secret"]
    assert client["client_secret_expires_at"] == 0
    stored = await auth_as.adapter.find_one("oauth_client", [])
    assert client["client_secret"] not in (stored["client_secret_hash"] or "")


@pytest.mark.parametrize(
    "uris",
    [
        None,
        [],
        ["http://evil.example/cb"],  # plain http on a non-loopback host
        ["https://client.example/cb#frag"],  # fragments are forbidden (RFC 6749 §3.1.2)
        ["https:callback"],  # HTTPS URI must include an authority
        ["https://user@client.example/cb"],
        ["http://localhost:bad/cb"],
        ["javascript:alert(1)"],
    ],
)
async def test_register_rejects_bad_redirect_uris(auth_as, uris):
    payload = {"redirect_uris": uris} if uris is not None else {}
    res = await auth_as.fetch(request_json(f"{BASE}/oauth2/register", payload))
    assert res.status == 400
    assert (await res.json())["error"] == "invalid_redirect_uri"


async def test_register_accepts_loopback_and_custom_schemes(auth_as):
    client = await register(
        auth_as,
        redirect_uris=["http://127.0.0.1/cb", "http://localhost:6274/cb", "com.example.app:/cb"],
    )
    assert len(client["redirect_uris"]) == 3


async def test_register_requires_json_content_type(auth_as):
    res = await auth_as.fetch(
        Request(
            f"http://localhost{BASE}/oauth2/register",
            method="POST",
            headers={"content-type": "text/plain"},
            body=json.dumps({"redirect_uris": ["https://client.example/cb"]}),
        )
    )
    assert res.status == 400
    assert (await res.json())["error"] == "invalid_request"


async def test_mcp_mode_rejects_custom_scheme_redirect(adapter):
    auth = make_auth(adapter, resource="https://mcp.example.com/mcp")
    res = await auth.fetch(
        request_json(
            f"{BASE}/oauth2/register",
            {
                "redirect_uris": ["com.example.app:/cb"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code"],
            },
        )
    )
    assert res.status == 400
    assert (await res.json())["error"] == "invalid_redirect_uri"


@pytest.mark.parametrize(
    "patch",
    [
        {"token_endpoint_auth_method": "private_key_jwt"},
        {"grant_types": ["refresh_token"]},
        {"grant_types": ["implicit"]},
        {"response_types": ["token"]},
    ],
)
async def test_register_rejects_unsupported_metadata(auth_as, patch):
    res = await auth_as.fetch(
        request_json(
            f"{BASE}/oauth2/register", {"redirect_uris": ["https://client.example/cb"], **patch}
        )
    )
    assert res.status == 400
    assert (await res.json())["error"] == "invalid_client_metadata"


# -- authorize -------------------------------------------------------------------------


async def test_authorize_unknown_client_answers_directly(auth_as):
    res = await auth_as.fetch(
        Request(f"http://localhost{BASE}/oauth2/authorize?client_id=nope&redirect_uri=x")
    )
    assert res.status == 400  # no redirect: RFC 6749 §4.1.2.1


async def test_authorize_unregistered_redirect_answers_directly(auth_as):
    client = await register(auth_as)
    res = await auth_as.fetch(
        authorize_request(client, verifier="v" * 43, redirect_uri="https://evil.example/cb")
    )
    assert res.status == 400


async def test_authorize_loopback_port_may_vary(auth_as):
    cookie = await signed_in_cookie(auth_as)
    client = await register(auth_as, redirect_uris=["http://127.0.0.1/cb"])
    res = await auth_as.fetch(
        authorize_request(
            client, verifier="v" * 43, cookie=cookie, redirect_uri="http://127.0.0.1:49152/cb"
        )
    )
    assert res.status == 302  # to consent — the vary-port loopback URI was accepted


async def test_authorize_without_session_redirects_to_login(auth_as):
    client = await register(auth_as)
    res = await auth_as.fetch(authorize_request(client, verifier="v" * 43))
    assert res.status == 302
    location = res.headers.get("location")
    assert location.startswith("http://localhost/login?redirect=")
    assert "oauth2%2Fauthorize" in location


async def test_authorize_first_time_redirects_to_consent(auth_as):
    cookie = await signed_in_cookie(auth_as)
    client = await register(auth_as)
    res = await auth_as.fetch(
        authorize_request(client, verifier="v" * 43, cookie=cookie, scope="mcp")
    )
    assert res.status == 302
    location = res.headers.get("location")
    assert location.startswith("http://localhost/consent?")
    params = location_params(location)
    assert params["client_id"] == client["client_id"]
    assert params["client_name"] == "Test Client"
    assert params["scope"] == "mcp"
    assert "set-cookie" in res.headers


@pytest.mark.parametrize(
    ("patch", "error"),
    [
        ({"response_type": "token"}, "unsupported_response_type"),
        ({"code_challenge": ""}, "invalid_request"),
        ({"code_challenge_method": "plain"}, "invalid_request"),
    ],
)
async def test_authorize_error_redirects(auth_as, patch, error):
    client = await register(auth_as)
    res = await auth_as.fetch(authorize_request(client, verifier="v" * 43, **patch))
    assert res.status == 302
    params = location_params(res.headers.get("location"))
    assert params["error"] == error
    assert params["state"] == "st4te"


async def test_authorize_rejects_multiple_resources(auth_as):
    client = await register(auth_as)
    url = (
        f"http://localhost{BASE}/oauth2/authorize?"
        + urlencode(
            {
                "response_type": "code",
                "client_id": client["client_id"],
                "redirect_uri": client["redirect_uris"][0],
                "code_challenge": s256("v" * 43),
                "code_challenge_method": "S256",
            }
        )
        + "&resource=https://a.example&resource=https://b.example"
    )
    res = await auth_as.fetch(Request(url))
    assert res.status == 302
    assert location_params(res.headers.get("location"))["error"] == "invalid_target"


async def test_mcp_mode_requires_its_resource_on_authorize(adapter):
    resource = "https://mcp.example.com/mcp"
    auth = make_auth(adapter, resource=resource)
    cookie = await signed_in_cookie(auth)
    client = await register(auth)

    missing = await auth.fetch(authorize_request(client, verifier="v" * 43, cookie=cookie))
    assert location_params(missing.headers.get("location"))["error"] == "invalid_target"

    wrong = await auth.fetch(
        authorize_request(
            client,
            verifier="v" * 43,
            cookie=cookie,
            resource="https://other.example/mcp",
        )
    )
    assert location_params(wrong.headers.get("location"))["error"] == "invalid_target"

    malformed = await auth.fetch(
        authorize_request(
            client,
            verifier="v" * 43,
            cookie=cookie,
            resource="https://[invalid/mcp",
        )
    )
    assert location_params(malformed.headers.get("location"))["error"] == "invalid_target"


async def test_authorize_rejects_unknown_scope_when_configured(adapter):
    auth = make_auth(adapter, scopes_supported=("mcp", "profile"))
    client = await register(auth)
    res = await auth.fetch(authorize_request(client, verifier="v" * 43, scope="mcp admin"))
    assert res.status == 302
    assert location_params(res.headers.get("location"))["error"] == "invalid_scope"


async def test_authorize_skips_consent_once_granted(auth_as):
    _tokens, client, cookie = await full_grant(auth_as, scope="mcp")
    verifier = "another-verifier-that-is-long-enough-42"
    res = await auth_as.fetch(
        authorize_request(client, verifier=verifier, cookie=cookie, scope="mcp")
    )
    assert res.status == 302
    params = location_params(res.headers.get("location"))
    assert "code" in params  # straight back to the client, no consent hop


async def test_authorize_widening_scope_needs_fresh_consent(auth_as):
    _tokens, client, cookie = await full_grant(auth_as, scope="mcp")
    res = await auth_as.fetch(
        authorize_request(client, verifier="v" * 43, cookie=cookie, scope="mcp admin")
    )
    assert res.status == 302
    assert res.headers.get("location").startswith("http://localhost/consent?")


# -- consent ---------------------------------------------------------------------------


async def test_consent_reject_returns_access_denied(auth_as):
    cookie = await signed_in_cookie(auth_as)
    client = await register(auth_as)
    res = await auth_as.fetch(authorize_request(client, verifier="v" * 43, cookie=cookie))
    pending = cookie_pair(res)
    consent = await auth_as.fetch(
        request_json(f"{BASE}/oauth2/consent", {"accept": False}, cookie=f"{cookie}; {pending}")
    )
    assert consent.status == 200
    params = location_params((await consent.json())["redirect_uri"])
    assert params["error"] == "access_denied"
    assert params["state"] == "st4te"


async def test_consent_requires_session_and_pending_request(auth_as):
    res = await auth_as.fetch(request_json(f"{BASE}/oauth2/consent", {"accept": True}))
    assert res.status == 401
    cookie = await signed_in_cookie(auth_as)
    res = await auth_as.fetch(
        request_json(f"{BASE}/oauth2/consent", {"accept": True}, cookie=cookie)
    )
    assert res.status == 400


async def test_consent_cookie_is_bound_to_the_user(auth_as):
    cookie = await signed_in_cookie(auth_as, email="alice@example.com")
    client = await register(auth_as)
    res = await auth_as.fetch(authorize_request(client, verifier="v" * 43, cookie=cookie))
    pending = cookie_pair(res)
    other = await signed_in_cookie(auth_as, email="mallory@example.com")
    hijack = await auth_as.fetch(
        request_json(f"{BASE}/oauth2/consent", {"accept": True}, cookie=f"{other}; {pending}")
    )
    assert hijack.status == 400


# -- token: authorization_code grant ------------------------------------------------------


async def test_token_full_flow_public_client(auth_as):
    tokens, client, _cookie = await full_grant(auth_as, scope="mcp", resource="https://rs.example")
    assert tokens["access_token"].startswith("hat_")
    assert tokens["refresh_token"].startswith("har_")
    assert tokens["token_type"] == "Bearer"
    assert tokens["expires_in"] == 3600
    assert tokens["scope"] == "mcp"

    claims = await auth_as.verify_oauth_token(tokens["access_token"])
    assert claims["client_id"] == client["client_id"]
    assert claims["scopes"] == ["mcp"]
    assert claims["resource"] == "https://rs.example"


async def test_token_response_is_uncacheable(auth_as):
    cookie = await signed_in_cookie(auth_as)
    client = await register(auth_as)
    verifier = "v" * 43
    code = await obtain_code(auth_as, cookie, client, verifier=verifier)
    res = await exchange(auth_as, client, code, verifier=verifier)
    assert res.headers.get("cache-control") == "no-store"


async def test_dpop_code_access_refresh_and_introspection_are_end_to_end_bound(adapter):
    resource = "https://mcp.example/mcp"
    resource_server = OAuthResourceServer(
        client_id="mcp-resource-server",
        client_secret="resource-server-secret-at-least-32-characters",
        resource=resource,
    )
    auth = make_auth(
        adapter,
        dpop=DPoPConfig(),
        resource=resource,
        scopes_supported=("mcp",),
        resource_servers=(resource_server,),
    )
    metadata = await auth.fetch(Request("http://localhost/.well-known/oauth-authorization-server"))
    assert (await metadata.json())["dpop_signing_alg_values_supported"] == ["ES256"]

    private_key = ec.generate_private_key(ec.SECP256R1())
    public = private_key.public_key().public_numbers()
    key = (
        private_key,
        {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(public.x.to_bytes(32)),
            "y": b64url(public.y.to_bytes(32)),
        },
    )
    jkt = jwk_thumbprint(key[1])
    client = await register(auth, dpop_bound_access_tokens=True)
    assert client["dpop_bound_access_tokens"] is True
    cookie = await signed_in_cookie(auth)
    verifier = "dpop-code-verifier-with-sufficient-length-42"
    code = await obtain_code(
        auth,
        cookie,
        client,
        verifier=verifier,
        scope="mcp",
        resource=resource,
        dpop_jkt=jkt,
    )

    missing = await exchange(auth, client, code, verifier=verifier, resource=resource)
    assert missing.status == 400
    assert (await missing.json())["error"] == "invalid_dpop_proof"

    token_proof = make_proof(
        key,
        method="POST",
        url=f"http://localhost{BASE}/oauth2/token",
        jti="authorization-code-proof",
    )
    issued = await exchange(
        auth,
        client,
        code,
        verifier=verifier,
        resource=resource,
        headers={"dpop": token_proof},
    )
    assert issued.status == 200, await issued.text()
    tokens = await issued.json()
    assert tokens["token_type"] == "DPoP"
    claims = await auth.verify_oauth_token(tokens["access_token"], resource=resource)
    assert claims["dpop_jkt"] == jkt

    introspected = await auth.fetch(
        request_form(
            f"{BASE}/oauth2/introspect",
            {"token": tokens["access_token"]},
            headers=basic_auth(resource_server.client_id, resource_server.client_secret),
        )
    )
    introspection = await introspected.json()
    assert introspection["token_type"] == "DPoP"
    assert introspection["cnf"] == {"jkt": jkt}

    other_private = ec.generate_private_key(ec.SECP256R1())
    other_public = other_private.public_key().public_numbers()
    other_key = (
        other_private,
        {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(other_public.x.to_bytes(32)),
            "y": b64url(other_public.y.to_bytes(32)),
        },
    )
    wrong_rotation = await auth.fetch(
        request_form(
            f"{BASE}/oauth2/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": client["client_id"],
                "resource": resource,
            },
            headers={
                "dpop": make_proof(
                    other_key,
                    method="POST",
                    url=f"http://localhost{BASE}/oauth2/token",
                    jti="wrong-refresh-key",
                )
            },
        )
    )
    assert wrong_rotation.status == 400
    assert (await wrong_rotation.json())["error"] == "invalid_dpop_proof"

    rotated = await auth.fetch(
        request_form(
            f"{BASE}/oauth2/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": client["client_id"],
                "resource": resource,
            },
            headers={
                "dpop": make_proof(
                    key,
                    method="POST",
                    url=f"http://localhost{BASE}/oauth2/token",
                    jti="valid-refresh-key",
                )
            },
        )
    )
    assert rotated.status == 200, await rotated.text()
    assert (await rotated.json())["token_type"] == "DPoP"


async def test_server_wide_dpop_policy_prevents_bearer_issuance_for_every_client(adapter):
    resource = "https://mcp.example/mcp"
    auth = make_auth(
        adapter,
        dpop=DPoPConfig(require_bound_tokens=True),
        resource=resource,
        scopes_supported=("mcp",),
    )
    client = await register(auth)
    assert client["dpop_bound_access_tokens"] is False
    cookie = await signed_in_cookie(auth)
    verifier = "server-wide-dpop-verifier-with-sufficient-length-42"

    missing_jkt = await auth.fetch(
        authorize_request(
            client,
            verifier=verifier,
            cookie=cookie,
            scope="mcp",
            resource=resource,
        )
    )
    assert missing_jkt.status == 302
    missing_jkt_error = location_params(missing_jkt.headers.get("location"))
    assert missing_jkt_error["error"] == "invalid_request"
    assert missing_jkt_error["error_description"] == "dpop_jkt is required for this client"
    assert "code" not in missing_jkt_error

    private_key = ec.generate_private_key(ec.SECP256R1())
    public = private_key.public_key().public_numbers()
    key = (
        private_key,
        {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(public.x.to_bytes(32)),
            "y": b64url(public.y.to_bytes(32)),
        },
    )
    code = await obtain_code(
        auth,
        cookie,
        client,
        verifier=verifier,
        scope="mcp",
        resource=resource,
        dpop_jkt=jwk_thumbprint(key[1]),
    )

    missing_code_proof = await exchange(
        auth,
        client,
        code,
        verifier=verifier,
        resource=resource,
    )
    assert missing_code_proof.status == 400
    assert (await missing_code_proof.json())["error"] == "invalid_dpop_proof"

    token_url = f"http://localhost{BASE}/oauth2/token"
    issued = await exchange(
        auth,
        client,
        code,
        verifier=verifier,
        resource=resource,
        headers={
            "dpop": make_proof(
                key,
                method="POST",
                url=token_url,
                jti="server-wide-code-proof",
            )
        },
    )
    assert issued.status == 200, await issued.text()
    tokens = await issued.json()
    assert tokens["token_type"] == "DPoP"

    refresh_data = {
        "grant_type": "refresh_token",
        "refresh_token": tokens["refresh_token"],
        "client_id": client["client_id"],
        "resource": resource,
    }
    missing_refresh_proof = await auth.fetch(request_form(f"{BASE}/oauth2/token", refresh_data))
    assert missing_refresh_proof.status == 400
    assert (await missing_refresh_proof.json())["error"] == "invalid_dpop_proof"

    rotated = await auth.fetch(
        request_form(
            f"{BASE}/oauth2/token",
            refresh_data,
            headers={
                "dpop": make_proof(
                    key,
                    method="POST",
                    url=token_url,
                    jti="server-wide-refresh-proof",
                )
            },
        )
    )
    assert rotated.status == 200, await rotated.text()
    assert (await rotated.json())["token_type"] == "DPoP"


async def test_dpop_support_preserves_current_bearer_mcp_clients(adapter):
    auth = make_auth(adapter, dpop=DPoPConfig())
    tokens, _client, _cookie = await full_grant(auth, scope="mcp")
    assert tokens["token_type"] == "Bearer"


async def test_dpop_bound_registration_requires_server_support_and_code_binding(auth_as):
    unsupported = await auth_as.fetch(
        request_json(
            f"{BASE}/oauth2/register",
            {
                "redirect_uris": ["https://client.example/cb"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code"],
                "dpop_bound_access_tokens": True,
            },
        )
    )
    assert unsupported.status == 400
    assert (await unsupported.json())["error"] == "invalid_client_metadata"


async def test_token_requires_form_content_type_and_rejects_other_auth_schemes(auth_as):
    malformed_body = await auth_as.fetch(
        Request(
            f"http://localhost{BASE}/oauth2/token",
            method="POST",
            headers={"content-type": "multipart/form-data; boundary=x"},
            body=b"--x--\r\n",
        )
    )
    assert malformed_body.status == 400
    assert (await malformed_body.json())["error"] == "invalid_request"

    client = await register(auth_as)
    unsupported_auth = await auth_as.fetch(
        request_form(
            f"{BASE}/oauth2/token",
            {"grant_type": "authorization_code", "client_id": client["client_id"]},
            headers={"authorization": "Bearer not-client-auth"},
        )
    )
    assert unsupported_auth.status == 401
    assert (await unsupported_auth.json())["error"] == "invalid_client"


async def test_token_rejects_wrong_pkce_verifier(auth_as):
    cookie = await signed_in_cookie(auth_as)
    client = await register(auth_as)
    code = await obtain_code(auth_as, cookie, client, verifier="v" * 43)
    res = await exchange(auth_as, client, code, verifier="w" * 43)
    assert res.status == 400
    assert (await res.json())["error"] == "invalid_grant"


async def test_code_replay_revokes_the_tokens_it_issued(auth_as):
    cookie = await signed_in_cookie(auth_as)
    client = await register(auth_as)
    verifier = "v" * 43
    code = await obtain_code(auth_as, cookie, client, verifier=verifier)
    first = await exchange(auth_as, client, code, verifier=verifier)
    assert first.status == 200
    access = (await first.json())["access_token"]
    assert await auth_as.verify_oauth_token(access) is not None

    replay = await exchange(auth_as, client, code, verifier=verifier)
    assert replay.status == 400
    assert (await replay.json())["error"] == "invalid_grant"
    # RFC 9700 §4.2: the replay burned everything the code had issued.
    assert await auth_as.verify_oauth_token(access) is None


async def test_concurrent_code_exchange_mints_exactly_one_token_family(auth_as, monkeypatch):
    cookie = await signed_in_cookie(auth_as)
    client = await register(auth_as)
    verifier = "v" * 43
    code = await obtain_code(auth_as, cookie, client, verifier=verifier)

    # This test targets the guarded 0 -> 1 claim when both requests read the
    # unused code. A request that observes state 1 is a different, deliberately
    # fail-closed replay-during-mint case covered by the next test.
    initial_reads = 0
    both_read_unused = asyncio.Event()
    original_find_one = auth_as.adapter.find_one

    async def synchronized_find_one(model, where):
        nonlocal initial_reads
        row = await original_find_one(model, where)
        if model == "oauth_code" and row is not None and row["used"] == 0:
            initial_reads += 1
            if initial_reads == 2:
                both_read_unused.set()
            await both_read_unused.wait()
        return row

    monkeypatch.setattr(auth_as.adapter, "find_one", synchronized_find_one)
    first, second = await asyncio.gather(
        exchange(auth_as, client, code, verifier=verifier),
        exchange(auth_as, client, code, verifier=verifier),
    )

    assert initial_reads == 2
    assert sorted((first.status, second.status)) == [200, 400]
    assert len(await auth_as.adapter.find_many("oauth_token", [])) == 1


async def test_code_replay_during_mint_cannot_leave_a_valid_token(adapter, monkeypatch):
    auth = make_auth(adapter)
    cookie = await signed_in_cookie(auth)
    client = await register(auth)
    verifier = "v" * 43
    code = await obtain_code(auth, cookie, client, verifier=verifier)

    create_started = asyncio.Event()
    resume_create = asyncio.Event()
    original_create = adapter.create

    async def paused_create(model, data):
        if model == "oauth_token":
            create_started.set()
            await resume_create.wait()
        return await original_create(model, data)

    monkeypatch.setattr(adapter, "create", paused_create)
    winner = asyncio.create_task(exchange(auth, client, code, verifier=verifier))
    await create_started.wait()

    replay = await exchange(auth, client, code, verifier=verifier)
    assert replay.status == 400
    resume_create.set()
    first = await winner

    assert first.status == 400
    rows = await adapter.find_many("oauth_token", [])
    assert len(rows) == 1
    assert rows[0]["revoked"] == 1


async def test_token_rejects_expired_code(adapter):
    auth = make_auth(adapter, code_ttl=timedelta(seconds=-1))
    cookie = await signed_in_cookie(auth)
    client = await register(auth)
    verifier = "v" * 43
    code = await obtain_code(auth, cookie, client, verifier=verifier)
    res = await exchange(auth, client, code, verifier=verifier)
    assert res.status == 400
    assert (await res.json())["error"] == "invalid_grant"


async def test_token_rejects_another_clients_code(auth_as):
    cookie = await signed_in_cookie(auth_as)
    client_a = await register(auth_as)
    client_b = await register(auth_as, client_name="B")
    verifier = "v" * 43
    code = await obtain_code(auth_as, cookie, client_a, verifier=verifier)
    res = await exchange(
        auth_as, client_b, code, verifier=verifier, redirect_uri=client_a["redirect_uris"][0]
    )
    assert res.status == 400
    assert (await res.json())["error"] == "invalid_grant"


async def test_token_rejects_redirect_uri_mismatch(auth_as):
    cookie = await signed_in_cookie(auth_as)
    client = await register(
        auth_as, redirect_uris=["https://client.example/cb", "https://client.example/other"]
    )
    verifier = "v" * 43
    code = await obtain_code(auth_as, cookie, client, verifier=verifier)
    res = await exchange(
        auth_as, client, code, verifier=verifier, redirect_uri="https://client.example/other"
    )
    assert res.status == 400
    assert (await res.json())["error"] == "invalid_grant"


async def test_token_resource_must_match_the_code(auth_as):
    cookie = await signed_in_cookie(auth_as)
    client = await register(auth_as)
    verifier = "v" * 43
    code = await obtain_code(
        auth_as, cookie, client, verifier=verifier, resource="https://rs.example"
    )
    res = await exchange(auth_as, client, code, verifier=verifier, resource="https://other.example")
    assert res.status == 400
    assert (await res.json())["error"] == "invalid_target"


async def test_mcp_mode_requires_resource_again_at_token_endpoint(adapter):
    resource = "https://mcp.example.com/mcp"
    auth = make_auth(adapter, resource=resource)
    cookie = await signed_in_cookie(auth)
    client = await register(auth)
    verifier = "v" * 43
    code = await obtain_code(auth, cookie, client, verifier=verifier, resource=resource)

    missing = await exchange(auth, client, code, verifier=verifier)
    assert missing.status == 400
    assert (await missing.json())["error"] == "invalid_target"

    accepted = await exchange(
        auth,
        client,
        code,
        verifier=verifier,
        resource="HTTPS://MCP.EXAMPLE.COM/mcp",
    )
    assert accepted.status == 200


async def test_confidential_client_authentication(auth_as):
    cookie = await signed_in_cookie(auth_as)
    client = await register(
        auth_as,
        token_endpoint_auth_method="client_secret_basic",
        grant_types=["authorization_code"],
    )
    verifier = "v" * 43
    code = await obtain_code(auth_as, cookie, client, verifier=verifier)

    wrong = await exchange(
        auth_as,
        client,
        code,
        verifier=verifier,
        headers={
            "authorization": "Basic "
            + base64.b64encode(f"{client['client_id']}:not-the-secret".encode()).decode()
        },
    )
    assert wrong.status == 401
    assert (await wrong.json())["error"] == "invalid_client"
    assert (wrong.headers.get("www-authenticate") or "").startswith("Basic")

    good = await exchange(
        auth_as,
        client,
        code,
        verifier=verifier,
        headers={
            "authorization": "Basic "
            + base64.b64encode(f"{client['client_id']}:{client['client_secret']}".encode()).decode()
        },
    )
    assert good.status == 200
    body = await good.json()
    assert body["access_token"].startswith("hat_")
    assert "refresh_token" not in body  # grant_types did not include refresh_token


async def test_auth_method_must_match_registration(auth_as):
    cookie = await signed_in_cookie(auth_as)
    public = await register(auth_as)  # registered as "none"
    verifier = "v" * 43
    code = await obtain_code(auth_as, cookie, public, verifier=verifier)
    res = await exchange(auth_as, public, code, verifier=verifier, secret="made-up")
    assert res.status == 401  # presenting a secret makes it client_secret_post: mismatch
    assert (await res.json())["error"] == "invalid_client"


# -- token: refresh_token grant -----------------------------------------------------------


async def test_refresh_rotation_and_reuse_detection(auth_as):
    tokens, client, _cookie = await full_grant(auth_as, scope="mcp")

    res = await auth_as.fetch(
        request_form(
            f"{BASE}/oauth2/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": client["client_id"],
            },
        )
    )
    assert res.status == 200
    rotated = await res.json()
    assert rotated["access_token"] != tokens["access_token"]
    assert rotated["refresh_token"] != tokens["refresh_token"]
    assert await auth_as.verify_oauth_token(rotated["access_token"]) is not None

    # Replaying the rotated-out refresh token burns the whole family
    # (RFC 9700 §4.14) — including the fresh access token.
    reuse = await auth_as.fetch(
        request_form(
            f"{BASE}/oauth2/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": client["client_id"],
            },
        )
    )
    assert reuse.status == 400
    assert (await reuse.json())["error"] == "invalid_grant"
    assert await auth_as.verify_oauth_token(rotated["access_token"]) is None


async def test_concurrent_refresh_mints_exactly_one_replacement(auth_as, monkeypatch):
    tokens, client, _cookie = await full_grant(auth_as, scope="mcp")

    # Hold both requests after they read the same active token.  A plain
    # gather() is scheduler-dependent: if the second request first observes
    # the winner's in-progress state, it is correctly treated as reuse and
    # burns the family (covered by the next test).
    original_find_one = auth_as.adapter.find_one
    both_read = asyncio.Event()
    refresh_reads = 0

    async def synchronized_find_one(model, where):
        nonlocal refresh_reads
        row = await original_find_one(model, where)
        if model == "oauth_token" and any(item.field == "refresh_token_hash" for item in where):
            refresh_reads += 1
            if refresh_reads == 2:
                both_read.set()
            await both_read.wait()
        return row

    monkeypatch.setattr(auth_as.adapter, "find_one", synchronized_find_one)

    async def refresh():
        return await auth_as.fetch(
            request_form(
                f"{BASE}/oauth2/token",
                {
                    "grant_type": "refresh_token",
                    "refresh_token": tokens["refresh_token"],
                    "client_id": client["client_id"],
                },
            )
        )

    first, second = await asyncio.gather(refresh(), refresh())

    assert sorted((first.status, second.status)) == [200, 400]
    assert len(await auth_as.adapter.find_many("oauth_token", [])) == 2


async def test_refresh_replay_during_rotation_cannot_leave_a_valid_token(adapter, monkeypatch):
    auth = make_auth(adapter)
    tokens, client, _cookie = await full_grant(auth, scope="mcp")

    create_started = asyncio.Event()
    resume_create = asyncio.Event()
    original_create = adapter.create

    async def paused_create(model, data):
        if model == "oauth_token":
            create_started.set()
            await resume_create.wait()
        return await original_create(model, data)

    monkeypatch.setattr(adapter, "create", paused_create)

    async def refresh():
        return await auth.fetch(
            request_form(
                f"{BASE}/oauth2/token",
                {
                    "grant_type": "refresh_token",
                    "refresh_token": tokens["refresh_token"],
                    "client_id": client["client_id"],
                },
            )
        )

    winner = asyncio.create_task(refresh())
    await create_started.wait()
    replay = await refresh()
    assert replay.status == 400
    resume_create.set()
    first = await winner

    assert first.status == 400
    rows = await adapter.find_many("oauth_token", [])
    assert len(rows) == 2
    assert all(row["revoked"] for row in rows)
    assert await auth.verify_oauth_token(tokens["access_token"]) is None


async def test_mcp_mode_requires_resource_on_refresh(adapter):
    resource = "https://mcp.example.com/mcp"
    auth = make_auth(adapter, resource=resource)
    tokens, client, _cookie = await full_grant(auth, resource=resource)

    missing = await auth.fetch(
        request_form(
            f"{BASE}/oauth2/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": client["client_id"],
            },
        )
    )
    assert missing.status == 400
    assert (await missing.json())["error"] == "invalid_target"

    accepted = await auth.fetch(
        request_form(
            f"{BASE}/oauth2/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": client["client_id"],
                "resource": resource,
            },
        )
    )
    assert accepted.status == 200


async def test_refresh_rejects_other_clients_token(auth_as):
    tokens, _client, _cookie = await full_grant(auth_as)
    other = await register(auth_as, client_name="Other")
    res = await auth_as.fetch(
        request_form(
            f"{BASE}/oauth2/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": other["client_id"],
            },
        )
    )
    assert res.status == 400
    assert (await res.json())["error"] == "invalid_grant"


async def test_refresh_scope_may_narrow_but_not_widen(auth_as):
    tokens, client, _cookie = await full_grant(auth_as, scope="mcp profile")
    narrowed = await auth_as.fetch(
        request_form(
            f"{BASE}/oauth2/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": client["client_id"],
                "scope": "mcp",
            },
        )
    )
    assert narrowed.status == 200
    body = await narrowed.json()
    assert body["scope"] == "mcp"

    widened = await auth_as.fetch(
        request_form(
            f"{BASE}/oauth2/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": body["refresh_token"],
                "client_id": client["client_id"],
                "scope": "mcp profile admin",
            },
        )
    )
    assert widened.status == 400
    assert (await widened.json())["error"] == "invalid_scope"


# -- verification (the hayate-mcp splice point) -------------------------------------------


async def test_verify_rejects_expired_and_foreign_tokens(adapter):
    auth = make_auth(adapter, access_token_ttl=timedelta(seconds=-1))
    tokens, _client, _cookie = await full_grant(auth)
    assert await auth.verify_oauth_token(tokens["access_token"]) is None
    assert await auth.verify_oauth_token("hat_never-issued") is None
    assert await auth.verify_oauth_token("ha_an-api-key-not-an-oauth-token") is None


async def test_verifier_factory_enforces_resource(auth_as):
    tokens, _client, _cookie = await full_grant(auth_as, resource="https://mcp.example")
    bound = auth_as.oauth_token_verifier(resource="https://mcp.example")
    assert (await bound(tokens["access_token"]))["resource"] == "https://mcp.example"
    wrong = auth_as.oauth_token_verifier(resource="https://other.example")
    assert await wrong(tokens["access_token"]) is None


async def test_unsupported_grant_type(auth_as):
    client = await register(auth_as)
    res = await auth_as.fetch(
        request_form(
            f"{BASE}/oauth2/token",
            {"grant_type": "client_credentials", "client_id": client["client_id"]},
        )
    )
    assert res.status == 400
    assert (await res.json())["error"] == "unsupported_grant_type"


# -- RFC 7009 revocation ---------------------------------------------------------------


def basic_auth(client_id: str, client_secret: str) -> dict[str, str]:
    encoded = base64.b64encode(
        f"{quote_plus(client_id, safe='')}:{quote_plus(client_secret, safe='')}".encode()
    ).decode()
    return {"authorization": f"Basic {encoded}"}


async def test_revocation_is_idempotent_private_and_family_wide(auth_as):
    tokens, client, _cookie = await full_grant(auth_as)
    other = await register(auth_as, client_name="Other")

    foreign = await auth_as.fetch(
        request_form(
            f"{BASE}/oauth2/revoke",
            {"token": tokens["access_token"], "client_id": other["client_id"]},
        )
    )
    assert foreign.status == 200
    assert await auth_as.verify_oauth_token(tokens["access_token"]) is not None

    revoked = await auth_as.fetch(
        request_form(
            f"{BASE}/oauth2/revoke",
            {
                "token": tokens["access_token"],
                "token_type_hint": "refresh_token",
                "client_id": client["client_id"],
            },
        )
    )
    assert revoked.status == 200
    assert await revoked.text() == ""
    assert revoked.headers.get("cache-control") == "no-store"
    assert revoked.headers.get("pragma") == "no-cache"
    assert await auth_as.verify_oauth_token(tokens["access_token"]) is None

    refresh = await auth_as.fetch(
        request_form(
            f"{BASE}/oauth2/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": client["client_id"],
            },
        )
    )
    assert refresh.status == 400

    unknown = await auth_as.fetch(
        request_form(
            f"{BASE}/oauth2/revoke",
            {"token": "unknown", "client_id": client["client_id"]},
        )
    )
    assert unknown.status == 200
    assert await unknown.text() == ""


async def test_confidential_client_revokes_with_http_basic(auth_as):
    cookie = await signed_in_cookie(auth_as)
    client = await register(
        auth_as,
        token_endpoint_auth_method="client_secret_basic",
    )
    verifier = "confidential-code-verifier-string-long-enough"
    code = await obtain_code(auth_as, cookie, client, verifier=verifier)
    headers = basic_auth(client["client_id"], client["client_secret"])
    exchanged = await exchange(
        auth_as,
        client,
        code,
        verifier=verifier,
        headers=headers,
    )
    tokens = await exchanged.json()

    invalid = await auth_as.fetch(
        request_form(
            f"{BASE}/oauth2/revoke",
            {"token": tokens["access_token"]},
            headers=basic_auth(client["client_id"], "wrong"),
        )
    )
    assert invalid.status == 401
    assert await auth_as.verify_oauth_token(tokens["access_token"]) is not None

    revoked = await auth_as.fetch(
        request_form(
            f"{BASE}/oauth2/revoke",
            {"token": tokens["refresh_token"]},
            headers=headers,
        )
    )
    assert revoked.status == 200
    assert await auth_as.verify_oauth_token(tokens["access_token"]) is None


async def test_revocation_racing_refresh_never_discloses_a_live_replacement(adapter, monkeypatch):
    auth = make_auth(adapter)
    tokens, client, _cookie = await full_grant(auth)
    create_started = asyncio.Event()
    resume_create = asyncio.Event()
    original_create = adapter.create

    async def paused_create(model, data):
        if model == "oauth_token":
            create_started.set()
            await resume_create.wait()
        return await original_create(model, data)

    monkeypatch.setattr(adapter, "create", paused_create)
    rotating = asyncio.create_task(
        auth.fetch(
            request_form(
                f"{BASE}/oauth2/token",
                {
                    "grant_type": "refresh_token",
                    "refresh_token": tokens["refresh_token"],
                    "client_id": client["client_id"],
                },
            )
        )
    )
    await create_started.wait()
    revoked = await auth.fetch(
        request_form(
            f"{BASE}/oauth2/revoke",
            {"token": tokens["refresh_token"], "client_id": client["client_id"]},
        )
    )
    assert revoked.status == 200
    resume_create.set()
    response = await rotating
    assert response.status == 400
    rows = await adapter.find_many("oauth_token", [])
    assert rows
    assert not any(row["revoked"] == 0 for row in rows)


# -- RFC 7662 introspection ------------------------------------------------------------


async def test_introspection_is_resource_bound_authenticated_and_private(adapter):
    resource = "https://mcp.example/mcp"
    resource_server_id = "mcp resource/server"
    resource_server_secret = "r +:/?" * 7
    auth = make_auth(
        adapter,
        resource=resource,
        scopes_supported=("mcp",),
        resource_servers=(
            OAuthResourceServer(
                client_id=resource_server_id,
                client_secret=resource_server_secret,
                resource=resource,
            ),
        ),
    )
    metadata = await auth.fetch(Request("http://localhost/.well-known/oauth-authorization-server"))
    document = await metadata.json()
    assert document["introspection_endpoint"] == f"http://localhost{BASE}/oauth2/introspect"
    assert document["introspection_endpoint_auth_methods_supported"] == ["client_secret_basic"]

    tokens, client, _cookie = await full_grant(auth, scope="mcp", resource=resource)
    headers = basic_auth(resource_server_id, resource_server_secret)
    active = await auth.fetch(
        request_form(
            f"{BASE}/oauth2/introspect",
            {"token": tokens["access_token"], "token_type_hint": "refresh_token"},
            headers=headers,
        )
    )
    assert active.status == 200
    assert active.headers.get("cache-control") == "no-store"
    assert active.headers.get("pragma") == "no-cache"
    claims = await active.json()
    assert claims["active"] is True
    assert claims["client_id"] == client["client_id"]
    assert claims["scope"] == "mcp"
    assert claims["aud"] == resource
    assert claims["iss"] == "http://localhost"
    assert claims["token_type"] == "Bearer"
    assert isinstance(claims["exp"], int)
    assert isinstance(claims["iat"], int)

    unknown = await auth.fetch(
        request_form(
            f"{BASE}/oauth2/introspect",
            {"token": "not-issued"},
            headers=headers,
        )
    )
    assert await unknown.json() == {"active": False}

    unauthorized = await auth.fetch(
        request_form(
            f"{BASE}/oauth2/introspect",
            {"token": tokens["access_token"]},
            headers=basic_auth(resource_server_id, "wrong"),
        )
    )
    assert unauthorized.status == 401
    assert unauthorized.headers.get("www-authenticate") == 'Basic realm="oauth2/introspect"'

    duplicated = await auth.fetch(
        Request(
            f"http://localhost{BASE}/oauth2/introspect",
            method="POST",
            headers={
                "content-type": "application/x-www-form-urlencoded",
                **headers,
            },
            body=f"token={tokens['access_token']}&token=other",
        )
    )
    assert duplicated.status == 400
    assert (await duplicated.json())["error"] == "invalid_request"


async def test_introspection_hides_tokens_from_another_resource(adapter):
    issued_resource = "https://mcp.example/a"
    other_resource = "https://mcp.example/b"
    auth = make_auth(
        adapter,
        resource_servers=(
            OAuthResourceServer("resource-a", "a" * 32, issued_resource),
            OAuthResourceServer("resource-b", "b" * 32, other_resource),
        ),
    )
    tokens, _client, _cookie = await full_grant(auth, resource=issued_resource)
    response = await auth.fetch(
        request_form(
            f"{BASE}/oauth2/introspect",
            {"token": tokens["access_token"]},
            headers=basic_auth("resource-b", "b" * 32),
        )
    )
    assert await response.json() == {"active": False}


# -- End-user consent management -------------------------------------------------------


async def test_user_can_list_and_revoke_a_consent(auth_as):
    tokens, client, cookie = await full_grant(auth_as, scope="mcp profile")
    listed = await auth_as.fetch(
        Request(
            f"http://localhost{BASE}/oauth2/consents",
            headers={"cookie": cookie},
        )
    )
    assert listed.status == 200
    assert listed.headers.get("cache-control") == "no-store"
    consent = (await listed.json())["consents"]
    assert len(consent) == 1
    assert consent[0]["client_id"] == client["client_id"]
    assert consent[0]["client_name"] == "Test Client"
    assert consent[0]["scope"] == "mcp profile"
    assert consent[0]["created_at"]
    assert consent[0]["updated_at"]

    revoked = await auth_as.fetch(
        request_json(
            f"{BASE}/oauth2/consents/revoke",
            {"client_id": client["client_id"]},
            cookie=cookie,
        )
    )
    assert revoked.status == 200
    assert await revoked.json() == {"success": True}
    assert await auth_as.verify_oauth_token(tokens["access_token"]) is None
    after = await auth_as.fetch(
        Request(
            f"http://localhost{BASE}/oauth2/consents",
            headers={"cookie": cookie},
        )
    )
    assert await after.json() == {"consents": []}

    verifier = "authorize-again-after-revocation-verifier"
    authorize_again = await auth_as.fetch(
        authorize_request(client, verifier=verifier, cookie=cookie, scope="mcp")
    )
    assert authorize_again.status == 302
    assert "/consent?" in authorize_again.headers.get("location")


async def test_another_user_cannot_revoke_someone_elses_consent(auth_as):
    tokens, client, _owner_cookie = await full_grant(auth_as)
    other_cookie = await signed_in_cookie(auth_as, "other@example.com")
    response = await auth_as.fetch(
        request_json(
            f"{BASE}/oauth2/consents/revoke",
            {"client_id": client["client_id"]},
            cookie=other_cookie,
        )
    )
    assert response.status == 200
    assert await auth_as.verify_oauth_token(tokens["access_token"]) is not None


async def test_consent_revocation_racing_code_exchange_cannot_leave_a_live_token(
    adapter, monkeypatch
):
    auth = make_auth(adapter)
    cookie = await signed_in_cookie(auth)
    client = await register(auth)
    verifier = "consent-race-code-verifier-long-enough"
    code = await obtain_code(auth, cookie, client, verifier=verifier)
    create_started = asyncio.Event()
    resume_create = asyncio.Event()
    original_create = adapter.create

    async def paused_create(model, data):
        if model == "oauth_token":
            create_started.set()
            await resume_create.wait()
        return await original_create(model, data)

    monkeypatch.setattr(adapter, "create", paused_create)
    exchanging = asyncio.create_task(exchange(auth, client, code, verifier=verifier))
    await create_started.wait()
    revoked = await auth.fetch(
        request_json(
            f"{BASE}/oauth2/consents/revoke",
            {"client_id": client["client_id"]},
            cookie=cookie,
        )
    )
    assert revoked.status == 200
    resume_create.set()
    response = await exchanging
    assert response.status == 400
    rows = await adapter.find_many("oauth_token", [])
    assert rows
    assert not any(row["revoked"] == 0 for row in rows)
